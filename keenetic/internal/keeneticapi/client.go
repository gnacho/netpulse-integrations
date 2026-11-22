// Package keeneticapi is a read-only client for the KeeneticOS RCI HTTP API.
//
// RCI is a JSON mirror of the command-line tree: a URL path under /rci/ is a
// path through the same tree a CLI session walks. This package implements the
// /auth challenge-response handshake and GET queries against /rci/show/...
// It carries no write path by construction: the only POST it ever issues is
// the authentication request.
//
// Protocol notes that naive clients trip over (established against public
// client implementations; re-verified against live hardware in the
// integration fixtures):
//
//   - Neither HTTP Basic nor Digest works on the LAN web port. The handshake
//     is a challenge: GET /auth answers 401 with the realm and challenge, the
//     client answers with md5(login:realm:password) hashed again into
//     sha256(challenge+md5), and the router opens a cookie session.
//   - The session cookie NAME is randomised per router, so a cookie jar must
//     read it from Set-Cookie; hand-built headers do not survive it.
//   - The session lives in a 300-second sliding window. Every request extends
//     it, but an idle gap longer than that yields 401 on the next call, so
//     every request re-authenticates transparently at most once.
//   - The realm varies by model and must come from the response, never a
//     constant. Over KeenDNS the X-NDM-* headers are absent (out of scope:
//     this client talks to the LAN address).
//   - The router frequently answers HTTP 200 with the failure inside the
//     body: {"status":[{"status":"error","code":...,"message":...}]}. A
//     client must walk the body as well as the HTTP status.
//   - Paths absent on the installed firmware answer 404 with an empty body.
//     Callers decide per section whether a missing path is a feature gap
//     (nil section in the payload) or a hard error.
package keeneticapi

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gnacho/netpulse-integrations/internal/tlspin"
)

// Config is the address and credentials of one KeeneticOS unit.
type Config struct {
	// Host is the base URL ("http://192.168.1.1") or a bare host or
	// host:port; a bare target talks plain HTTP, which is the LAN default.
	Host string
	User string
	// Password of a dedicated read-only account; the integration never uses
	// the admin account the owner browses the UI with.
	Password string
	// Timeout per HTTP request. Zero means 10s.
	Timeout time.Duration
	// InsecureTLS accepts the unit self-signed certificate on https://
	// targets. Never set for plain HTTP targets; it has no effect there.
	// Mutually exclusive with CertFP: a pin is the stronger trust.
	InsecureTLS bool
	// CertFP is a comma-separated list of SHA-256 SPKI pins of the unit
	// certificate (https:// targets): the handshake must present a key
	// matching one of them. The pin is validated at configuration time, so
	// a typo fails before the first request instead of mid-cycle.
	CertFP string
}

// AuthError reports that the router rejected the credentials. It is terminal:
// the poller stops instead of retrying, so a wrong password cannot trip the
// router's brute-force protection.
type AuthError struct {
	Detail string
}

func (e *AuthError) Error() string {
	if e.Detail == "" {
		return "authentication rejected by the router"
	}
	return "authentication rejected by the router: " + e.Detail
}

// Terminal marks AuthError for the shared pusher loop's stop-on-terminal rule.
func (e *AuthError) Terminal() bool { return true }

// NotFoundError reports that every candidate path answered 404: this firmware
// does not expose the section. Callers usually downgrade it to a nil section.
type NotFoundError struct {
	Paths []string
}

func (e *NotFoundError) Error() string {
	return "path not found on this firmware: " + strings.Join(e.Paths, ", ")
}

// APIError reports an error the router answered inside HTTP 200
// (status[].status == "error").
type APIError struct {
	Code    string
	Ident   string
	Message string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = "unknown error"
	}
	if e.Ident != "" {
		return fmt.Sprintf("rci error (%s): %s", e.Ident, msg)
	}
	return "rci error: " + msg
}

// statusBody is the failure envelope the router hides inside HTTP 200.
type statusBody struct {
	Status []struct {
		Status  string `json:"status"`
		Code    string `json:"code"`
		Ident   string `json:"ident"`
		Message string `json:"message"`
	} `json:"status"`
}

// Client is a read-only RCI client for one unit. It keeps the authenticated
// cookie session open: the 401 answers re-authenticate transparently at most
// once per request. Safe for sequential use from one poll loop.
type Client struct {
	base     *url.URL
	user     string
	password string
	http     *http.Client
}

// New validates the config and returns a client. It does not talk to the
// router; the first request authenticates.
func New(cfg Config) (*Client, error) {
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		return nil, errors.New("keenetic host is required")
	}
	if !strings.Contains(host, "://") {
		host = "http://" + host
	}
	u, err := url.Parse(host)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid keenetic host %q", cfg.Host)
	}
	if cfg.User == "" || cfg.Password == "" {
		return nil, errors.New("keenetic user and password are required")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("cookie jar: %w", err)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if u.Scheme == "https" {
		switch {
		case strings.TrimSpace(cfg.CertFP) != "":
			// Deliberate pinning: skip the system trust and verify the
			// handshake against the configured SPKI pins instead.
			pins, err := tlspin.Parse(cfg.CertFP)
			if err != nil {
				return nil, fmt.Errorf("keenetic cert_fp: %w", err)
			}
			transport.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // deliberate SPKI pinning below
				VerifyConnection: func(cs tls.ConnectionState) error {
					return tlspin.Verify(cs.PeerCertificates, pins)
				},
				MinVersion: tls.VersionTLS12,
			}
		case cfg.InsecureTLS:
			transport.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // documented option for the unit self-signed certificate
				MinVersion:         tls.VersionTLS12,
			}
		}
	}
	return &Client{
		base:     u,
		user:     cfg.User,
		password: cfg.Password,
		http:     &http.Client{Timeout: timeout, Transport: transport, Jar: jar},
	}, nil
}

// Get performs GET /rci/<path> and returns the raw JSON document. A 401
// re-authenticates once (the sliding session window) and retries. A 404 is a
// NotFoundError. An error envelope inside HTTP 200 is an APIError.
func (c *Client) Get(ctx context.Context, path string) (json.RawMessage, error) {
	body, err := c.get(ctx, path)
	if !errors.Is(err, errNeedAuth) {
		return body, err
	}
	// The session window expired (or the router rebooted): one transparent
	// re-auth, then retry the query exactly once.
	if err := c.authenticate(ctx); err != nil {
		return nil, err
	}
	body, err = c.get(ctx, path)
	if errors.Is(err, errNeedAuth) {
		// The router keeps rejecting the session even after a fresh
		// handshake: the credentials (or the unit's auth state) are broken,
		// not merely expired. Terminal — the same rule a rejected handshake
		// follows.
		return nil, &AuthError{Detail: fmt.Sprintf("GET /rci/%s: session rejected after re-authentication", path)}
	}
	return body, err
}

// TryGet queries the candidate paths in order and returns the first answer
// that exists, together with the path that produced it. KeeneticOS renames
// sections between release branches ("ip/dhcp/binding" vs "ip/dhcp/binding(s)"),
// so callers list the known spellings and keep whatever the firmware answers.
// When every candidate is a 404 the result is a NotFoundError listing them.
func (c *Client) TryGet(ctx context.Context, paths ...string) (json.RawMessage, string, error) {
	missing := make([]string, 0, len(paths))
	for _, path := range paths {
		body, err := c.Get(ctx, path)
		var nf *NotFoundError
		switch {
		case err == nil:
			return body, path, nil
		case errors.As(err, &nf):
			missing = append(missing, path)
		default:
			return nil, "", err
		}
	}
	return nil, "", &NotFoundError{Paths: missing}
}

// errNeedAuth is the internal signal that the request answered 401.
var errNeedAuth = errors.New("session expired")

func (c *Client) get(ctx context.Context, path string) (json.RawMessage, error) {
	if strings.ContainsAny(path, " ?#") || strings.Contains(path, "//") {
		return nil, fmt.Errorf("invalid rci path %q", path)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base.String()+"/rci/"+path, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET /rci/%s: %w", path, err)
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return nil, errNeedAuth
	case http.StatusNotFound:
		return nil, &NotFoundError{Paths: []string{path}}
	}
	if res.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return nil, fmt.Errorf("GET /rci/%s: HTTP %d: %s", path, res.StatusCode, strings.TrimSpace(string(message)))
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("GET /rci/%s: %w", path, err)
	}
	if err := walkStatus(raw); err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}

// maxBodyBytes caps one answer at 4 MiB: show/ip/nat alone can pass 100 KB on
// a busy router and this client only queries bounded sections; anything larger
// is a wrong (or hostile) answer worth rejecting instead of buffering.
const maxBodyBytes = 4 << 20

// walkStatus turns the HTTP-200 error envelope into an APIError. A body that
// is not an object with a status array is ordinary data and passes through.
func walkStatus(raw []byte) error {
	var sb statusBody
	if err := json.Unmarshal(raw, &sb); err != nil {
		return nil // not a status envelope: ordinary data
	}
	for _, st := range sb.Status {
		if st.Status == "error" {
			return &APIError{Code: st.Code, Ident: st.Ident, Message: st.Message}
		}
	}
	return nil
}

// authenticate runs the challenge-response handshake and opens the session:
// the router answers the POST with the session cookie the jar keeps. All
// later requests walk with that cookie until the router closes the session;
// credential rejection is terminal.
func (c *Client) authenticate(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base.String()+"/auth", nil)
	if err != nil {
		return err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("auth challenge: %w", err)
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))

	realm := strings.TrimSpace(res.Header.Get("X-NDM-Realm"))
	challenge := strings.TrimSpace(res.Header.Get("X-NDM-Challenge"))
	if realm == "" || challenge == "" {
		// Some firmwares only carry them in WWW-Authenticate:
		// x-ndw2-interactive realm="..." challenge="..." session_cookie="..."
		realm, challenge = parseAuthChallenge(res.Header.Get("WWW-Authenticate"), realm, challenge)
	}
	if realm == "" || challenge == "" {
		return fmt.Errorf("auth challenge: router answered HTTP %d without realm/challenge", res.StatusCode)
	}

	key := authKey(c.user, c.password, realm, challenge)
	payload, err := json.Marshal(map[string]string{"login": c.user, "password": key})
	if err != nil {
		return err
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, c.base.String()+"/auth", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res2, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("auth submit: %w", err)
	}
	defer res2.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res2.Body, 4096))
	if res2.StatusCode != http.StatusOK {
		// 401/403 are the credential verdict: the derived key was rejected.
		// Retrying with the same secret cannot succeed - terminal.
		if res2.StatusCode == http.StatusUnauthorized || res2.StatusCode == http.StatusForbidden {
			return &AuthError{Detail: fmt.Sprintf("HTTP %d", res2.StatusCode)}
		}
		// Anything else - a 5xx under load, 429 rate limiting, an
		// unexpected 4xx from a firmware that changed the endpoint - is a
		// transient server condition, not credential evidence: a plain
		// error keeps the unit retryable next cycle instead of the
		// supervisor disabling it (review round 2: 429 explicitly
		// retryable).
		return fmt.Errorf("auth submit: HTTP %d", res2.StatusCode)
	}
	return nil
}

// parseAuthChallenge extracts realm and challenge from the WWW-Authenticate
// header when the dedicated headers are absent.
func parseAuthChallenge(header, realm, challenge string) (string, string) {
	fields := map[string]string{}
	for _, m := range authParamRe.FindAllStringSubmatch(header, -1) {
		fields[m[1]] = m[2]
	}
	if realm == "" {
		realm = fields["realm"]
	}
	if challenge == "" {
		challenge = fields["challenge"]
	}
	return realm, challenge
}

var authParamRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

// authKey computes sha256(challenge + md5(login:realm:password)), the exact
// scheme the router expects, lowercase hex on both steps.
func authKey(login, password, realm, challenge string) string {
	md5Sum := md5.Sum([]byte(login + ":" + realm + ":" + password))
	md5Hex := hex.EncodeToString(md5Sum[:])
	shaSum := sha256.Sum256([]byte(challenge + md5Hex))
	return hex.EncodeToString(shaSum[:])
}
