package fn

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/gnacho/netpulse-integrations/internal/tlspin"
)

// userAgent: the switch's embedded web server answers {"logout":true,
// "reason":"notAuth"} to any User-Agent that does not look like a browser,
// even to a request carrying a valid session cookie.
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"

// webClient talks to the backend the switch's own UI uses:
// /cgi/get.cgi?cmd=<name> and /cgi/set.cgi?cmd=<name>.
type webClient struct {
	base   string
	user   string
	pass   string
	hc     *http.Client
	authed bool
}

func newWebClient(host, user, pass string, insecure bool, certFP string) (*webClient, error) {
	base := strings.TrimSuffix(host, "/")
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("fn: host %q: %w", host, err)
	}
	tlsCfg := &tls.Config{
		// Measured on the device (FN SWITCH 8 PRO, firmware V1.1.6): the
		// embedded Hydra server negotiates TLS 1.2 with static-RSA
		// AES-256-GCM, and every ECDHE suite fails the handshake. Go left
		// those suites out of the default ClientHello, so they are listed
		// explicitly, and the ECDHE candidates stay for a firmware that
		// improves. TLS 1.0 and 1.1 are not offered: this device would not
		// take them and the switch is not worth the exposure.
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		InsecureSkipVerify: insecure, //nolint:gosec // explicit opt-in
	}
	// The UI serves a self-signed certificate, so pinning is the normal way to
	// authenticate it. The pin is the SHA-256 of the certificate's public key
	// (SPKI), the same format and semantics as the push client's server_fp, and
	// it is checked on every handshake. With no pin, no CA and no insecure
	// flag, standard verification applies, which fails closed on that
	// certificate.
	if certFP != "" {
		pins, err := tlspin.Parse(certFP)
		if err != nil {
			return nil, err
		}
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // the pin below is the verification
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			return tlspin.Verify(cs.PeerCertificates, pins)
		}
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("fn: cookie jar: %w", err)
	}
	return &webClient{
		base: base, user: user, pass: pass,
		hc: &http.Client{
			Jar:       jar,
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// envelope is the wrapper every cgi endpoint puts around its payload. A
// rejected session arrives as {"logout":true,"reason":"notAuth"} with HTTP 200,
// which is why the status code alone never says whether a read worked.
type envelope struct {
	Data   json.RawMessage `json:"data"`
	Logout bool            `json:"logout"`
	Reason string          `json:"reason"`
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
}

func (w *webClient) do(ctx context.Context, method, path, body string) (*envelope, error) {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, w.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := w.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fn: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("fn: read %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fn: %s: %s: %s", path, resp.Status, firstLine(string(raw)))
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("fn: %s is not JSON: %w (%s)", path, err, firstLine(string(raw)))
	}
	return &env, nil
}

// login runs the three steps the UI performs, in that order:
//
//  1. GET home_login issues the login_txn token
//  2. POST home_loginAuth checks the credentials
//  3. GET home_loginStatus is where the "session" cookie is issued
//
// Step 3 is not optional cosmetics: without that cookie every cmd answers
// notAuth, and step 2 alone reports save_success even for a bad user, so the
// credentials can only be verified here.
//
// The body is sent UNENCODED: this server does not percent-decode the form, so
// an "@" arriving as "%40" reads as an invalid user while the response still
// says save_success.
func (w *webClient) login(ctx context.Context) error {
	if _, err := w.do(ctx, http.MethodGet, "/cgi/get.cgi?cmd=home_login", ""); err != nil {
		return err
	}
	env, err := w.do(ctx, http.MethodPost, "/cgi/set.cgi?cmd=home_loginAuth",
		"username="+w.user+"&password="+w.pass)
	if err != nil {
		return err
	}
	if env.Status != "" && env.Status != "ok" {
		return fmt.Errorf("fn: login rejected: %s %s", env.Status, env.Msg)
	}
	env, err = w.do(ctx, http.MethodGet, "/cgi/get.cgi?cmd=home_loginStatus", "")
	if err != nil {
		return err
	}
	var st struct {
		Status     string `json:"status"`
		FailReason string `json:"failReason"`
	}
	if len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, &st); err != nil {
			return fmt.Errorf("fn: login status: %w", err)
		}
	}
	if st.Status != "ok" {
		return fmt.Errorf("fn: login not authenticated (status=%q %s)", st.Status, st.FailReason)
	}
	return nil
}

// get reads one cmd into out. The session is REUSED: the device has few global
// session slots (an extra login answers errLoginSessionNum and does not free up
// for minutes), so the client only logs in again when a response says notAuth.
func (w *webClient) get(ctx context.Context, cmd string, out any) error {
	if !w.authed {
		if err := w.login(ctx); err != nil {
			return err
		}
		w.authed = true
	}
	for attempt := 0; attempt < 2; attempt++ {
		env, err := w.do(ctx, http.MethodGet,
			fmt.Sprintf("/cgi/get.cgi?cmd=%s&dummy=%d", cmd, time.Now().UnixMilli()), "")
		if err != nil {
			return err
		}
		if env.Logout {
			w.authed = false
			if err := w.login(ctx); err != nil {
				return err
			}
			w.authed = true
			continue
		}
		if len(env.Data) == 0 {
			return fmt.Errorf("fn: cmd=%s returned no data", cmd)
		}
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("fn: cmd=%s: %w", cmd, err)
		}
		return nil
	}
	return fmt.Errorf("fn: cmd=%s: session rejected twice", cmd)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160]
	}
	return strings.TrimSpace(s)
}
