package push

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gnacho/netpulse-integrations/internal/tlspin"
	"github.com/gnacho/netpulse/agent/probe"
)

type Client struct {
	server string
	http   *http.Client
}

// NewClient returns a client that pushes to the NetPulse ingest endpoint.
// Either caFile (a PEM CA added to the system trust roots) or serverFP (a
// SHA-256 SPKI pin, comma-separated for several keys) authenticates the
// server; setting both is a configuration error. A pin is the option that
// works with the NetPulse generated certificate, which is issued for
// 127.0.0.1 and fails host name verification from any LAN address. An HTTPS
// server URL with neither option is rejected instead of falling back to a
// raw x509 failure at push time.
func NewClient(server string, timeout time.Duration, caFile, serverFP string) (*Client, error) {
	server = strings.TrimRight(strings.TrimSpace(server), "/")
	if server == "" {
		return nil, fmt.Errorf("NetPulse server URL is required")
	}
	u, err := url.Parse(server)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid NetPulse server URL %q", server)
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	caFile = strings.TrimSpace(caFile)
	serverFP = strings.TrimSpace(serverFP)
	if caFile != "" && serverFP != "" {
		return nil, errors.New("ca_file and server_fp are mutually exclusive")
	}
	var pins []string
	if serverFP != "" {
		var err error
		pins, err = tlspin.Parse(serverFP)
		if err != nil {
			return nil, fmt.Errorf("invalid server fingerprint: %w", err)
		}
	}
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("default HTTP transport has unexpected type %T", http.DefaultTransport)
	}
	transport = transport.Clone()
	switch {
	case caFile != "" && u.Scheme == "https":
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read NetPulse CA file: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("NetPulse CA file contains no valid certificates")
		}
		tlsConfig := &tls.Config{RootCAs: roots}
		if transport.TLSClientConfig != nil {
			tlsConfig = transport.TLSClientConfig.Clone()
			tlsConfig.RootCAs = roots
		}
		transport.TLSClientConfig = tlsConfig
	case len(pins) > 0:
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // deliberate SPKI pinning below
			VerifyConnection: func(cs tls.ConnectionState) error {
				return tlspin.Verify(cs.PeerCertificates, pins, u.Hostname())
			},
			MinVersion: tls.VersionTLS12,
		}
	case strings.HasPrefix(server, "https://"):
		return nil, errors.New("HTTPS requires server_fp or ca_file for server authentication")
	}
	return &Client{server: server, http: &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: sameOriginRedirect}}, nil
}

// maxRedirects caps the redirect chain so a server that loops cannot keep the
// pusher busy until the timeout.
const maxRedirects = 3

// sameOriginRedirect follows a redirect only when it stays on the scheme, host
// and port of the configured server, and only when the request keeps its POST
// method and body. The ingest endpoint expects a signed POST, so a 301, 302 or
// 303 would silently turn the push into an unsigned GET. Refusing cross-origin
// redirects keeps the bearer token and the signature from leaving the server
// the operator configured.
func sameOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	origin := via[0].URL
	if req.URL.Scheme != origin.Scheme || req.URL.Host != origin.Host {
		return fmt.Errorf("refusing redirect to another origin (%s -> %s)", origin.Redacted(), req.URL.Redacted())
	}
	if req.Method != http.MethodPost {
		return fmt.Errorf("refusing redirect that changes the request method from POST to %s, the ingest endpoint only accepts a signed POST", req.Method)
	}
	return nil
}

// Send marshals once, then signs and sends those exact bytes.
func (c *Client) Send(ctx context.Context, token string, payload probe.Payload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	sig := hmac.New(sha256.New, []byte(token))
	_, _ = sig.Write(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server+"/api/ingest/agent", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create ingest request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Agent-Signature", hex.EncodeToString(sig.Sum(nil)))
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("send ingest request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusAccepted || response.StatusCode == http.StatusOK {
		return nil
	}
	message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return fmt.Errorf("ingest returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
}
