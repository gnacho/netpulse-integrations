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
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	caFile = strings.TrimSpace(caFile)
	serverFP = strings.TrimSpace(serverFP)
	if caFile != "" && serverFP != "" {
		return nil, errors.New("ca_file and server_fp are mutually exclusive: a pin is the option that works with the NetPulse generated certificate")
	}
	var pins []string
	if serverFP != "" {
		var err error
		pins, err = tlspin.Parse(serverFP)
		if err != nil {
			return nil, fmt.Errorf("server_fp: %w", err)
		}
	}
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("default HTTP transport has unexpected type %T", http.DefaultTransport)
	}
	transport = transport.Clone()
	switch {
	case caFile != "":
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
				return tlspin.Verify(cs.PeerCertificates, pins)
			},
			MinVersion: tls.VersionTLS12,
		}
	case strings.HasPrefix(server, "https://"):
		return nil, errors.New("HTTPS requires server_fp (SHA-256 SPKI pin) or ca_file; omit both only for plain HTTP")
	}
	return &Client{server: server, http: &http.Client{Timeout: timeout, Transport: transport}}, nil
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
