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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

type Client struct {
	server string
	http   *http.Client
}

// Config contains the shared NetPulse destination and TLS trust settings.
type Config struct {
	Server   string
	Timeout  time.Duration
	CAFile   string
	ServerFP string
}

func NewClient(cfg Config) (*Client, error) {
	server := strings.TrimRight(strings.TrimSpace(cfg.Server), "/")
	if server == "" {
		return nil, fmt.Errorf("NetPulse server URL is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	u, err := url.Parse(server)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid NetPulse server URL %q", server)
	}
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("default HTTP transport has unexpected type %T", http.DefaultTransport)
	}
	transport = transport.Clone()
	if u.Scheme == "https" {
		if strings.TrimSpace(cfg.ServerFP) != "" {
			if strings.TrimSpace(cfg.CAFile) != "" {
				return nil, fmt.Errorf("configure either server_fp or ca_file, not both")
			}
			pins, err := parsePins(cfg.ServerFP)
			if err != nil {
				return nil, err
			}
			transport.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // The pinned key or CA is verified in VerifyConnection.
				MinVersion:         tls.VersionTLS12,
				VerifyConnection: func(state tls.ConnectionState) error {
					return verifyPinnedChain(state.PeerCertificates, u.Hostname(), pins, time.Now())
				},
			}
		} else if strings.TrimSpace(cfg.CAFile) != "" {
			pem, err := os.ReadFile(cfg.CAFile)
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
		} else {
			return nil, fmt.Errorf("HTTPS requires server_fp (NETPULSE_SERVER_FP) or ca_file (NETPULSE_CA_FILE); use the SPKI pin for NetPulse's self-signed certificate")
		}
	}
	return &Client{server: server, http: &http.Client{Timeout: cfg.Timeout, Transport: transport}}, nil
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
