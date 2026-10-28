package push

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

type Client struct {
	server string
	http   *http.Client
}

func NewClient(server string, timeout time.Duration) (*Client, error) {
	server = strings.TrimRight(strings.TrimSpace(server), "/")
	if server == "" {
		return nil, fmt.Errorf("NetPulse server URL is required")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Client{server: server, http: &http.Client{Timeout: timeout}}, nil
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
