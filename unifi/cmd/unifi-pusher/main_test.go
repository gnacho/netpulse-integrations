package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gnacho/netpulse-integrations/internal/pusher"
	"github.com/gnacho/netpulse-integrations/unifi"
	"github.com/gnacho/netpulse/agent/probe"
)

func unifiPusherConfig(server string) pusher.Config {
	return pusher.Config{
		Name: "unifi-pusher", Server: server, Token: "token", Slug: "ctrl",
		Version: "test", Interval: 20 * time.Millisecond,
	}
}

// End to end against the real poller: a controller that rejects the
// credentials must stop the pusher after one login attempt. Retrying the same
// failed login every cycle can trip the controller's brute-force protection.
func TestRunStopsAfterRejectedLogin(t *testing.T) {
	var logins atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/network/api/auth/login", func(w http.ResponseWriter, _ *http.Request) {
		logins.Add(1)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	poller := unifi.New(unifi.Config{Host: ts.URL})
	done := make(chan error, 1)
	go func() {
		done <- pusher.Run(context.Background(), unifiPusherConfig("http://127.0.0.1:1"), pusher.FromData(poller.Poll))
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after a rejected login")
	}
	if got := logins.Load(); got != 1 {
		t.Fatalf("login endpoint hit %d times, want 1", got)
	}
}

// Transient failures keep being retried: an unreachable controller must not
// disable the pusher.
func TestRunKeepsRetryingTransientFailures(t *testing.T) {
	ts := httptest.NewServer(http.NewServeMux())
	url := ts.URL
	ts.Close() // nothing listens there anymore: connection refused every cycle

	poller := unifi.New(unifi.Config{Host: url})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inner := pusher.FromData(poller.Poll)
	var polls atomic.Int64
	collect := func(ctx context.Context) (*probe.Payload, error) {
		if polls.Add(1) >= 3 {
			cancel()
		}
		return inner(ctx)
	}
	done := make(chan error, 1)
	go func() {
		done <- pusher.Run(ctx, unifiPusherConfig("http://127.0.0.1:1"), collect)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("Run did not keep retrying transient failures")
	}
	if got := polls.Load(); got < 3 {
		t.Fatalf("collector ran %d times, want at least 3", got)
	}
}
