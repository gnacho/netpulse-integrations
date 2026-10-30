package supervisor

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netpulse-integrations/internal/push"
	"github.com/gnacho/netpulse/agent/probe"
)

type terminalTestError struct{}

func (terminalTestError) Error() string  { return "credentials rejected" }
func (terminalTestError) Terminal() bool { return true }

func TestTerminalPollErrorStopsOnlyThatPoller(t *testing.T) {
	client, err := push.NewClient("http://127.0.0.1", time.Second, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	calls := 0
	runPoller(context.Background(), client, Poller{
		Vendor: "bbox", Slug: "hall", Token: "token", Interval: 10 * time.Second,
		Collect: func(context.Context) (*probe.PayloadData, error) {
			calls++
			return nil, terminalTestError{}
		},
	}, logger)
	if calls != 1 {
		t.Fatalf("collector called %d times, want 1", calls)
	}
	if !strings.Contains(logs.String(), "ALERT: integration disabled") {
		t.Fatalf("terminal failure did not log an alert: %s", logs.String())
	}
}

func TestRunRejectsNoPollers(t *testing.T) {
	err := Run(context.Background(), nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no integrations are configured") {
		t.Fatalf("err = %v, want no integrations error", err)
	}
}

func TestRunRejectsInvalidPollerConfigs(t *testing.T) {
	collect := func(context.Context) (*probe.PayloadData, error) { return &probe.PayloadData{}, nil }
	cases := []struct {
		name string
		p    Poller
	}{
		{"missing vendor", Poller{Slug: "s", Token: "t", Interval: 10 * time.Second, Collect: collect}},
		{"missing slug", Poller{Vendor: "v", Token: "t", Interval: 10 * time.Second, Collect: collect}},
		{"missing token", Poller{Vendor: "v", Slug: "s", Interval: 10 * time.Second, Collect: collect}},
		{"interval below minimum", Poller{Vendor: "v", Slug: "s", Token: "t", Interval: 9 * time.Second, Collect: collect}},
		{"sub-second interval", Poller{Vendor: "v", Slug: "s", Token: "t", Interval: 1500 * time.Millisecond, Collect: collect}},
		{"missing collect", Poller{Vendor: "v", Slug: "s", Token: "t", Interval: 10 * time.Second}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Run(context.Background(), nil, []Poller{tc.p}, nil)
			if err == nil || !strings.Contains(err.Error(), "invalid configuration") {
				t.Fatalf("err = %v, want invalid configuration", err)
			}
		})
	}
}

func TestRunRejectsDuplicateSlugs(t *testing.T) {
	collect := func(context.Context) (*probe.PayloadData, error) { return &probe.PayloadData{}, nil }
	err := Run(context.Background(), nil, []Poller{
		{Vendor: "bbox", Slug: "hall", Token: "t1", Interval: 10 * time.Second, Collect: collect},
		{Vendor: "routeros", Slug: "hall", Token: "t2", Interval: 10 * time.Second, Collect: collect},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), `duplicate integration slug "hall"`) {
		t.Fatalf("err = %v, want duplicate slug error", err)
	}
}

func TestRunClosesPollersAfterContextCancellation(t *testing.T) {
	client, err := push.NewClient("http://127.0.0.1", time.Second, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closed := make(chan string, 2)
	pollers := []Poller{
		{Vendor: "bbox", Slug: "hall", Token: "t1", Interval: 10 * time.Second,
			Collect: func(context.Context) (*probe.PayloadData, error) { return &probe.PayloadData{}, nil },
			Close:   func(context.Context) error { closed <- "hall"; return nil }},
		{Vendor: "routeros", Slug: "attic", Token: "t2", Interval: 10 * time.Second,
			Collect: func(context.Context) (*probe.PayloadData, error) { return &probe.PayloadData{}, nil },
			Close:   func(context.Context) error { closed <- "attic"; return nil }},
	}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, client, pollers, logger) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	close(closed)
	got := map[string]bool{}
	for slug := range closed {
		got[slug] = true
	}
	if len(got) != 2 {
		t.Fatalf("close called for %v, want both pollers", got)
	}
}
