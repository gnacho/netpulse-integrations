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
	client, err := push.NewClient("http://127.0.0.1", time.Second, "")
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
