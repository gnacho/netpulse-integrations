package asuswrt

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

// fakeRunner answers the radio-tools probe without touching the shell.
type fakeRunner struct {
	err   error
	calls int
}

func (f *fakeRunner) Run(ctx context.Context, cmd string, timeout time.Duration) (string, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	return "ok", nil
}

// radioPayload builds a payload whose wireless section carries n radios.
func radioPayload(n int) *probe.Payload {
	pl := &probe.Payload{Data: probe.PayloadData{Wireless: &probe.WirelessData{}}}
	for i := 0; i < n; i++ {
		pl.Data.Wireless.Radios = append(pl.Data.Wireless.Radios, probe.Radio{Name: "5 GHz", Channel: 48})
	}
	return pl
}

// captureLogs swaps the default logger for one that writes to a buffer.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// newTestCollector builds a Collector with fake collect, runner, clock and
// sleep hooks so tests never wait on the wall clock.
func newTestCollector(collect func(context.Context) (*probe.Payload, error), run probe.Runner, now func() time.Time, sleep func(context.Context, time.Duration)) *Collector {
	return &Collector{
		collect: collect,
		run:     run,
		now:     now,
		sleep:   sleep,
		grace:   graceWindow,
		backoff: backoffSchedule,
	}
}

func TestCollectorRetriesUntilRadiosAreReady(t *testing.T) {
	calls := 0
	var sleeps []time.Duration
	collect := func(ctx context.Context) (*probe.Payload, error) {
		calls++
		if calls == 1 {
			return &probe.Payload{}, nil
		}
		return radioPayload(1), nil
	}
	c := newTestCollector(collect, &fakeRunner{}, func() time.Time { return time.Unix(0, 0) },
		func(ctx context.Context, d time.Duration) { sleeps = append(sleeps, d) })
	payload, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error = %v, want nil", err)
	}
	if got := len(payload.Data.Wireless.GetRadios()); got != 1 {
		t.Fatalf("radios = %d, want 1: the payload must wait for the ready sample", got)
	}
	if calls != 2 {
		t.Fatalf("collect calls = %d, want 2", calls)
	}
	if len(sleeps) != 1 || sleeps[0] != 5*time.Second {
		t.Fatalf("sleeps = %v, want [5s]", sleeps)
	}
}

func TestCollectorRetriesInsideWindowThenContinues(t *testing.T) {
	logs := captureLogs(t)
	calls := 0
	var sleeps []time.Duration
	clock := time.Unix(0, 0)
	collect := func(ctx context.Context) (*probe.Payload, error) {
		calls++
		clock = clock.Add(time.Second)
		return &probe.Payload{}, nil
	}
	c := newTestCollector(collect, &fakeRunner{}, func() time.Time { return clock },
		func(ctx context.Context, d time.Duration) { sleeps = append(sleeps, d); clock = clock.Add(d) })
	payload, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error = %v, want nil", err)
	}
	if payload == nil {
		t.Fatal("Collect payload = nil, want the radio-less sample")
	}
	if calls != 5 {
		t.Fatalf("collect calls = %d, want 5 (first sample plus the whole schedule)", calls)
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 30 * time.Second, 60 * time.Second}
	if len(sleeps) != len(want) {
		t.Fatalf("sleeps = %v, want %v", sleeps, want)
	}
	for i, d := range want {
		if sleeps[i] != d {
			t.Fatalf("sleeps = %v, want %v", sleeps, want)
		}
	}
	if out := logs.String(); !strings.Contains(out, "radios still not ready after the startup grace window") {
		t.Fatalf("log = %q, want the grace window expiry line", out)
	}
}

func TestCollectorWindowExpiryCutsTheScheduleShort(t *testing.T) {
	calls := 0
	var sleeps []time.Duration
	clock := time.Unix(0, 0)
	collect := func(ctx context.Context) (*probe.Payload, error) {
		calls++
		clock = clock.Add(10 * time.Second)
		return &probe.Payload{}, nil
	}
	c := newTestCollector(collect, &fakeRunner{}, func() time.Time { return clock },
		func(ctx context.Context, d time.Duration) { sleeps = append(sleeps, d); clock = clock.Add(d) })
	payload, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error = %v, want nil", err)
	}
	if payload == nil {
		t.Fatal("Collect payload = nil, want the radio-less sample")
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 30 * time.Second}
	if len(sleeps) != len(want) {
		t.Fatalf("sleeps = %v, want %v: the next wait would end past the window", sleeps, want)
	}
	for i, d := range want {
		if sleeps[i] != d {
			t.Fatalf("sleeps = %v, want %v", sleeps, want)
		}
	}
	if calls != 4 {
		t.Fatalf("collect calls = %d, want 4", calls)
	}
}

func TestCollectorRealErrorAfterNotReadyStopsTheWait(t *testing.T) {
	calls := 0
	var sleeps []time.Duration
	boom := errors.New("server rejected the token")
	collect := func(ctx context.Context) (*probe.Payload, error) {
		calls++
		if calls < 3 {
			return &probe.Payload{}, nil
		}
		return nil, boom
	}
	c := newTestCollector(collect, &fakeRunner{}, func() time.Time { return time.Unix(0, 0) },
		func(ctx context.Context, d time.Duration) { sleeps = append(sleeps, d) })
	payload, err := c.Collect(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("Collect error = %v, want %v: real errors must not be swallowed by the grace", err, boom)
	}
	if payload != nil {
		t.Fatalf("Collect payload = %+v, want nil on error", payload)
	}
	if calls != 3 {
		t.Fatalf("collect calls = %d, want 3", calls)
	}
	if len(sleeps) != 2 {
		t.Fatalf("sleeps = %v, want two waits before the error", sleeps)
	}
}

func TestCollectorPassesRealErrorsWithoutGrace(t *testing.T) {
	boom := errors.New("server unreachable")
	calls := 0
	sleeps := 0
	collect := func(ctx context.Context) (*probe.Payload, error) {
		calls++
		return nil, boom
	}
	c := newTestCollector(collect, &fakeRunner{}, func() time.Time { return time.Unix(0, 0) },
		func(ctx context.Context, d time.Duration) { sleeps++ })
	payload, err := c.Collect(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("Collect error = %v, want %v", err, boom)
	}
	if payload != nil {
		t.Fatalf("Collect payload = %+v, want nil on error", payload)
	}
	if calls != 1 || sleeps != 0 {
		t.Fatalf("calls = %d sleeps = %d, want one call and no wait", calls, sleeps)
	}
}

func TestCollectorDoesNotWaitWithoutRadioTools(t *testing.T) {
	calls := 0
	sleeps := 0
	collect := func(ctx context.Context) (*probe.Payload, error) {
		calls++
		return &probe.Payload{}, nil
	}
	runner := &fakeRunner{err: errors.New("exit status 1")}
	c := newTestCollector(collect, runner, func() time.Time { return time.Unix(0, 0) },
		func(ctx context.Context, d time.Duration) { sleeps++ })
	payload, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error = %v, want nil", err)
	}
	if payload == nil {
		t.Fatal("Collect payload = nil, want the radio-less sample")
	}
	if calls != 1 || sleeps != 0 {
		t.Fatalf("calls = %d sleeps = %d, want one call and no wait: no radio tool can ever report radios", calls, sleeps)
	}
	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want 1", runner.calls)
	}
}

func TestCollectorGraceEndsAfterFirstRadioSample(t *testing.T) {
	calls := 0
	sleeps := 0
	collect := func(ctx context.Context) (*probe.Payload, error) {
		calls++
		if calls == 1 {
			return radioPayload(1), nil
		}
		return &probe.Payload{}, nil
	}
	clock := time.Unix(0, 0)
	c := newTestCollector(collect, &fakeRunner{}, func() time.Time { return clock },
		func(ctx context.Context, d time.Duration) { sleeps++; clock = clock.Add(d) })
	for i := 0; i < 2; i++ {
		if _, err := c.Collect(context.Background()); err != nil {
			t.Fatalf("Collect error = %v, want nil", err)
		}
	}
	if calls != 2 || sleeps != 0 {
		t.Fatalf("calls = %d sleeps = %d, want the second radio-less sample pushed as-is: the grace never re-arms", calls, sleeps)
	}
}

func TestCollectorLogsTheRetryReason(t *testing.T) {
	logs := captureLogs(t)
	calls := 0
	collect := func(ctx context.Context) (*probe.Payload, error) {
		calls++
		if calls == 1 {
			return &probe.Payload{}, nil
		}
		return radioPayload(1), nil
	}
	c := newTestCollector(collect, &fakeRunner{}, func() time.Time { return time.Unix(0, 0) },
		func(ctx context.Context, d time.Duration) {})
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Collect error = %v, want nil", err)
	}
	out := logs.String()
	if !strings.Contains(out, "radios not ready, retry 1/4 in 5s") {
		t.Fatalf("log = %q, want the retry line to name the reason", out)
	}
}

func TestCollectorContinuingIsLoggedOnce(t *testing.T) {
	logs := captureLogs(t)
	clock := time.Unix(0, 0)
	c := newTestCollector(func(ctx context.Context) (*probe.Payload, error) { return &probe.Payload{}, nil },
		&fakeRunner{}, func() time.Time { return clock },
		func(ctx context.Context, d time.Duration) { clock = clock.Add(d) })
	for i := 0; i < 3; i++ {
		if _, err := c.Collect(context.Background()); err != nil {
			t.Fatalf("Collect error = %v, want nil", err)
		}
	}
	if got := strings.Count(logs.String(), "radios still not ready after the startup grace window"); got != 1 {
		t.Fatalf("grace expiry lines = %d, want 1, log = %q", got, logs.String())
	}
}

func TestCollectorCancelledContextEndsTheWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	collect := func(ctx context.Context) (*probe.Payload, error) {
		calls++
		return &probe.Payload{}, nil
	}
	c := newTestCollector(collect, &fakeRunner{}, func() time.Time { return time.Unix(0, 0) },
		func(ctx context.Context, d time.Duration) { cancel() })
	payload, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect error = %v, want nil", err)
	}
	if payload == nil {
		t.Fatal("Collect payload = nil, want the sample collected so far")
	}
	if calls != 1 {
		t.Fatalf("collect calls = %d, want 1", calls)
	}
}

func TestCollectorCollectDataReturnsDataSection(t *testing.T) {
	c := newTestCollector(func(ctx context.Context) (*probe.Payload, error) { return radioPayload(2), nil },
		&fakeRunner{}, func() time.Time { return time.Unix(0, 0) },
		func(ctx context.Context, d time.Duration) {})
	data, err := c.CollectData(context.Background())
	if err != nil {
		t.Fatalf("CollectData error = %v, want nil", err)
	}
	if len(data.Wireless.GetRadios()) != 2 {
		t.Fatalf("radios = %d, want 2", len(data.Wireless.GetRadios()))
	}
}

func TestCollectorCollectDataPassesErrorsThrough(t *testing.T) {
	boom := errors.New("collection failed")
	c := newTestCollector(func(ctx context.Context) (*probe.Payload, error) { return nil, boom },
		&fakeRunner{}, func() time.Time { return time.Unix(0, 0) },
		func(ctx context.Context, d time.Duration) {})
	data, err := c.CollectData(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("CollectData error = %v, want %v", err, boom)
	}
	if data != nil {
		t.Fatalf("CollectData data = %+v, want nil on error", data)
	}
}

func TestNewCollectorWiresDefaults(t *testing.T) {
	c := NewCollector(probe.ShellRunner{}, "asus-main", "0.1.0")
	if c.grace != 2*time.Minute {
		t.Fatalf("grace = %v, want 2m", c.grace)
	}
	if len(c.backoff) != 4 || c.backoff[0] != 5*time.Second || c.backoff[3] != 60*time.Second {
		t.Fatalf("backoff = %v, want [5s 10s 30s 60s]", c.backoff)
	}
	if c.collect == nil || c.run == nil {
		t.Fatal("NewCollector must wire the probe collection and the runner")
	}
}
