package main

import (
	"context"
	"testing"
)

func TestRunValidatesCommonConfiguration(t *testing.T) {
	t.Setenv("NETPULSE_SERVER", "")
	t.Setenv("NETPULSE_TOKEN", "")
	t.Setenv("NETPULSE_SLUG", "")
	if err := run(context.Background()); err == nil {
		t.Fatal("expected missing configuration to fail")
	}
}
