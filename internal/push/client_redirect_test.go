package push

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

func TestSendDoesNotForwardCredentialsAcrossRedirects(t *testing.T) {
	for _, downgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "cross-origin", true: "https-to-http"}[downgrade], func(t *testing.T) {
			var targetHits atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetHits.Add(1)
				if r.Header.Get("Authorization") != "" || r.Header.Get("X-Agent-Signature") != "" {
					t.Errorf("redirect leaked credentials/signature")
				}
			}))
			defer target.Close()
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-Agent-Signature") == "" {
					t.Errorf("source did not receive signed request")
				}
				http.Redirect(w, r, target.URL, http.StatusFound)
			}))
			defer source.Close()
			url := source.URL
			pin := ""
			if downgrade {
				source.Close()
				secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-Agent-Signature") == "" {
						t.Errorf("source did not receive signed request")
					}
					http.Redirect(w, r, target.URL, http.StatusFound)
				}))
				defer secure.Close()
				sum := sha256.Sum256(secure.Certificate().RawSubjectPublicKeyInfo)
				pin = hex.EncodeToString(sum[:])
				url = secure.URL
			}
			client, err := NewClient(url, time.Second, "", pin)
			if err != nil {
				t.Fatal(err)
			}
			err = client.Send(context.Background(), "secret", probe.Payload{Router: "test"})
			if err == nil || !strings.Contains(err.Error(), "302") {
				t.Fatalf("Send error = %v, want redirect response", err)
			}
			if got := targetHits.Load(); got != 0 {
				t.Fatalf("redirect target received %d requests", got)
			}
		})
	}
}
