package push

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

func TestSendDoesNotForwardCredentialsAcrossOrigins(t *testing.T) {
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

			handler := func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-Agent-Signature") == "" {
					t.Errorf("source did not receive signed request")
				}
				http.Redirect(w, r, target.URL, http.StatusFound)
			}
			url := ""
			pin := ""
			if downgrade {
				secure := httptest.NewTLSServer(http.HandlerFunc(handler))
				defer secure.Close()
				sum := sha256.Sum256(secure.Certificate().RawSubjectPublicKeyInfo)
				pin = hex.EncodeToString(sum[:])
				url = secure.URL
			} else {
				source := httptest.NewServer(http.HandlerFunc(handler))
				defer source.Close()
				url = source.URL
			}

			client, err := NewClient(url, time.Second, "", pin)
			if err != nil {
				t.Fatal(err)
			}
			err = client.Send(context.Background(), "secret", probe.Payload{Router: "test"})
			if err == nil || !strings.Contains(err.Error(), "another origin") {
				t.Fatalf("Send error = %v, want origin refusal", err)
			}
			if got := targetHits.Load(); got != 0 {
				t.Fatalf("redirect target received %d requests", got)
			}
		})
	}
}

func TestSendRejectsRedirectThatWouldChangeTheMethod(t *testing.T) {
	var targetHits atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("moved") == "" {
			http.Redirect(w, r, server.URL+"/api/ingest/agent?moved=1", http.StatusFound)
			return
		}
		targetHits.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, time.Second, "", "")
	if err != nil {
		t.Fatal(err)
	}
	err = client.Send(context.Background(), "secret", probe.Payload{Router: "test"})
	if err == nil || !strings.Contains(err.Error(), "changes the request method") {
		t.Fatalf("Send error = %v, want method-change refusal", err)
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests, the unsigned GET must not be sent", got)
	}
}

func TestSendFollowsSameOriginRedirect(t *testing.T) {
	var hits atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			http.Redirect(w, r, server.URL+"/api/ingest/agent?moved=1", http.StatusTemporaryRedirect)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("method after redirect = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Errorf("Authorization after redirect = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		mac := hmac.New(sha256.New, []byte("secret"))
		mac.Write(body)
		if got, want := r.Header.Get("X-Agent-Signature"), hex.EncodeToString(mac.Sum(nil)); got != want {
			t.Errorf("signature after redirect does not match the resent body")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, time.Second, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Send(context.Background(), "secret", probe.Payload{Router: "test"}); err != nil {
		t.Fatalf("Send error = %v, want success after a 307", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("handler hits = %d, want 2 (original plus redirect)", got)
	}
}
