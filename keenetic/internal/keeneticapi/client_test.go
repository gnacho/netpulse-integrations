package keeneticapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeRouter is a minimal KeeneticOS RCI stand-in: the challenge handshake,
// one protected section, and configurable failure modes.
type fakeRouter struct {
	server    *httptest.Server
	cookies   map[string]string // cookie name -> value issued by /auth
	challenge string
	realm     string
	password  string
	// paths serves GET /rci/<path>; absence answers 404.
	paths map[string]string
	// http200Error makes the next /rci answer HTTP 200 with an error envelope.
	http200Error bool
	// authFailures counts rejected POST /auth attempts.
	authFailures int
	// rcCalls counts authenticated /rci requests (auth calls excluded).
	rcCalls int
	// authCalls counts GET /auth handshakes.
	authCalls int
}

func newFakeRouter(t *testing.T) *fakeRouter {
	t.Helper()
	f := &fakeRouter{
		cookies:   map[string]string{},
		challenge: "0123456789abcdef0123456789abcdef",
		realm:     "Keenetic Test",
		password:  "hunter2",
		paths: map[string]string{
			"show/version": `{"title":"5.1","model":"Ultra (KN-1811)","hw_id":"KN-1811"}`,
			"show/system":  `{"hostname":"keenetic-test","cpuload":7,"memtotal":262144,"memfree":131072,"uptime":3600}`,
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			f.authCalls++
			name := "sess-" + fmt.Sprint(f.authCalls)
			f.cookies[name] = "sid-" + name
			w.Header().Set("X-NDM-Realm", f.realm)
			w.Header().Set("X-NDM-Challenge", f.challenge)
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("x-ndw2-interactive realm=%q challenge=%q session_cookie=%q", f.realm, f.challenge, name))
			http.SetCookie(w, &http.Cookie{Name: name, Value: f.cookies[name], HttpOnly: true})
			w.WriteHeader(http.StatusUnauthorized)
		case http.MethodPost:
			var body struct {
				Login    string `json:"login"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			if body.Password != authKey(body.Login, f.password, f.realm, f.challenge) {
				f.authFailures++
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// The router answers the submit with an empty object and the
			// session cookie the jar already carries.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	})
	mux.HandleFunc("/rci/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/rci/")
		var session *http.Cookie
		for _, c := range r.Cookies() {
			// Validate the VALUE against the session the fake issued: after
			// the test wipes f.cookies the old jar entry must stop working,
			// which is what drives the transparent re-auth path.
			if c.Value != "" && f.cookies[c.Name] == c.Value {
				session = c
				break
			}
		}
		if session == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.http200Error {
			f.http200Error = false
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":[{"status":"error","code":"6553609","ident":"Network::Interface::Base","message":"unable to find (empty)."}]}`))
			return
		}
		body, ok := f.paths[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f.rcCalls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// clientFor returns a client pointed at the fake router.
func clientFor(t *testing.T, f *fakeRouter) *Client {
	t.Helper()
	c, err := New(Config{Host: f.server.URL, User: "netpulse", Password: f.password})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestAuthenticateHandshake(t *testing.T) {
	f := newFakeRouter(t)
	c := clientFor(t, f)
	body, err := c.Get(context.Background(), "show/version")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	var version struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &version); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if version.Model != "Ultra (KN-1811)" {
		t.Fatalf("model = %q", version.Model)
	}
	if f.authCalls != 1 {
		t.Fatalf("auth handshakes = %d, want 1", f.authCalls)
	}
	if f.rcCalls != 1 {
		t.Fatalf("rci calls = %d, want 1", f.rcCalls)
	}
}

func TestReauthAfterSessionLoss(t *testing.T) {
	f := newFakeRouter(t)
	c := clientFor(t, f)
	if _, err := c.Get(context.Background(), "show/system"); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	// Simulate the 300-second sliding window closing: the router forgets the
	// session, the next call must transparently re-authenticate and succeed.
	f.authCalls = 0
	f.cookies = map[string]string{} // every issued cookie is now invalid
	if _, err := c.Get(context.Background(), "show/system"); err != nil {
		t.Fatalf("Get after session loss: %v", err)
	}
	if f.authCalls != 1 {
		t.Fatalf("auth handshakes after loss = %d, want exactly one re-auth", f.authCalls)
	}
}

func TestWrongPasswordIsTerminal(t *testing.T) {
	f := newFakeRouter(t)
	c, err := New(Config{Host: f.server.URL, User: "netpulse", Password: "wrong"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Get(context.Background(), "show/system")
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("err = %v, want AuthError", err)
	}
	if !authErr.Terminal() {
		t.Fatal("AuthError must be terminal so the poller stops retrying")
	}
	if f.authFailures != 1 {
		t.Fatalf("rejected auth attempts = %d, want 1 (no brute-force hammering)", f.authFailures)
	}
}

func TestNotFoundPerPath(t *testing.T) {
	f := newFakeRouter(t)
	c := clientFor(t, f)
	_, err := c.Get(context.Background(), "show/mws")
	var nf *NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("err = %v, want NotFoundError", err)
	}
}

func TestTryGetPicksFirstExistingPath(t *testing.T) {
	f := newFakeRouter(t)
	f.paths["show/ip/dhcp/binding"] = `[{"mac":"AA:BB:CC:00:00:01","ip":"192.168.1.100","name":"server"}]`
	c := clientFor(t, f)
	body, path, err := c.TryGet(context.Background(), "show/ip/dhcp/bindings", "show/ip/dhcp/binding")
	if err != nil {
		t.Fatalf("TryGet: %v", err)
	}
	if path != "show/ip/dhcp/binding" {
		t.Fatalf("path = %q, want the variant the firmware answered", path)
	}
	if !strings.Contains(string(body), "AA:BB:CC:00:00:01") {
		t.Fatalf("body = %s", body)
	}
}

func TestTryGetAllMissing(t *testing.T) {
	f := newFakeRouter(t)
	c := clientFor(t, f)
	_, _, err := c.TryGet(context.Background(), "show/a", "show/b")
	var nf *NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("err = %v, want NotFoundError", err)
	}
	if len(nf.Paths) != 2 {
		t.Fatalf("missing paths = %v", nf.Paths)
	}
}

func TestErrorInsideHTTP200(t *testing.T) {
	f := newFakeRouter(t)
	c := clientFor(t, f)
	f.http200Error = true
	_, err := c.Get(context.Background(), "show/system")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want APIError", err)
	}
	if apiErr.Ident != "Network::Interface::Base" || apiErr.Message != "unable to find (empty)." {
		t.Fatalf("apiErr = %+v", apiErr)
	}
}

func TestAuthKeyScheme(t *testing.T) {
	// The scheme: md5(login:realm:password) lowercase hex, then
	// sha256(challenge + md5hex) lowercase hex. Fixed vectors so a silent
	// change of separator or case cannot pass unnoticed.
	got := authKey("admin", "pass", "Keenetic Ultra", "challengesecret")
	const want = "d183fda958d703e1f309c86b488fb64d09b0992f173ec9dc5f9db8f3c0617fc4"
	if got != want {
		t.Fatalf("authKey = %s, want %s", got, want)
	}
}
