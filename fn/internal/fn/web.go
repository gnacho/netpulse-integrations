package fn

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// userAgent: el servidor embebido de este switch responde {"logout":true,
// "reason":"notAuth"} a cualquier User-Agent que no parezca un navegador.
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"

// webClient habla con el backend que usa la propia UI del switch:
// /cgi/get.cgi?cmd=<nombre> y /cgi/set.cgi?cmd=<nombre>.
type webClient struct {
	base   string
	user   string
	pass   string
	hc     *http.Client
	authed bool
}

func newWebClient(host, user, pass string, insecure bool) (*webClient, error) {
	base := strings.TrimSuffix(host, "/")
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("fn: host %q: %w", host, err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("fn: cookie jar: %w", err)
	}
	return &webClient{
		base: base, user: user, pass: pass,
		hc: &http.Client{
			Jar:     jar,
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					// El servidor embebido (Hydra) solo negocia TLS 1.2 con
					// intercambio de claves RSA estático: sin ofrecer esas suites el
					// handshake falla con "remote error" antes de cualquier HTTP.
					// Go las dejó fuera del ClientHello por defecto, así que van
					// explícitas (y se mantienen las ECDHE por si el firmware
					// mejora algún día).
					MinVersion: tls.VersionTLS10,
					CipherSuites: []uint16{
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					},
					InsecureSkipVerify: insecure, //nolint:gosec // opt-in
				},
			},
		},
	}, nil
}

type envelope struct {
	Data   json.RawMessage `json:"data"`
	Logout bool            `json:"logout"`
	Reason string          `json:"reason"`
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
}

func (w *webClient) do(ctx context.Context, method, path, body string) (*envelope, error) {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, w.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := w.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fn: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("fn: leer %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fn: %s: %s: %s", path, resp.Status, firstLine(string(raw)))
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("fn: %s no es JSON: %w (%s)", path, err, firstLine(string(raw)))
	}
	return &env, nil
}

// login: los tres pasos que hace la UI. El order importa:
//  1. GET  home_login      → sella login_txn
//  2. POST home_loginAuth  → valida la credencial
//  3. GET  home_loginStatus → es DONDE se sella la cookie "session"; sin ella
//     cualquier cmd responde notAuth.
//
// El cuerpo va SIN codificar por porcentaje: el servidor no decodifica el
// form-urlencoded y un "@" convertido en "%40" llega como usuario inválido
// (responde save_success igualmente, así que no se puede detectar por ahí).
func (w *webClient) login(ctx context.Context) error {
	if _, err := w.do(ctx, http.MethodGet, "/cgi/get.cgi?cmd=home_login", ""); err != nil {
		return err
	}
	env, err := w.do(ctx, http.MethodPost, "/cgi/set.cgi?cmd=home_loginAuth",
		"username="+w.user+"&password="+w.pass)
	if err != nil {
		return err
	}
	if env.Status != "" && env.Status != "ok" {
		return fmt.Errorf("fn: login rechazado: %s %s", env.Status, env.Msg)
	}
	env, err = w.do(ctx, http.MethodGet, "/cgi/get.cgi?cmd=home_loginStatus", "")
	if err != nil {
		return err
	}
	var st struct {
		Status     string `json:"status"`
		FailReason string `json:"failReason"`
	}
	if len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, &st); err != nil {
			return fmt.Errorf("fn: estado de login: %w", err)
		}
	}
	if st.Status != "ok" {
		return fmt.Errorf("fn: login no autenticado (status=%q %s)", st.Status, st.FailReason)
	}
	return nil
}

// get lee un cmd y lo decodifica en out. La sesión se REUTILIZA: el equipo
// tiene pocas ranuras de sesión (login de más responde errLoginSessionNum),
// así que solo se vuelve a entrar cuando una respuesta dice notAuth.
func (w *webClient) get(ctx context.Context, cmd string, out any) error {
	if !w.authed {
		if err := w.login(ctx); err != nil {
			return err
		}
		w.authed = true
	}
	for attempt := 0; attempt < 2; attempt++ {
		env, err := w.do(ctx, http.MethodGet,
			fmt.Sprintf("/cgi/get.cgi?cmd=%s&dummy=%d", cmd, time.Now().UnixMilli()), "")
		if err != nil {
			return err
		}
		if env.Logout {
			w.authed = false
			if err := w.login(ctx); err != nil {
				return err
			}
			w.authed = true
			continue
		}
		if len(env.Data) == 0 {
			return fmt.Errorf("fn: cmd=%s no devolvió data", cmd)
		}
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("fn: cmd=%s: %w", cmd, err)
		}
		return nil
	}
	return fmt.Errorf("fn: cmd=%s: sesión rechazada dos veces", cmd)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160]
	}
	return strings.TrimSpace(s)
}
