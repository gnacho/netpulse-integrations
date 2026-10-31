package fn

import (
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// El CLI de este switch es la única fuente de la temperatura (el backend web
// no tiene ningún cmd de ventilador/sonda) y da la memoria en KB reales.
// No es camino crítico: si el SSH falla, el pusher sigue entregando todo lo
// demás y esas dos vitals quedan nil (contrato de #441: nil, no cero).
type cliClient struct {
	addr    string
	user    string
	pass    string
	hostFP  string
	timeout time.Duration
}

// sample: temperatura en °C y memoria en KB (0 = no leída).
type sample struct {
	tempC   int
	hasTemp bool
	totalKB float64
	freeKB  float64
	hasMem  bool
}

var (
	reTemp = regexp.MustCompile(`temperature_c\s*=\s*(\d+)`)
	// "Mem:          256088        87412       168676            0            0            0"
	reMem = regexp.MustCompile(`(?m)^Mem:\s+(\d+)\s+(\d+)\s+(\d+)`)
)

func (c *cliClient) sample(ctx context.Context) (*sample, error) {
	cfg := &ssh.ClientConfig{
		User:            c.user,
		Auth:            []ssh.AuthMethod{ssh.Password(c.pass)},
		HostKeyCallback: c.hostKeyCallback(),
		Timeout:         c.timeout,
		Config:          ssh.Config{},
	}
	conn, err := ssh.Dial("tcp", c.addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("fn: ssh %s: %w", c.addr, err)
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("fn: sesión ssh: %w", err)
	}
	defer sess.Close()
	// Sin PTY este CLI ejecuta pero no escribe absolutamente nada.
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty("vt100", 24, 80, modes); err != nil {
		return nil, fmt.Errorf("fn: pty: %w", err)
	}
	in, err := sess.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := sess.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := sess.Shell(); err != nil {
		return nil, fmt.Errorf("fn: shell: %w", err)
	}

	e := &expect{in: in, ch: make(chan []byte, 64), secret: c.pass}
	go pump(out, e.ch)

	// El gate "Press <Enter>" pinta su prompt antes de armar el lector y se
	// come la primera línea que mande el cliente; eso desplaza usuario y
	// contraseña una línea (la contraseña acababa en "Username:"). Se tira un
	// Enter de más nada más abrir el canal y luego se contesta SIEMPRE el
	// prompt que está en pantalla.
	e.send("\r")
	time.Sleep(2 * time.Second)
	prompts := []string{"Username:", "Password:", "Switch#", "Switch>", "Authentication Failed", "Login incorrect"}
	inside := false
	for round := 0; round < 8 && !inside; round++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		idx, txt := e.wait(prompts, 15*time.Second)
		if idx < 0 {
			return nil, fmt.Errorf("fn: login ssh sin progreso: %s", firstLine(txt))
		}
		switch prompts[idx] {
		case "Username:":
			e.send(c.user + "\r")
		case "Password:":
			e.send(c.pass + "\r")
		case "Authentication Failed", "Login incorrect":
			// el equipo reabre el login; la siguiente ronda contesta lo que pida
		default:
			inside = true
		}
		time.Sleep(2 * time.Second)
	}
	if !inside {
		return nil, fmt.Errorf("fn: login ssh no llegó al prompt")
	}

	raw := e.run(ctx, "show fan") + "\n" + e.run(ctx, "show memory statistics")
	s := &sample{}
	if m := reTemp.FindStringSubmatch(raw); m != nil {
		if v, err := strconv.Atoi(m[1]); err == nil && v > 0 {
			s.tempC, s.hasTemp = v, true
		}
	}
	if m := reMem.FindStringSubmatch(raw); m != nil {
		total, _ := strconv.ParseFloat(m[1], 64)
		used, _ := strconv.ParseFloat(m[2], 64)
		free, _ := strconv.ParseFloat(m[3], 64)
		if total > 0 {
			s.totalKB, s.freeKB, s.hasMem = total, free+used*0, true
			s.freeKB = free
		}
	}
	e.send("exit\r")
	time.Sleep(300 * time.Millisecond)
	if !s.hasTemp && !s.hasMem {
		return nil, fmt.Errorf("fn: el CLI no devolvió ni fan ni memoria")
	}
	return s, nil
}

func (c *cliClient) hostKeyCallback() ssh.HostKeyCallback {
	want := strings.TrimPrefix(c.hostFP, "SHA256:")
	if want == "" {
		// Igual que FN_INSECURE para el canal web: sin huella fijada el
		// pusher acepta la del momento (red local de confianza).
		return func(string, net.Addr, ssh.PublicKey) error { return nil }
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		got := strings.TrimPrefix(ssh.FingerprintSHA256(key), "SHA256:")
		if got != want {
			return fmt.Errorf("fn: hostkey %s no coincide con el fijado %s", got, want)
		}
		return nil
	}
}

func pump(out io.Reader, ch chan<- []byte) {
	b := make([]byte, 4096)
	for {
		n, err := out.Read(b)
		if n > 0 {
			ch <- append([]byte(nil), b[:n]...)
		}
		if err != nil {
			close(ch)
			return
		}
	}
}

type expect struct {
	in     io.WriteCloser
	ch     chan []byte
	buf    strings.Builder
	secret string
}

func (e *expect) mask(s string) string {
	if e.secret != "" {
		s = strings.ReplaceAll(s, e.secret, "<pw>")
	}
	return s
}

func (e *expect) wait(patterns []string, timeout time.Duration) (int, string) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case b := <-e.ch:
			e.buf.Write(b)
		case <-time.After(200 * time.Millisecond):
		}
		s := cleanTTY(e.buf.String())
		for i, p := range patterns {
			if strings.Contains(s, p) {
				e.buf.Reset()
				return i, s
			}
		}
	}
	s := cleanTTY(e.buf.String())
	e.buf.Reset()
	return -1, s
}

func (e *expect) send(s string) { _, _ = io.WriteString(e.in, s) }

// run manda un comando y devuelve su salida hasta que vuelve el prompt.
func (e *expect) run(ctx context.Context, cmd string) string {
	if ctx.Err() != nil {
		return ""
	}
	e.send(cmd + "\r")
	limit := time.Now().Add(30 * time.Second)
	acc := strings.Builder{}
	prompts := []string{"--More--", "Switch#", "Switch>"}
	for time.Now().Before(limit) {
		idx, txt := e.wait(prompts, 10*time.Second)
		acc.WriteString(txt)
		if idx < 0 {
			break
		}
		if prompts[idx] == "--More--" {
			e.send(" ") // el paginador se traga la línea siguiente si no se le da
			continue
		}
		break
	}
	return acc.String()
}

// cleanTTY quita las secuencias de escape (el CLI limpia pantalla con CSI H/J)
// y los CR, para que la salida se pueda parsear tal cual.
func cleanTTY(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && !((s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z')) {
				j++
			}
			i = j
			continue
		}
		if s[i] == '\r' {
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
