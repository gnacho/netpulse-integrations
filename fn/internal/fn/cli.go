package fn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// The CLI is the only source of the fan temperature (the web backend has no
// fan or sensor cmd at all) and it reports memory in real kilobytes. It is not
// on the critical path: when SSH fails the pusher still delivers everything
// else and those two vitals stay nil (#441: nil, never a fabricated zero).
type cliClient struct {
	addr    string
	user    string
	pass    string
	hostFP  string
	timeout time.Duration
}

// sample: fan temperature in Celsius and memory in KB (0 = not read). usedKB is
// the device's own used column, which is what the payload reports so the server
// does not have to derive it from total minus free.
type sample struct {
	tempC   int
	hasTemp bool
	totalKB float64
	usedKB  float64
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
		return nil, fmt.Errorf("fn: ssh session: %w", err)
	}
	defer sess.Close()
	// Without a PTY this CLI runs the commands and writes nothing at all: the
	// exec channel exits 0 with empty output.
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

	// The "Press <Enter>" gate draws its prompt before it arms the reader, so
	// the first line the client sends is swallowed; that shifts username and
	// password by one prompt each (the password used to land on "Username:").
	// One throwaway Enter goes out as soon as the channel opens, and after that
	// the loop always answers whatever prompt is actually on screen.
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
			return nil, fmt.Errorf("fn: ssh login made no progress: %s", txt)
		}
		switch prompts[idx] {
		case "Username:":
			e.send(c.user + "\r")
		case "Password:":
			e.send(c.pass + "\r")
		case "Authentication Failed", "Login incorrect":
			// the device reopens the login; the next round answers what it asks
		default:
			inside = true
		}
		time.Sleep(2 * time.Second)
	}
	if !inside {
		return nil, fmt.Errorf("fn: ssh login never reached a prompt")
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
			s.totalKB, s.usedKB, s.freeKB, s.hasMem = total, used, free, true
		}
	}
	e.send("exit\r")
	time.Sleep(300 * time.Millisecond)
	if !s.hasTemp && !s.hasMem {
		return nil, fmt.Errorf("fn: the CLI returned neither fan nor memory")
	}
	return s, nil
}

func (c *cliClient) hostKeyCallback() ssh.HostKeyCallback {
	want := strings.TrimPrefix(c.hostFP, "SHA256:")
	if want == "" {
		// No pinned key means no session: New() already refuses a password
		// without a fingerprint, so this is the backstop that keeps a directly
		// built client from ever sending credentials to an unknown host.
		return func(string, net.Addr, ssh.PublicKey) error {
			return errors.New("fn: no ssh_host_fp pinned, refusing the CLI channel")
		}
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		got := strings.TrimPrefix(ssh.FingerprintSHA256(key), "SHA256:")
		if got != want {
			return fmt.Errorf("fn: hostkey %s does not match the pinned %s", got, want)
		}
		return nil
	}
}

// pump copies the session output into ch and closes it when the reader is done,
// which is how wait learns the connection died.
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

// mask keeps the password out of everything the caller may log. A misaligned
// login sequence echoes it on the Username: line, and the accumulated screen is
// exactly what the failure messages quote.
func (e *expect) mask(s string) string {
	if e.secret != "" {
		s = strings.ReplaceAll(s, e.secret, "<pw>")
	}
	return s
}

// render is the screen as text, cleaned and masked, without consuming it: the
// patterns are matched against the accumulated buffer, so a prompt split across
// two reads still has to be visible on the next pass.
func (e *expect) render() string { return e.mask(cleanTTY(e.buf.String())) }

// drain returns the same text and consumes the buffer, which is what a resolved
// or abandoned wait owes the next caller.
func (e *expect) drain() string {
	s := e.render()
	e.buf.Reset()
	return s
}

// wait returns the index of the first pattern to appear on screen, or -1 when
// the timeout runs out or the output stops. A closed channel is terminal and
// must return at once: receiving from it yields a zero slice forever, so the
// naive receive would spin on a core for the whole 10-15 s of its timeout while
// the session is already dead.
func (e *expect) wait(patterns []string, timeout time.Duration) (int, string) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case b, ok := <-e.ch:
			if !ok {
				return -1, e.drain()
			}
			e.buf.Write(b)
		case <-time.After(200 * time.Millisecond):
		}
		s := e.render()
		for i, p := range patterns {
			if strings.Contains(s, p) {
				e.buf.Reset()
				return i, s
			}
		}
	}
	return -1, e.drain()
}

func (e *expect) send(s string) { _, _ = io.WriteString(e.in, s) }

// run sends one command and returns its output until the prompt comes back.
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
			e.send(" ") // the pager eats the next line unless it is fed
			continue
		}
		break
	}
	return acc.String()
}

// cleanTTY strips the escape sequences (this CLI clears the screen with CSI H/J)
// and the carriage returns, so the output can be parsed as it stands.
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
