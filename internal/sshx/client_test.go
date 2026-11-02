package sshx_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

// gateway returns a gateway allowing 127.0.0.1 for target.ssh, or nothing.
func gateway(allow bool) *egress.Gateway {
	p := policy.Defaults()
	if allow {
		p.Sovereignty.Network.Allow = []policy.AllowRule{{Host: "127.0.0.1", Purpose: policy.PurposeTargetSSH}}
	} else {
		p.Sovereignty.Network.Allow = nil
	}
	return egress.New(p, nil)
}

// deps builds Deps on the test server's in-memory agent and a temporary,
// empty known_hosts path (never the real ~/.ssh).
func deps(t *testing.T, srv *sshtest.Server, allow bool) sshx.Deps {
	t.Helper()
	ag := srv.NewAgent(t)
	return sshx.Deps{
		Gateway:    gateway(allow),
		KnownHosts: filepath.Join(t.TempDir(), "known_hosts"),
		Agent:      func() (agent.ExtendedAgent, io.Closer, error) { return ag, nil, nil },
		Now:        time.Now,
	}
}

// tgt is the server as Michel stores it, with its confirmed fingerprint.
func tgt(t *testing.T, srv *sshtest.Server, pinned bool) target.Target {
	t.Helper()
	host, port, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	tg := target.Target{ID: "01TARGETDEMO", Name: "srv-demo", Host: host, Port: p, User: "deploy"}
	if pinned {
		tg.HostKey = srv.HostKeyFingerprint()
	}
	return tg
}

func dial(t *testing.T, d sshx.Deps, tg target.Target) *sshx.Client {
	t.Helper()
	c, err := sshx.Dial(context.Background(), d, tg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func otherFingerprint(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.FingerprintSHA256(k)
}

func echoArgs(e sshtest.Exec) int {
	for _, a := range e.Args[1:] {
		io.WriteString(e.Stdout, a+"\n")
	}
	return 0
}

func TestDialThroughGateway(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{Commands: map[string]sshtest.Handler{"echo-args": echoArgs}})
	c := dial(t, deps(t, srv, true), tgt(t, srv, true))
	res, err := c.Run(context.Background(), []string{"echo-args", "hello"}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(res.Stdout) != "hello\n" || res.Exit != 0 {
		t.Fatalf("got %q exit %d", res.Stdout, res.Exit)
	}

	srv2 := sshtest.New(t, sshtest.Options{})
	_, err = sshx.Dial(context.Background(), deps(t, srv2, false), tgt(t, srv2, true))
	if !errors.Is(err, sshx.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	if !errors.Is(err, egress.ErrEgressDenied) {
		t.Fatalf("want the egress error kept, got %v", err)
	}
	if n := srv2.Accepted(); n != 0 {
		t.Fatalf("a denied dial opened %d TCP connections", n)
	}
}

func TestUnknownHostKeyReturnsFingerprint(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{})
	d := deps(t, srv, true)
	tg := tgt(t, srv, false)
	_, err := sshx.Dial(context.Background(), d, tg)
	var unk sshx.ErrHostKeyUnknown
	if !errors.As(err, &unk) {
		t.Fatalf("want ErrHostKeyUnknown, got %v", err)
	}
	if unk.Fingerprint != srv.HostKeyFingerprint() || !strings.HasPrefix(unk.Fingerprint, "SHA256:") {
		t.Fatalf("fingerprint %q, want %q", unk.Fingerprint, srv.HostKeyFingerprint())
	}
	fp, err := sshx.Fingerprint(context.Background(), d, tg)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if fp != srv.HostKeyFingerprint() {
		t.Fatalf("Fingerprint %q, want %q", fp, srv.HostKeyFingerprint())
	}
	if n := srv.AuthAttempts(); n != 0 {
		t.Fatalf("the server saw %d authentication attempts before the key was confirmed", n)
	}
}

func TestChangedHostKeyBlocksBeforeAnyCommand(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{Commands: map[string]sshtest.Handler{"echo-args": echoArgs}})
	d := deps(t, srv, true)
	tg := tgt(t, srv, false)
	tg.HostKey = otherFingerprint(t)
	_, err := sshx.Dial(context.Background(), d, tg)
	var ch sshx.ErrHostKeyChanged
	if !errors.As(err, &ch) {
		t.Fatalf("want ErrHostKeyChanged, got %v", err)
	}
	if ch.Want != tg.HostKey || ch.Got != srv.HostKeyFingerprint() {
		t.Fatalf("got %+v", ch)
	}
	if l := srv.Log(); len(l) != 0 {
		t.Fatalf("commands reached the server: %v", l)
	}
	if n := srv.AuthAttempts(); n != 0 {
		t.Fatalf("authenticated %d times against a changed host key", n)
	}

	// A known_hosts entry with another key for the host is a change too.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	ok, _ := ssh.NewPublicKey(other)
	line := knownhosts.Line([]string{knownhosts.Normalize(srv.Addr())}, ok)
	if err := os.WriteFile(d.KnownHosts, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tg.HostKey = ""
	_, err = sshx.Dial(context.Background(), d, tg)
	if !errors.As(err, &ch) || ch.Got != srv.HostKeyFingerprint() || ch.Want != ssh.FingerprintSHA256(ok) {
		t.Fatalf("want ErrHostKeyChanged from known_hosts, got %v (%+v)", err, ch)
	}
	if l := srv.Log(); len(l) != 0 {
		t.Fatalf("commands reached the server: %v", l)
	}
}

func TestKnownHostsAccepted(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{Commands: map[string]sshtest.Handler{"echo-args": echoArgs}})
	d := deps(t, srv, true)
	line := knownhosts.Line([]string{knownhosts.Normalize(srv.Addr())}, srv.HostPublicKey())
	if err := os.WriteFile(d.KnownHosts, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := dial(t, d, tgt(t, srv, false))
	if c.HostKeyFingerprint() != srv.HostKeyFingerprint() {
		t.Fatalf("fingerprint %q", c.HostKeyFingerprint())
	}
	if _, err := c.Run(context.Background(), []string{"echo-args", "x"}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNoAgentIsClear(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{})
	d := deps(t, srv, true)
	d.Agent = func() (agent.ExtendedAgent, io.Closer, error) {
		return nil, nil, errors.New("open pipe: the system cannot find the file specified")
	}
	_, err := sshx.Dial(context.Background(), d, tgt(t, srv, true))
	if !errors.Is(err, sshx.ErrNoAgent) {
		t.Fatalf("want ErrNoAgent, got %v", err)
	}
	if !strings.Contains(err.Error(), "agent") {
		t.Fatalf("message does not name the agent: %v", err)
	}
	if n := srv.Accepted(); n != 0 {
		t.Fatalf("connected %d times without an agent", n)
	}

	// An agent without any key is no agent either.
	empty := agent.NewKeyring().(agent.ExtendedAgent)
	d.Agent = func() (agent.ExtendedAgent, io.Closer, error) { return empty, nil, nil }
	_, err = sshx.Dial(context.Background(), d, tgt(t, srv, true))
	if !errors.Is(err, sshx.ErrNoAgent) {
		t.Fatalf("want ErrNoAgent for an empty agent, got %v", err)
	}
}

func TestPasswordOnlyServer(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{PasswordOnly: true})
	_, err := sshx.Dial(context.Background(), deps(t, srv, true), tgt(t, srv, true))
	if !errors.Is(err, sshx.ErrNoKeyAccepted) {
		t.Fatalf("want ErrNoKeyAccepted, got %v", err)
	}

	// A key the server does not know is refused the same way.
	srv2 := sshtest.New(t, sshtest.Options{})
	d := deps(t, srv2, true)
	stranger := agent.NewKeyring().(agent.ExtendedAgent)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := stranger.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	d.Agent = func() (agent.ExtendedAgent, io.Closer, error) { return stranger, nil, nil }
	_, err = sshx.Dial(context.Background(), d, tgt(t, srv2, true))
	if !errors.Is(err, sshx.ErrNoKeyAccepted) {
		t.Fatalf("want ErrNoKeyAccepted for an unknown key, got %v", err)
	}
}

func TestRunQuotesArgv(t *testing.T) {
	var got []string
	srv := sshtest.New(t, sshtest.Options{Commands: map[string]sshtest.Handler{
		"probe": func(e sshtest.Exec) int { got = append([]string(nil), e.Args...); return 3 },
	}})
	c := dial(t, deps(t, srv, true), tgt(t, srv, true))
	res, err := c.Run(context.Background(), []string{"probe", "a'b; rm x", "$HOME", ""}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Exit != 3 {
		t.Fatalf("exit %d", res.Exit)
	}
	want := []string{"probe", "a'b; rm x", "$HOME", ""}
	if strings.Join(got, "|") != strings.Join(want, "|") || len(got) != len(want) {
		t.Fatalf("server got %q, want %q", got, want)
	}
	if q := sshx.Quote([]string{"a'b", "c d"}); q != `'a'\''b' 'c d'` {
		t.Fatalf("Quote = %s", q)
	}
	if l := srv.Log(); len(l) != 1 || l[0] != `'probe' 'a'\''b; rm x' '$HOME' ''` {
		t.Fatalf("log %q", l)
	}
}

func TestRunStdin(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{Commands: map[string]sshtest.Handler{
		"cat": func(e sshtest.Exec) int { io.Copy(e.Stdout, e.Stdin); io.WriteString(e.Stderr, "err"); return 0 },
	}})
	c := dial(t, deps(t, srv, true), tgt(t, srv, true))
	res, err := c.Run(context.Background(), []string{"cat"}, strings.NewReader("in"))
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != "in" || string(res.Stderr) != "err" {
		t.Fatalf("got %q / %q", res.Stdout, res.Stderr)
	}
}

func TestRunCapsOutput(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{Commands: map[string]sshtest.Handler{
		"big": func(e sshtest.Exec) int {
			chunk := bytes.Repeat([]byte("x"), 64<<10)
			for i := 0; i < 40; i++ { // 2.5 MiB
				if _, err := e.Stdout.Write(chunk); err != nil {
					return 1
				}
			}
			return 0
		},
	}})
	c := dial(t, deps(t, srv, true), tgt(t, srv, true))
	res, err := c.Run(context.Background(), []string{"big"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) != sshx.MaxOutput || !res.Truncated {
		t.Fatalf("got %d bytes, truncated %v; want %d, true", len(res.Stdout), res.Truncated, sshx.MaxOutput)
	}
	if sshx.MaxOutput != 1<<20 {
		t.Fatalf("MaxOutput = %d", sshx.MaxOutput)
	}
}

func TestRunTimeout(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{Commands: map[string]sshtest.Handler{
		"hang": func(e sshtest.Exec) int { <-e.Ctx.Done(); return 1 },
	}})
	d := deps(t, srv, true)
	d.CommandTimeout = 200 * time.Millisecond
	c := dial(t, d, tgt(t, srv, true))
	start := time.Now()
	_, err := c.Run(context.Background(), []string{"hang"}, nil)
	if !errors.Is(err, sshx.ErrCommandTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want ErrCommandTimeout, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("timeout took %v", time.Since(start))
	}
	if sshx.DefaultCommandTimeout != 60*time.Second {
		t.Fatalf("DefaultCommandTimeout = %v", sshx.DefaultCommandTimeout)
	}
}

func TestConnectAudited(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := sshtest.New(t, sshtest.Options{Commands: map[string]sshtest.Handler{
		"secret": func(e sshtest.Exec) int { io.WriteString(e.Stdout, "SECRET-OUTPUT"); return 0 },
	}})
	d := deps(t, srv, true)
	d.Audit = audit.NewLogger(st, time.Now)
	c, err := sshx.Dial(context.Background(), d, tgt(t, srv, true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Run(context.Background(), []string{"secret"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	rows, err := st.DB().Query(`SELECT action, target, result, evidence FROM audit_event`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var action, tg, result, ev string
		if err := rows.Scan(&action, &tg, &result, &ev); err != nil {
			t.Fatal(err)
		}
		if action != "target.connect" {
			continue
		}
		n++
		if tg != "01TARGETDEMO" || result != "ok" {
			t.Fatalf("target %q result %q", tg, result)
		}
		for _, want := range []string{`"user":"deploy"`, `"host_key":"` + srv.HostKeyFingerprint() + `"`, `"duration_ms":`, `"result":"ok"`} {
			if !strings.Contains(ev, want) {
				t.Fatalf("evidence %s lacks %s", ev, want)
			}
		}
		if strings.Contains(ev, "SECRET") || strings.Contains(ev, "secret") {
			t.Fatalf("command or output leaked into the audit: %s", ev)
		}
	}
	if n != 1 {
		t.Fatalf("%d target.connect events, want 1", n)
	}
}

// multiKey is a server with the three usual host key types; the x/crypto
// default would negotiate ECDSA first.
func multiKey(t *testing.T) *sshtest.Server {
	return sshtest.New(t, sshtest.Options{
		HostKeyTypes: []string{"rsa", "ecdsa", "ed25519"},
		Commands:     map[string]sshtest.Handler{"echo-args": echoArgs},
	})
}

func TestKnownHostsOnlyOneKeyTypeOfSeveral(t *testing.T) {
	for _, typ := range []string{"ed25519", "rsa", "ecdsa"} {
		t.Run(typ, func(t *testing.T) {
			srv := multiKey(t)
			d := deps(t, srv, true)
			key := srv.HostPublicKeyOf(typ)
			line := knownhosts.Line([]string{knownhosts.Normalize(srv.Addr())}, key)
			if err := os.WriteFile(d.KnownHosts, []byte(line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := sshx.Dial(context.Background(), d, tgt(t, srv, false))
			if err != nil {
				t.Fatalf("known_hosts lists only the %s key: Dial: %v", typ, err)
			}
			defer c.Close()
			if c.HostKeyFingerprint() != ssh.FingerprintSHA256(key) || c.HostKeyType() != key.Type() {
				t.Fatalf("negotiated %s %s, want the %s key", c.HostKeyType(), c.HostKeyFingerprint(), typ)
			}
		})
	}
}

func TestFingerprintPrefersEd25519(t *testing.T) {
	srv := multiKey(t)
	d := deps(t, srv, true)
	tg := tgt(t, srv, false)
	want := ssh.FingerprintSHA256(srv.HostPublicKeyOf("ed25519"))
	fp, typ, err := sshx.FingerprintKey(context.Background(), d, tg)
	if err != nil {
		t.Fatal(err)
	}
	if fp != want || typ != ssh.KeyAlgoED25519 {
		t.Fatalf("Fingerprint = %s %s, want the Ed25519 key %s", typ, fp, want)
	}
	if fp2, _ := sshx.Fingerprint(context.Background(), d, tg); fp2 != want {
		t.Fatalf("Fingerprint = %s", fp2)
	}
	_, err = sshx.Dial(context.Background(), d, tg)
	var unk sshx.ErrHostKeyUnknown
	if !errors.As(err, &unk) || unk.Fingerprint != want || unk.KeyType != ssh.KeyAlgoED25519 {
		t.Fatalf("unknown host: %v (%+v)", err, unk)
	}

	// The confirmed Ed25519 fingerprint is the pin Dial checks against.
	tg.HostKey = want
	c, err := sshx.Dial(context.Background(), d, tg)
	if err != nil {
		t.Fatalf("pinned Ed25519 fingerprint refused: %v", err)
	}
	c.Close()
}

// The end of a stream cut by MaxOutput is kept apart: a script's last line
// (its outcome) is never lost.
func TestRunKeepsTailOfCutStream(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{Commands: map[string]sshtest.Handler{
		"noisy": func(e sshtest.Exec) int {
			chunk := bytes.Repeat([]byte("y"), 64<<10)
			for i := 0; i < 20; i++ { // 1.25 MiB
				if _, err := e.Stderr.Write(chunk); err != nil {
					return 1
				}
			}
			io.WriteString(e.Stderr, "\nlast line\n")
			return 1
		},
	}})
	c := dial(t, deps(t, srv, true), tgt(t, srv, true))
	res, err := c.Run(context.Background(), []string{"noisy"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || bytes.Contains(res.Stderr, []byte("last line")) {
		t.Fatalf("truncated %v", res.Truncated)
	}
	if !bytes.HasSuffix(res.StderrTail, []byte("last line\n")) || len(res.StderrTail) > sshx.TailSize {
		t.Errorf("tail %d bytes, ends %q", len(res.StderrTail), res.StderrTail[max(0, len(res.StderrTail)-20):])
	}
}
