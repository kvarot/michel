package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/agent"

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

// targetEnv is a simulated server, its agent and a fake HOME with an SSH
// configuration naming it: no real server, agent or ~/.ssh is ever reached.
type targetEnv struct {
	dir, home string
	ssh       *sshtest.Server
	pipes     []string
	// shell, when set, runs the `sh -s` scripts sent to the server (the log
	// filter); nil leaves `sh -s` unsupported.
	shell sshtest.ShellFunc
}

func newTargetEnv(t *testing.T) *targetEnv {
	t.Helper()
	e := &targetEnv{dir: t.TempDir(), home: t.TempDir()}
	e.ssh = sshtest.New(t, sshtest.Options{Shell: func(s *sshtest.Server, script string, out, errw io.Writer) int {
		if e.shell == nil {
			io.WriteString(errw, "sh: not supported\n")
			return 127
		}
		return e.shell(s, script, out, errw)
	}, Commands: map[string]sshtest.Handler{
		"cat": func(x sshtest.Exec) int {
			if len(x.Args) == 2 && x.Args[1] == "/etc/os-release" {
				io.WriteString(x.Stdout, "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nVERSION_ID=\"12\"\nID=debian\n")
				return 0
			}
			return 1
		},
		"uname":   func(x sshtest.Exec) int { io.WriteString(x.Stdout, "6.1.0-21-amd64\n"); return 0 },
		"command": func(x sshtest.Exec) int { return 1 },
		"env": func(x sshtest.Exec) int {
			i := 1
			for i < len(x.Args) && strings.Contains(x.Args[i], "=") {
				i++
			}
			switch {
			case i >= len(x.Args):
				return 127
			case x.Args[i] == "cat" && len(x.Args) == i+2 && x.Args[i+1] == "/etc/os-release":
				io.WriteString(x.Stdout, "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nVERSION_ID=\"12\"\nID=debian\n")
				return 0
			case x.Args[i] == "uname":
				io.WriteString(x.Stdout, "6.1.0-21-amd64\n")
				return 0
			}
			return 1
		},
	}})
	ag := e.ssh.NewAgent(t)
	oldAgent, oldHome := sshAgent, userHomeDir
	sshAgent = func(path string) func() (agent.ExtendedAgent, io.Closer, error) {
		e.pipes = append(e.pipes, path)
		return func() (agent.ExtendedAgent, io.Closer, error) { return ag, nil, nil }
	}
	userHomeDir = func() (string, error) { return e.home, nil }
	t.Cleanup(func() { sshAgent, userHomeDir = oldAgent, oldHome })
	host, port, _ := strings.Cut(e.ssh.Addr(), ":")
	cfg := "Host srv-demo\n  HostName " + host + "\n  User deploy\n  Port " + port + "\n  IdentityFile ~/.ssh/id_demo\n"
	if err := os.MkdirAll(filepath.Join(e.home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.home, ".ssh", "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *targetEnv) port() int {
	_, p, _ := strings.Cut(e.ssh.Addr(), ":")
	n, _ := strconv.Atoi(p)
	return n
}

func TestTargetDiscoverAndAdd(t *testing.T) {
	e := newTargetEnv(t)
	_, out, _, err := run(t, e.dir, "target", "discover")
	if err != nil || !strings.Contains(out, "srv-demo") || !strings.Contains(out, "deploy") || strings.Contains(out, "id_demo") {
		t.Fatalf("discover: %q %v", out, err)
	}
	_, out, _, err = run(t, e.dir, "target", "discover", "--json")
	var cands []map[string]any
	if err != nil || json.Unmarshal([]byte(out), &cands) != nil || len(cands) != 1 || cands[0]["Alias"] != "srv-demo" || cands[0]["Known"] != false {
		t.Fatalf("discover --json: %q %v", out, err)
	}
	// An empty HOME finds nothing and says so.
	old := userHomeDir
	userHomeDir = func() (string, error) { return t.TempDir(), nil }
	_, out, _, err = run(t, e.dir, "target", "discover")
	userHomeDir = old
	if err != nil || !strings.Contains(out, "found no server") {
		t.Errorf("empty discover: %q %v", out, err)
	}

	// Adding from the candidate takes its host, port and user, with the defaults.
	_, out, _, err = run(t, e.dir, "target", "add", "srv-demo")
	if err != nil || !strings.Contains(out, "Added server srv-demo (deploy@127.0.0.1:"+strconv.Itoa(e.port())+")") || !strings.Contains(out, "fix level 1") ||
		!strings.Contains(out, "check interval: 24h") || !strings.Contains(out, "michel target trust srv-demo") {
		t.Fatalf("add: %q %v", out, err)
	}
	_, out, _, err = run(t, e.dir, "target", "list", "--json")
	var rows []struct {
		Name, Host, User, CheckInterval string
		Port, FixLevel                  int
		HostKeyPinned, Active           bool
	}
	if err != nil || json.Unmarshal([]byte(out), &rows) != nil || len(rows) != 1 {
		t.Fatalf("list: %q %v", out, err)
	}
	if r := rows[0]; r.Name != "srv-demo" || r.Host != "127.0.0.1" || r.Port != e.port() || r.User != "deploy" || r.FixLevel != 1 || r.CheckInterval != "24h" ||
		r.HostKeyPinned || !r.Active {
		t.Errorf("row = %+v", r)
	}
	// The network rule is written in the policy file, and the candidate is now known.
	b, _ := os.ReadFile(filepath.Join(e.dir, "config.yaml"))
	if !strings.Contains(string(b), "127.0.0.1") || !strings.Contains(string(b), "target.ssh") {
		t.Errorf("policy file:\n%s", b)
	}
	_, out, _, _ = run(t, e.dir, "target", "discover", "--json")
	_ = json.Unmarshal([]byte(out), &cands)
	if len(cands) != 1 || cands[0]["Known"] != true {
		t.Errorf("after add: %s", out)
	}
	if ev := auditRows(t, e.dir, "target.add"); len(ev) != 1 || ev[0].result != "ok" || ev[0].evidence["rules_written"] != float64(1) {
		t.Errorf("audit = %+v", ev)
	}
	// By hand: a host needs --user; the manual interval and the level 0 are kept.
	if _, _, _, err := run(t, e.dir, "target", "add", "192.0.2.10"); err == nil || !strings.Contains(err.Error(), "--user") {
		t.Errorf("add without user: %v", err)
	}
	_, out, _, err = run(t, e.dir, "target", "add", "192.0.2.10", "--user", "deploy", "--name", "by-hand", "--interval", "manual", "--level", "0", "--kind", "hds", "--env", "preprod")
	if err != nil || !strings.Contains(out, "check interval: manual") || !strings.Contains(out, "fix level 0") {
		t.Fatalf("add by hand: %q %v", out, err)
	}
	// Refusals: a duplicate name, a bad interval, an unknown preprod.
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"add", "192.0.2.11", "--user", "d", "--name", "by-hand"}, "already has this name"},
		{[]string{"add", "192.0.2.12", "--user", "d", "--interval", "soon"}, "manual"},
		{[]string{"add", "192.0.2.13", "--user", "d", "--preprod", "ghost"}, "not a server of Michel"},
		{[]string{"add", "192.0.2.14", "--user", "d", "--site-url", "ftp://x"}, "http"},
	} {
		if _, _, _, err := run(t, e.dir, append([]string{"target"}, tc.args...)...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v", tc.args, err)
		}
	}
}

func TestTargetTrustFingerprint(t *testing.T) {
	e := newTargetEnv(t)
	if _, _, _, err := run(t, e.dir, "target", "add", "srv-demo"); err != nil {
		t.Fatal(err)
	}
	fp := e.ssh.HostKeyFingerprint()
	// Without --fingerprint it only shows the fingerprint: nothing is saved.
	_, out, _, err := run(t, e.dir, "target", "trust", "srv-demo")
	if err != nil || !strings.Contains(out, fp) || !strings.Contains(out, "--fingerprint "+fp) {
		t.Fatalf("show: %q %v", out, err)
	}
	pinned := func() string {
		tg, err := targetByName(t, e.dir, "srv-demo")
		if err != nil {
			t.Fatal(err)
		}
		return tg.HostKey
	}
	if pinned() != "" {
		t.Error("showing the fingerprint pinned it")
	}
	// A wrong fingerprint is refused, in clear, and saves nothing.
	_, _, _, err = run(t, e.dir, "target", "trust", "srv-demo", "--fingerprint", "SHA256:wrong")
	if err == nil || !strings.Contains(err.Error(), "not the one") || pinned() != "" {
		t.Fatalf("wrong fingerprint: %v pinned=%q", err, pinned())
	}
	_, out, _, err = run(t, e.dir, "target", "trust", "srv-demo", "--fingerprint", fp)
	if err != nil || !strings.Contains(out, "confirmed") || pinned() != fp {
		t.Fatalf("confirm: %q %v pinned=%q", out, err, pinned())
	}
	rows := auditRows(t, e.dir, "target.hostkey")
	if len(rows) != 2 || rows[0].result != "refused" || rows[1].result != "ok" {
		t.Errorf("audit = %+v", rows)
	}
	// Now a check runs against the simulated server, and counts what it finds.
	_, out, _, err = run(t, e.dir, "target", "check", "srv-demo")
	if err != nil || !strings.Contains(out, "Checked server srv-demo") {
		t.Fatalf("check: %q %v", out, err)
	}
	if _, _, _, err := run(t, e.dir, "target", "check", "nope"); err == nil || !strings.Contains(err.Error(), "No server") {
		t.Errorf("unknown server: %v", err)
	}
}

func TestTargetCheckWithoutAgentShowsNoPath(t *testing.T) {
	e := newTargetEnv(t)
	if _, _, _, err := run(t, e.dir, "target", "add", "srv-demo"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, e.dir, "target", "trust", "srv-demo", "--fingerprint", e.ssh.HostKeyFingerprint()); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(e.dir, "agent.sock")
	sshAgent = func(path string) func() (agent.ExtendedAgent, io.Closer, error) {
		return func() (agent.ExtendedAgent, io.Closer, error) {
			return nil, nil, errors.New("dial unix " + sock + ": no such file")
		}
	}
	_, _, _, err := run(t, e.dir, "target", "check", "srv-demo")
	if err == nil || !strings.Contains(err.Error(), "SSH agent") || strings.Contains(err.Error(), sock) {
		t.Errorf("check without agent: %v", err)
	}
}

func TestSSHDepsUseTheAgentPipeOfThePolicy(t *testing.T) {
	e := newTargetEnv(t)
	cfg := filepath.Join(e.dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("ssh:\n  agent_pipe: \"custom-agent\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, e.dir, "target", "list"); err != nil {
		t.Fatal(err)
	}
	// list does not open the agent; build the deps the way every command does.
	d := &Deps{Policy: policy.Defaults()}
	d.Policy.SSH.AgentPipe = "custom-agent"
	e.pipes = nil
	if sshDeps(d).Agent == nil || len(e.pipes) != 1 || e.pipes[0] != "custom-agent" {
		t.Errorf("pipes = %v", e.pipes)
	}
	d.Policy.SSH.AgentPipe = ""
	sshDeps(d)
	if len(e.pipes) != 2 || e.pipes[1] != "" {
		t.Errorf("default agent: pipes = %v", e.pipes)
	}
	// The policy file accepts the setting, and refuses a control character.
	p, _, err := policy.Load(cfg, e.dir)
	if err != nil || p.SSH.AgentPipe != "custom-agent" || policy.Validate(p) != nil {
		t.Fatalf("policy = %+v %v", p.SSH, err)
	}
	p.SSH.AgentPipe = "bad\x00pipe"
	if policy.Validate(p) == nil {
		t.Error("a control character in ssh.agent_pipe was accepted")
	}
}

func TestTargetSetAndRemove(t *testing.T) {
	e := newTargetEnv(t)
	for _, n := range []string{"alpha", "beta"} {
		if _, _, _, err := run(t, e.dir, "target", "add", "192.0.2.2"+map[string]string{"alpha": "0", "beta": "1"}[n], "--user", "deploy", "--name", n, "--env", map[string]string{"alpha": "prod", "beta": "preprod"}[n]); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := run(t, e.dir, "target", "set", "alpha"); err == nil || !strings.Contains(err.Error(), "Nothing to change") {
		t.Errorf("set nothing: %v", err)
	}
	_, out, _, err := run(t, e.dir, "target", "set", "alpha", "--level", "2", "--executor", "michel", "--sudo", "nopasswd", "--interval", "6h",
		"--site-url", "https://www.example.test/", "--preprod", "beta")
	if err != nil || !strings.Contains(out, "Updated server alpha") {
		t.Fatalf("set: %q %v", out, err)
	}
	a, err := targetByName(t, e.dir, "alpha")
	b, _ := targetByName(t, e.dir, "beta")
	if err != nil || a.FixLevel != 2 || a.Executor != target.ExecMichel || a.Sudo != target.SudoNopasswd || a.CheckInterval.Hours() != 6 ||
		a.SiteURL != "https://www.example.test/" || a.PreprodID != b.ID {
		t.Fatalf("alpha = %+v %v", a, err)
	}
	pb, _ := os.ReadFile(filepath.Join(e.dir, "config.yaml"))
	if !strings.Contains(string(pb), "www.example.test") || !strings.Contains(string(pb), "target.http") {
		t.Errorf("site rule missing:\n%s", pb)
	}
	// No chain: beta cannot get a preprod while alpha uses it, nor point at itself.
	for _, args := range [][]string{{"set", "beta", "--preprod", "alpha"}, {"set", "alpha", "--preprod", "alpha"}, {"set", "alpha", "--preprod", "ghost"}} {
		if _, _, _, err := run(t, e.dir, append([]string{"target"}, args...)...); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
	if _, _, _, err := run(t, e.dir, "target", "set", "alpha", "--preprod", "", "--interval", "manual"); err != nil {
		t.Fatal(err)
	}
	a, _ = targetByName(t, e.dir, "alpha")
	if a.PreprodID != "" || a.CheckInterval != target.ManualOnly {
		t.Errorf("alpha = %+v", a)
	}
	_, out, _, err = run(t, e.dir, "target", "remove", "alpha")
	if err != nil || !strings.Contains(out, "Removed server alpha") || !strings.Contains(out, "Nothing was changed on the server") {
		t.Fatalf("remove: %q %v", out, err)
	}
	if _, err := targetByName(t, e.dir, "alpha"); err == nil {
		t.Error("alpha is still there")
	}
	if _, _, _, err := run(t, e.dir, "target", "remove", "alpha"); err == nil || !strings.Contains(err.Error(), "No server") {
		t.Errorf("second remove: %v", err)
	}
	if ev := auditRows(t, e.dir, "target.remove"); len(ev) != 1 || ev[0].result != "ok" {
		t.Errorf("audit = %+v", ev)
	}
	// French messages, tutoiement.
	_, out, _, err = run(t, e.dir, "--lang", "fr", "target", "remove", "beta")
	if err != nil || !strings.Contains(out, "retiré") || !strings.Contains(out, "Rien n'a été changé") {
		t.Errorf("fr remove: %q %v", out, err)
	}
	_, out, _, _ = run(t, e.dir, "--lang", "fr", "target", "list")
	if !strings.Contains(out, "Aucun serveur") {
		t.Errorf("fr list: %q", out)
	}
}

// targetByName reads a server of the data folder dir.
func targetByName(t *testing.T, dir, name string) (target.Target, error) {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	return target.NewRepo(s).Get(context.Background(), name)
}
