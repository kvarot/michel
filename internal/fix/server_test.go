package fix

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/serverrules"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

const (
	srvBackups = "/var/lib/michel/backups/"
	demoSite   = "https://example.test"
)

// demoServer is one simulated server: its sshtest server, its shells, its
// stored target and the inventory the fake check starts from.
type demoServer struct {
	srv    *sshtest.Server
	root   *sshtest.Shell
	t      target.Target
	ver    string // PHP branch, "8.2"
	ini    string // the FPM php.ini
	cliIni string
	fpm    string // the FPM binary
	cli    string // the CLI binary

	mu        sync.Mutex
	fpmTest   int    // exit of php-fpm -t
	reloads   []int  // exit of each systemctl reload, in turn (then 0)
	cliStderr string // what php -c prints on its error output
	sim       string // apt-get -s output
	pkgVer    string // installed libdemo version
	aptExit   int    // exit of apt-get install
	// onFPMTest, when set, runs while the script is at php-fpm -t (outside
	// the lock): a test acts there in the middle of a run.
	onFPMTest func(e sshtest.Exec)
}

// serverFixture is a store, the fix service's deps and the demo servers.
type serverFixture struct {
	t       *testing.T
	st      *store.Store
	d       Deps
	targets *target.Repo
	gw      *egress.Gateway
	clock   time.Time
	servers map[string]*demoServer
	alerts  []servercheck.AlertInput
	// siteDown, when set, tells whether the site of a server answers.
	siteDown func(s *demoServer) bool
	siteGETs int
	// pkgFinding adds a libdemo advisory to the check of every server.
	pkgFinding bool
	agents     []agent.ExtendedAgent
}

func newServerFixture(t *testing.T) *serverFixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &serverFixture{t: t, st: st, targets: target.NewRepo(st), clock: time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC), servers: map[string]*demoServer{}}
	pol := policy.Defaults()
	pol.Sovereignty.Network.Allow = []policy.AllowRule{{Host: "127.0.0.1", Purpose: policy.PurposeTargetSSH}}
	f.gw = egress.New(pol, nil)
	now := func() time.Time { return f.clock }
	secrets, err := secret.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f.d = Deps{
		Secrets: secrets,
		Store:   st, Audit: audit.NewLogger(st, now), Lang: i18n.EN, Now: now, Actor: "test", Sessions: NewSessions(),
		Targets:     f.targets,
		SSH:         sshx.Deps{Gateway: f.gw, KnownHosts: filepath.Join(t.TempDir(), "known_hosts"), Now: time.Now},
		CheckServer: f.check,
		SiteCheck: func(ctx context.Context, url string) error {
			f.siteGETs++
			for _, s := range f.servers {
				if s.t.SiteURL == url && f.siteDown != nil && f.siteDown(s) {
					return errors.New("site down")
				}
			}
			return nil
		},
		Alert: func(ctx context.Context, in servercheck.AlertInput) { f.alerts = append(f.alerts, in) },
	}
	return f
}

// tick moves the clock on, so each inventory is newer than the last.
func (f *serverFixture) tick() time.Time {
	f.clock = f.clock.Add(time.Minute)
	return f.clock
}

const demoIni = "[PHP]\nengine = On\nexpose_php = On\nmemory_limit = 128M\n"

// addServer starts a server whose PHP branch is ver ("8.2"), with the php.ini
// text ini, and stores its target (executor, sudo).
func (f *serverFixture) addServer(name, ver, ini string, exec target.Executor, sudo target.SudoMode, mod func(*target.Target)) *demoServer {
	t := f.t
	t.Helper()
	s := &demoServer{ver: ver, ini: "/etc/php/" + ver + "/fpm/php.ini", cliIni: "/etc/php/" + ver + "/cli/php.ini",
		fpm: "/usr/sbin/php-fpm" + ver, cli: "/usr/bin/php" + ver, pkgVer: "1.0-1"}
	s.root = &sshtest.Shell{UID: 0, Home: "/root"}
	user := &sshtest.Shell{UID: 1000, Home: "/home/deploy"}
	var srv *sshtest.Server
	var apt sshtest.Handler
	cat := func(e sshtest.Exec, p string) int {
		v, ok := srv.File(p)
		if !ok {
			io.WriteString(e.Stderr, "cat: no such file\n")
			return 1
		}
		io.WriteString(e.Stdout, v)
		return 0
	}
	srv = sshtest.New(t, sshtest.Options{
		Files: map[string]string{s.ini: ini, s.cliIni: "[PHP]\nallow_url_include = On\n", s.fpm: "ELF", s.cli: "ELF", "/var/lib/dpkg/status": ""},
		Sudo:  sudo == target.SudoNopasswd, Shell: user.Func(), RootShell: s.root.Func(),
		Commands: map[string]sshtest.Handler{
			s.fpm: func(e sshtest.Exec) int {
				if s.onFPMTest != nil {
					s.onFPMTest(e)
				}
				s.mu.Lock()
				defer s.mu.Unlock()
				return s.fpmTest
			},
			s.cli: func(e sshtest.Exec) int {
				s.mu.Lock()
				defer s.mu.Unlock()
				io.WriteString(e.Stderr, s.cliStderr)
				return 0
			},
			"systemctl": func(e sshtest.Exec) int {
				s.mu.Lock()
				defer s.mu.Unlock()
				if len(s.reloads) == 0 {
					return 0
				}
				code := s.reloads[0]
				s.reloads = s.reloads[1:]
				return code
			},
			"apt-get": func(e sshtest.Exec) int { return apt(e) },
			// sudo -n cat of a root backup, sudo -n apt-get -s (sudo
			// nopasswd only: the server refuses sudo otherwise).
			"sudo": func(e sshtest.Exec) int {
				if len(e.Args) == 4 && e.Args[1] == "-n" && e.Args[2] == "cat" {
					return cat(e, e.Args[3])
				}
				if len(e.Args) > 3 && e.Args[1] == "-n" && e.Args[2] == "apt-get" {
					e.Args = e.Args[2:]
					return apt(e)
				}
				return 1
			},
			// cat as the SSH user: a root backup folder is not readable.
			"cat": func(e sshtest.Exec) int {
				if len(e.Args) != 2 || strings.HasPrefix(e.Args[1], "/var/lib/michel") {
					io.WriteString(e.Stderr, "cat: permission denied\n")
					return 1
				}
				p := e.Args[1]
				if !strings.HasPrefix(p, "/") {
					p = "/home/deploy/" + p
				}
				return cat(e, p)
			},
		},
	})
	apt = func(e sshtest.Exec) int {
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(e.Args) > 1 && e.Args[1] == "-s" {
			io.WriteString(e.Stdout, s.sim)
			return 0
		}
		if s.aptExit != 0 {
			return s.aptExit
		}
		s.pkgVer = "1.1-1"
		return 0
	}
	s.srv = srv
	host, port, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	pn, _ := strconv.Atoi(port)
	tg := target.Target{Name: name, Host: host, Port: pn, User: "deploy", HostKey: srv.HostKeyFingerprint(), Kind: target.KindVPS,
		Env: target.EnvProd, FixLevel: 1, Executor: exec, Sudo: sudo, SiteURL: "https://" + name + ".example.test"}
	if mod != nil {
		mod(&tg)
	}
	if tg, err = f.targets.Add(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	s.t = tg
	// Each server accepts its own key; the agent holds them all.
	f.agents = append(f.agents, srv.NewAgent(t))
	agents := append(multiAgent(nil), f.agents...)
	f.d.SSH.Agent = func() (agent.ExtendedAgent, io.Closer, error) { return agents, nil, nil }
	f.servers[tg.ID] = s
	return s
}

// multiAgent offers the keys of several in-memory agents (one per test
// server).
type multiAgent []agent.ExtendedAgent

func (m multiAgent) List() ([]*agent.Key, error) {
	var out []*agent.Key
	for _, a := range m {
		ks, err := a.List()
		if err != nil {
			return nil, err
		}
		out = append(out, ks...)
	}
	return out, nil
}

func (m multiAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return m.SignWithFlags(key, data, 0)
}

func (m multiAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	for _, a := range m {
		if sig, err := a.SignWithFlags(key, data, flags); err == nil {
			return sig, nil
		}
	}
	return nil, errors.New("no such key")
}

func (m multiAgent) Signers() ([]ssh.Signer, error) {
	var out []ssh.Signer
	for _, a := range m {
		ss, err := a.Signers()
		if err != nil {
			return nil, err
		}
		out = append(out, ss...)
	}
	return out, nil
}

func (m multiAgent) Add(agent.AddedKey) error   { return errors.New("read only") }
func (m multiAgent) Remove(ssh.PublicKey) error { return errors.New("read only") }
func (m multiAgent) RemoveAll() error           { return errors.New("read only") }
func (m multiAgent) Lock([]byte) error          { return errors.New("read only") }
func (m multiAgent) Unlock([]byte) error        { return errors.New("read only") }
func (m multiAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

// inventory is what the fake check reads on s: the files of its two
// runtimes and the directives in them.
func (s *demoServer) inventory(at time.Time) target.Inventory {
	inv := target.Inventory{
		TargetID: s.t.ID, At: at,
		OS: target.OSInfo{ID: "debian", VersionID: "12"},
		PHP: []target.PHPRuntime{
			{SAPI: "cli", Binary: s.cli, Version: s.ver + ".7", LoadedIni: s.cliIni, ScannedDir: "/etc/php/" + s.ver + "/cli/conf.d"},
			{SAPI: "fpm", Binary: s.fpm, Version: s.ver + ".7", LoadedIni: s.ini, ScannedDir: "/etc/php/" + s.ver + "/fpm/conf.d"},
		},
		Packages: []target.Package{{Name: "libdemo", Source: "libdemo", Version: s.pkgVer}},
		Files:    []target.FileSeen{{Path: s.cliIni}, {Path: s.ini}},
	}
	for _, rt := range inv.PHP {
		text, _ := s.srv.File(rt.LoadedIni)
		for i, line := range strings.Split(text, "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok || strings.HasPrefix(strings.TrimSpace(line), ";") {
				continue
			}
			inv.Directives = append(inv.Directives, target.Directive{SAPI: rt.SAPI, Binary: rt.Binary, Name: strings.TrimSpace(k),
				Value: strings.TrimSpace(v), File: rt.LoadedIni, Line: i + 1})
		}
	}
	return inv
}

// check is the fake servercheck.Check: it reads the server's files, judges
// them with the embedded rules and stores the findings as a check does.
func (f *serverFixture) check(ctx context.Context, id string) (servercheck.CheckResult, error) {
	s := f.servers[id]
	t, err := f.targets.Get(ctx, id)
	if err != nil {
		return servercheck.CheckResult{}, err
	}
	at := f.tick()
	inv := s.inventory(at)
	if err := f.targets.SaveInventory(ctx, inv); err != nil {
		return servercheck.CheckResult{}, err
	}
	set, err := serverrules.Rules()
	if err != nil {
		return servercheck.CheckResult{}, err
	}
	fs := serverrules.Evaluate(t, inv, set)
	if f.pkgFinding && s.pkgVer == "1.0-1" {
		fs = append(fs, scan.Finding{ID: scan.FindingID(t.ID, "os-packages", "os", "libdemo", "DSA-DEMO-1"), ProjectID: t.ID,
			ManifestRelPath: "os-packages", Ecosystem: "os", Package: "libdemo", OSVID: "DSA-DEMO-1", SeverityLabel: "high",
			InstalledVersion: "1.0-1", FixedVersions: []string{"1.1-1"}, Kind: scan.KindServerPackage})
	}
	tx, err := f.st.DB().BeginTx(ctx, nil)
	if err != nil {
		return servercheck.CheckResult{}, err
	}
	defer tx.Rollback()
	n, still, gone, _, err := scan.ApplyServerFindings(ctx, tx, t.ID, "run"+strconv.FormatInt(at.Unix(), 10), at, fs, scan.ServerApply{})
	if err != nil {
		return servercheck.CheckResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return servercheck.CheckResult{}, err
	}
	seen := make([]string, 0, len(fs))
	for _, x := range fs {
		seen = append(seen, x.ID)
	}
	return servercheck.CheckResult{New: n, Still: still, Gone: gone, Touched: true, ReleaseKnown: true, Seen: seen}, nil
}

// finding is the finding of rule (an OSV id) on s, checking first when
// asked.
func (f *serverFixture) finding(s *demoServer, osvID string) scan.Finding {
	f.t.Helper()
	list, err := scan.NewRepo(f.st).ListServerFindings(context.Background(), s.t.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, x := range list {
		if x.OSVID == osvID && x.SAPI != "cli" {
			return x
		}
	}
	f.t.Fatalf("no finding %s on %s", osvID, s.t.Name)
	return scan.Finding{}
}

func (f *serverFixture) mustCheck(s *demoServer) {
	f.t.Helper()
	if _, err := f.check(context.Background(), s.t.ID); err != nil {
		f.t.Fatal(err)
	}
}

func (f *serverFixture) attempt(id string) Attempt {
	f.t.Helper()
	a, err := f.d.repo().GetAttempt(context.Background(), id)
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}

func (f *serverFixture) proposal(id string) Proposal {
	f.t.Helper()
	p, ok, err := f.d.repo().CurrentProposal(context.Background(), id)
	if err != nil || !ok {
		f.t.Fatalf("proposal: %v %v", ok, err)
	}
	return p
}

// start prepares the fix of finding osvID on s and approves it.
func (f *serverFixture) startApproved(s *demoServer, osvID string) (Attempt, Proposal) {
	f.t.Helper()
	ctx := context.Background()
	a, err := StartServer(ctx, f.d, f.finding(s, osvID).ID)
	if err != nil {
		f.t.Fatalf("StartServer: %v", err)
	}
	p := f.proposal(a.ID)
	if err := Approve(ctx, f.d, a.ID, p.Hash); err != nil {
		f.t.Fatalf("Approve: %v", err)
	}
	return a, p
}

// sent counts the scripts the server received on standard input.
func sent(s *demoServer) int {
	n := 0
	for _, l := range s.srv.Log() {
		if strings.HasSuffix(l, "'sh' '-s'") {
			n++
		}
	}
	return n
}

func file(t *testing.T, s *demoServer, p string) string {
	t.Helper()
	v, ok := s.srv.File(p)
	if !ok {
		t.Fatalf("%s missing", p)
	}
	return v
}

func TestServerConfigFixEndToEnd(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	ctx := context.Background()
	var streamed []StepResult
	f.d.OnStep = func(_ string, st StepResult) { streamed = append(streamed, st) }

	a, err := StartServer(ctx, f.d, f.finding(s, "expose_php").ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.State != StateProposed || a.ProjectID != s.t.ID || a.Origin != OriginServer || a.Work.Server == nil {
		t.Fatalf("attempt %+v", a)
	}
	p := f.proposal(a.ID)
	if p.Scripts == nil || p.Server == nil || p.Server.Executor != target.ExecMichel || !p.Scripts.RunAsRoot {
		t.Fatalf("proposal %+v", p)
	}
	if p.Hash != serverHash(p.Scripts.Hash, *p.Server) || p.Summary != "Set expose_php to 0 on server srv-demo" {
		t.Errorf("hash or summary: %q", p.Summary)
	}
	if !strings.Contains(strings.Join(p.StepsServer, "\n"), "Save a copy of "+s.ini) {
		t.Errorf("explanation:\n%s", strings.Join(p.StepsServer, "\n"))
	}
	if sent(s) != 0 {
		t.Fatal("a script was sent before the approval")
	}
	if err := Apply(ctx, f.d, a.ID); !errors.Is(err, ErrBadTransition) {
		t.Fatalf("Apply before Approve: %v", err)
	}
	if err := Approve(ctx, f.d, a.ID, p.Hash); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, f.d, a.ID); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed {
		t.Fatalf("state %s cause %q", got.State, got.Cause)
	}
	if got := file(t, s, s.ini); got != "[PHP]\nengine = On\nexpose_php = 0\nmemory_limit = 128M\n" {
		t.Errorf("php.ini after the fix:\n%q", got)
	}
	var viaSudo bool
	for _, l := range s.srv.Log() {
		viaSudo = viaSudo || l == "'sudo' '-n' 'sh' '-s'"
	}
	if !viaSudo {
		t.Errorf("the root bundle was not sent with sudo -n sh -s: %q", s.srv.Log())
	}
	bak := srvBackups + p.Server.CorrectionID + "/1"
	if file(t, s, bak) != demoIni {
		t.Error("the server backup is not the original file")
	}
	// The backup is kept on the workstation, encrypted at rest.
	bs, err := f.d.backups(ctx, a.ID)
	if err != nil || len(bs) != 1 || string(bs[0].Content) != demoIni || bs[0].RemotePath != bak || bs[0].TargetID != s.t.ID {
		t.Fatalf("backups %+v %v", bs, err)
	}
	var blob string
	if err := f.st.DB().QueryRow(`SELECT blob FROM server_backup`).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(blob)
	if strings.Contains(blob, "expose_php") || bytes.Contains(raw, []byte("expose_php")) {
		t.Error("the backup is stored in clear")
	}
	if p := f.proposal(a.ID); len(p.Steps) == 0 || len(streamed) != len(p.Steps) {
		t.Errorf("steps %+v streamed %+v", p.Steps, streamed)
	} else {
		for _, st := range p.Steps {
			if !st.OK {
				t.Errorf("step %+v", st)
			}
		}
	}
	if f.finding(s, "expose_php").Status != scan.StatusGone {
		t.Error("the finding is not gone")
	}
	for _, act := range []string{"server_fix.propose", "server_fix.approve", "server_fix.apply", "server_fix.proven"} {
		if n := auditCount(t, f.st, act, "ok"); n != 1 {
			t.Errorf("%s: %d events", act, n)
		}
	}
	if len(f.alerts) != 0 {
		t.Errorf("alerts %+v", f.alerts)
	}
}

func auditCount(t *testing.T, st *store.Store, action, result string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM audit_event WHERE action = ? AND result = ?`, action, result).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestProvenFixedSurvivesLaterChecks: a later check, which closes absent
// findings, never touches the proof: the attempt stays proven_fixed and the
// finding stays gone with its date.
func TestProvenFixedSurvivesLaterChecks(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	if err := Apply(context.Background(), f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := f.st.DB().QueryRow(`SELECT status_changed_at FROM finding WHERE id = ?`, a.FindingID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	f.mustCheck(s)
	f.mustCheck(s)
	var status, after string
	if err := f.st.DB().QueryRow(`SELECT status, status_changed_at FROM finding WHERE id = ?`, a.FindingID).Scan(&status, &after); err != nil {
		t.Fatal(err)
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed || status != scan.StatusGone || after != before {
		t.Errorf("state %s, finding %s %s (was %s)", got.State, status, after, before)
	}
}

func TestApproveNeedsSnapshotForPackages(t *testing.T) {
	f := newServerFixture(t)
	f.pkgFinding = true
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	s.sim = "NOTE: This is only a simulation!\nInst libdemo [1.0-1] (1.1-1 Debian:12/stable [amd64])\nConf libdemo (1.1-1 Debian:12/stable [amd64])\n"
	f.mustCheck(s)
	ctx := context.Background()
	a, err := StartServer(ctx, f.d, f.finding(s, "DSA-DEMO-1").ID)
	if err != nil {
		t.Fatal(err)
	}
	p := f.proposal(a.ID)
	if !p.Server.NeedsSnapshot || !strings.Contains(p.Scripts.Apply, "'libdemo=1.1-1'") {
		t.Fatalf("package proposal %+v", p.Server)
	}
	if !strings.Contains(strings.Join(p.StepsServer, "\n"), "snapshot") {
		t.Error("the explanation does not say the snapshot is the way back")
	}
	if err := Approve(ctx, f.d, a.ID, p.Hash); !errors.Is(err, ErrSnapshotRequired) {
		t.Fatalf("Approve without snapshot: %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateProposed {
		t.Fatalf("state %s", got.State)
	}
	if err := SnapshotDone(ctx, f.d, a.ID, "web"); err != nil {
		t.Fatal(err)
	}
	if auditCount(t, f.st, "server_fix.snapshot_done", "ok") != 1 {
		t.Error("snapshot not audited")
	}
	if err := Approve(ctx, f.d, a.ID, p.Hash); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, f.d, a.ID); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed {
		t.Errorf("state %s cause %q", got.State, got.Cause)
	}
	// The simulation ran again in the same connection, right before the
	// script.
	log := s.srv.Log()
	for i, l := range log {
		if strings.HasSuffix(l, "'sh' '-s'") && (i == 0 || !strings.Contains(log[i-1], "'apt-get' '-s'")) {
			t.Errorf("no simulation right before the script: %q", log)
		}
	}
}

func TestSimulationRemovalRefusesPlan(t *testing.T) {
	f := newServerFixture(t)
	f.pkgFinding = true
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	clean := "Inst libdemo [1.0-1] (1.1-1 Debian:12/stable [amd64])\n"
	removal := clean + "Remv libother [2.0-1]\n"
	s.sim = removal
	f.mustCheck(s)
	ctx := context.Background()
	fid := f.finding(s, "DSA-DEMO-1").ID
	_, err := StartServer(ctx, f.d, fid)
	var wr serverfix.ErrWouldRemove
	if !errors.Is(err, ErrSimulationRefused) || !errors.As(err, &wr) || wr.Packages[0] != "libother" {
		t.Fatalf("StartServer: %v", err)
	}
	if list, _ := f.d.repo().ListAttempts(ctx, s.t.ID, ""); len(list) != 0 || sent(s) != 0 {
		t.Fatalf("attempts %d, scripts sent %d", len(list), sent(s))
	}
	// Clean at proposal time, a removal right before the apply: refused,
	// nothing applied.
	s.sim = clean
	a, err := StartServer(ctx, f.d, fid)
	if err != nil {
		t.Fatal(err)
	}
	p := f.proposal(a.ID)
	if err := SnapshotDone(ctx, f.d, a.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := Approve(ctx, f.d, a.ID, p.Hash); err != nil {
		t.Fatal(err)
	}
	s.sim = removal
	if err := Apply(ctx, f.d, a.ID); !errors.Is(err, ErrSimulationRefused) {
		t.Fatalf("Apply: %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateFailed || sent(s) != 0 || s.pkgVer != "1.0-1" {
		t.Errorf("state %s, sent %d, package %s", got.State, sent(s), s.pkgVer)
	}
}

func TestHashRecheckedBeforeSend(t *testing.T) {
	ctx := context.Background()
	for name, tamper := range map[string]string{
		"script text":       `UPDATE fix_proposal SET scripts = replace(scripts, 'correction appliquee', 'correction faite')`,
		"script and hash":   `UPDATE fix_proposal SET scripts = replace(replace(scripts, 'correction appliquee', 'x'), '"Hash":"', '"Hash":"0')`,
		"validated actions": `UPDATE fix_proposal SET scripts = replace(scripts, '"value":"0"', '"value":"Off"')`,
		"correction id":     `UPDATE fix_proposal SET scripts = replace(scripts, '"correction_id":"', '"correction_id":"0')`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newServerFixture(t)
			s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
			f.mustCheck(s)
			a, _ := f.startApproved(s, "expose_php")
			res, err := f.st.DB().Exec(tamper)
			if err != nil {
				t.Fatal(err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				t.Fatal("nothing tampered")
			}
			accepted := s.srv.Accepted()
			if err := Apply(ctx, f.d, a.ID); !errors.Is(err, ErrScriptChanged) {
				t.Fatalf("Apply: %v", err)
			}
			if sent(s) != 0 || s.srv.Accepted() != accepted || file(t, s, s.ini) != demoIni {
				t.Error("something reached the server")
			}
			if auditCount(t, f.st, "server_fix.apply", "refused") != 1 {
				t.Error("refusal not audited")
			}
		})
	}
	// The server changed since the validation: the scripts rendered from
	// the current inventory differ, nothing is sent.
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	s.srv.SetFile(s.ini, "[PHP]\nengine = On\n\nexpose_php = On\n")
	f.mustCheck(s)
	if err := Apply(ctx, f.d, a.ID); !errors.Is(err, ErrScriptChanged) || sent(s) != 0 {
		t.Fatalf("Apply after the server changed: %v, sent %d", err, sent(s))
	}
}

func TestSiteDownTriggersRollback(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	// The site breaks with the new setting and comes back without it.
	f.siteDown = func(d *demoServer) bool { v, _ := d.srv.File(d.ini); return strings.Contains(v, "expose_php = 0") }
	a, p := f.startApproved(s, "expose_php")
	if err := Apply(context.Background(), f.d, a.ID); !errors.Is(err, ErrServerRolledBack) {
		t.Fatalf("Apply: %v", err)
	}
	if file(t, s, s.ini) != demoIni {
		t.Errorf("php.ini not restored:\n%q", file(t, s, s.ini))
	}
	got := f.attempt(a.ID)
	if got.State != StateFailed || got.Cause != CauseRolledBack || CauseText(i18n.EN, got.Cause) != i18n.T(i18n.EN, "fix.server.rolled_back") {
		t.Errorf("state %s cause %q", got.State, got.Cause)
	}
	if len(f.alerts) != 1 || f.alerts[0].Kind != servercheck.AlertRolledBack || f.alerts[0].Urgent {
		t.Errorf("alerts %+v", f.alerts)
	}
	if f.siteGETs != 2 {
		t.Errorf("site checked %d times, want before and after undo", f.siteGETs)
	}
	if sent(s) != 2 || auditCount(t, f.st, "server_fix.rollback", "ok") != 1 {
		t.Errorf("sent %d", sent(s))
	}
	steps := f.proposal(a.ID).Steps
	if last := steps[len(steps)-1]; last.Op != StepRecollect {
		t.Errorf("steps %+v", steps)
	}
	var undo bool
	for _, st := range steps {
		undo = undo || (st.Op == StepUndo && st.OK)
	}
	if !undo {
		t.Errorf("no undo step: %+v", steps)
	}
	if f.finding(s, "expose_php").Status == scan.StatusGone {
		t.Error("the finding is gone after the rollback")
	}
	// A retry is a new correction id (the old one is spent on the server).
	a2, err := StartServer(context.Background(), f.d, a.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if f.proposal(a2.ID).Server.CorrectionID == p.Server.CorrectionID {
		t.Error("the retry reuses the correction id")
	}
}

func TestRollbackFailureAlertsUrgent(t *testing.T) {
	ctx := context.Background()
	// Site down, then the undo itself fails (its reload is refused).
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	f.siteDown = func(*demoServer) bool { return true }
	s.reloads = []int{0, 1}
	a, p := f.startApproved(s, "expose_php")
	if err := Apply(ctx, f.d, a.ID); !errors.Is(err, ErrServerRollbackFailed) {
		t.Fatalf("Apply: %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateFailed || got.Cause != i18n.T(i18n.EN, "fix.server.rollback_failed") {
		t.Errorf("state %s cause %q", got.State, got.Cause)
	}
	want := srvBackups + p.Server.CorrectionID + "/1 -> " + s.ini
	if len(f.alerts) != 1 || f.alerts[0].Kind != servercheck.AlertRollbackFailed || !f.alerts[0].Urgent ||
		len(f.alerts[0].Backups) != 1 || f.alerts[0].Backups[0] != want {
		t.Errorf("alerts %+v", f.alerts)
	}
	if auditCount(t, f.st, "server_fix.rollback", "error") != 1 {
		t.Error("failed rollback not audited")
	}

	// The script's own rollback fails (php-fpm -t and the reload refused):
	// exit 8, urgent.
	f = newServerFixture(t)
	s = f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	s.fpmTest, s.reloads = 1, []int{1}
	a, _ = f.startApproved(s, "expose_php")
	if err := Apply(ctx, f.d, a.ID); !errors.Is(err, ErrServerRollbackFailed) {
		t.Fatalf("Apply exit 8: %v", err)
	}
	if len(f.alerts) != 1 || f.alerts[0].Kind != servercheck.AlertRollbackFailed || !f.alerts[0].Urgent || len(f.alerts[0].Backups) != 1 {
		t.Errorf("alerts %+v", f.alerts)
	}
	// The backup was still fetched, to put back by hand.
	if bs, _ := f.d.backups(ctx, a.ID); len(bs) != 1 || string(bs[0].Content) != demoIni {
		t.Errorf("backups %+v", bs)
	}

	// A step fails and the script puts the files back itself: rolled back.
	f = newServerFixture(t)
	s = f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	s.fpmTest = 1
	a, _ = f.startApproved(s, "expose_php")
	if err := Apply(ctx, f.d, a.ID); !errors.Is(err, ErrServerRolledBack) {
		t.Fatalf("Apply exit 1: %v", err)
	}
	if got := f.attempt(a.ID); got.Cause != CauseRolledBack || file(t, s, s.ini) != demoIni {
		t.Errorf("cause %q", got.Cause)
	}
	if len(f.alerts) != 1 || f.alerts[0].Kind != servercheck.AlertRolledBack {
		t.Errorf("alerts %+v", f.alerts)
	}
}

func TestLineMovedRecollectsAndProposesAgain(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, p := f.startApproved(s, "expose_php")
	// The file changes on the server after the check, unseen by Michel.
	f.d.Targets = f.targets
	moved := "[PHP]\nengine = On\n\nexpose_php = On\n"
	s.srv.SetFile(s.ini, moved)
	ctx := context.Background()
	if err := Apply(ctx, f.d, a.ID); !errors.Is(err, ErrServerLineMoved) {
		t.Fatalf("Apply: %v", err)
	}
	if file(t, s, s.ini) != moved || len(f.alerts) != 0 {
		t.Errorf("file changed or alert sent: %+v", f.alerts)
	}
	if got := f.attempt(a.ID); got.State != StateFailed {
		t.Errorf("state %s", got.State)
	}
	list, _ := f.d.repo().ListAttempts(ctx, s.t.ID, string(StateProposed))
	if len(list) != 1 || list[0].ID == a.ID || f.proposal(list[0].ID).Server.CorrectionID == p.Server.CorrectionID {
		t.Fatalf("new proposal %+v", list)
	}
	if line := f.proposal(list[0].ID).Server.Actions[1].Line; line != 4 {
		t.Errorf("the new fix targets line %d, want 4", line)
	}
}

func TestUserExecutorWaitsForAppliedByMe(t *testing.T) {
	f := newServerFixture(t)
	// Executor michel without sudo: a root bundle is run by the user.
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNone, nil)
	f.mustCheck(s)
	ctx := context.Background()
	a, p := f.startApproved(s, "expose_php")
	if p.Server.Executor != target.ExecUser {
		t.Fatalf("executor %s", p.Server.Executor)
	}
	if !strings.Contains(strings.Join(p.StepsServer, "\n"), "I applied it") {
		t.Error("the explanation does not tell the user to run it")
	}
	if err := Apply(ctx, f.d, a.ID); !errors.Is(err, ErrNotMichelExecutor) {
		t.Fatalf("Apply: %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateApproved || sent(s) != 0 {
		t.Fatalf("state %s, sent %d", got.State, sent(s))
	}
	// The user runs the apply script as root on the server.
	var out, errb bytes.Buffer
	if code := s.root.Run(s.srv, p.Scripts.Apply, &out, &errb); code != 0 {
		t.Fatalf("apply by hand: exit %d %s", code, errb.String())
	}
	if err := AppliedByMe(ctx, f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed {
		t.Errorf("state %s cause %q", got.State, got.Cause)
	}
	if sent(s) != 0 {
		t.Error("Michel sent a script")
	}
	if err := AppliedByMe(ctx, f.d, a.ID); !errors.Is(err, ErrBadTransition) {
		t.Errorf("second AppliedByMe: %v", err)
	}
	// Executor user by default.
	f2 := newServerFixture(t)
	s2 := f2.addServer("srv-demo", "8.2", demoIni, target.ExecUser, target.SudoNopasswd, nil)
	f2.mustCheck(s2)
	if _, p2 := f2.startApproved(s2, "expose_php"); p2.Server.Executor != target.ExecUser {
		t.Errorf("executor %s", p2.Server.Executor)
	}
}

func TestUserExecutorSiteDownAlerts(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecUser, target.SudoNone, nil)
	f.mustCheck(s)
	f.siteDown = func(d *demoServer) bool { v, _ := d.srv.File(d.ini); return strings.Contains(v, "expose_php = 0") }
	ctx := context.Background()
	a, p := f.startApproved(s, "expose_php")
	var out, errb bytes.Buffer
	if code := s.root.Run(s.srv, p.Scripts.Apply, &out, &errb); code != 0 {
		t.Fatalf("apply by hand: exit %d", code)
	}
	if err := AppliedByMe(ctx, f.d, a.ID); !errors.Is(err, ErrServerSiteDown) {
		t.Fatalf("AppliedByMe: %v", err)
	}
	if len(f.alerts) != 1 || f.alerts[0].Kind != servercheck.AlertUndoNow || !f.alerts[0].Urgent || len(f.alerts[0].Backups) != 1 {
		t.Errorf("alerts %+v", f.alerts)
	}
	if got := f.attempt(a.ID); got.State != StateFailed || got.Cause != i18n.T(i18n.EN, "fix.server.site_down_user") {
		t.Errorf("state %s cause %q", got.State, got.Cause)
	}
	// Michel never runs undo itself for the user's fix.
	if sent(s) != 0 || !strings.Contains(file(t, s, s.ini), "expose_php = 0") {
		t.Error("Michel touched the server")
	}
}

func TestPreprodFirstThenProdRebuilt(t *testing.T) {
	f := newServerFixture(t)
	pre := f.addServer("srv-demo-pre", "8.3", demoIni, target.ExecMichel, target.SudoNopasswd, func(t *target.Target) { t.Env = target.EnvPreprod })
	prod := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(t *target.Target) { t.PreprodID = pre.t.ID })
	f.mustCheck(pre)
	f.mustCheck(prod)
	ctx := context.Background()
	prodFinding := f.finding(prod, "expose_php")
	a, err := StartServer(ctx, f.d, prodFinding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.ProjectID != pre.t.ID || a.Work.Server.ProdTargetID != prod.t.ID || a.Work.Server.ProdFindingID != prodFinding.ID {
		t.Fatalf("the first fix is not on the preprod: %+v %+v", a, a.Work.Server)
	}
	pp := f.proposal(a.ID)
	if !strings.Contains(pp.Scripts.Apply, "/etc/php/8.3/fpm/php.ini") {
		t.Error("preprod scripts do not use the preprod's paths")
	}
	if err := Approve(ctx, f.d, a.ID, pp.Hash); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed {
		t.Fatalf("preprod state %s %q", got.State, got.Cause)
	}
	list, _ := f.d.repo().ListAttempts(ctx, prod.t.ID, "")
	if len(list) != 1 || list[0].State != StateProposed || list[0].FindingID != prodFinding.ID {
		t.Fatalf("prod attempts %+v", list)
	}
	pr := f.proposal(list[0].ID)
	if pr.Hash == pp.Hash || pr.Scripts.Hash == pp.Scripts.Hash || !strings.Contains(pr.Scripts.Apply, "/etc/php/8.2/fpm/php.ini") ||
		strings.Contains(pr.Scripts.Apply, "8.3") {
		t.Error("the prod fix is not rebuilt from the prod inventory")
	}
	if sent(prod) != 0 || file(t, prod, prod.ini) != demoIni {
		t.Fatal("the prod was touched without its own approval")
	}
	if auditCount(t, f.st, "server_fix.promote", "ok") != 1 {
		t.Error("promotion not audited")
	}
	if err := Approve(ctx, f.d, list[0].ID, pr.Hash); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, f.d, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if got := f.attempt(list[0].ID); got.State != StateProvenFixed {
		t.Errorf("prod state %s", got.State)
	}
	// A preprod that does not show the finding: refused, nothing prepared.
	f2 := newServerFixture(t)
	pre2 := f2.addServer("srv-demo-pre", "8.3", "[PHP]\nexpose_php = Off\n", target.ExecMichel, target.SudoNopasswd, func(t *target.Target) { t.Env = target.EnvPreprod })
	prod2 := f2.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(t *target.Target) { t.PreprodID = pre2.t.ID })
	f2.mustCheck(pre2)
	f2.mustCheck(prod2)
	if _, err := StartServer(ctx, f2.d, f2.finding(prod2, "expose_php").ID); !errors.Is(err, ErrPreprodMissing) {
		t.Errorf("preprod without the finding: %v", err)
	}
}

func TestMitigationKeepsUpstreamOpen(t *testing.T) {
	f := newServerFixture(t)
	// PHP 8.2.7 built by hand: PHP2Shell is open, and so is its mitigation
	// (session.upload_progress.enabled is not set: PHP's default is On).
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	ctx := context.Background()
	mit := f.finding(s, "session_upload_progress_off")
	if !mit.Mitigation {
		t.Fatal("not a mitigation")
	}
	upstream := f.finding(s, "PHP2SHELL")
	a, err := StartServer(ctx, f.d, mit.ID)
	if err != nil {
		t.Fatal(err)
	}
	p := f.proposal(a.ID)
	if !p.Server.Mitigation || !strings.Contains(strings.Join(p.StepsServer, "\n"), "only holds the flaw back") {
		t.Errorf("mitigation not said: %+v", p.Server)
	}
	if err := Approve(ctx, f.d, a.ID, p.Hash); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(file(t, s, s.ini), "session.upload_progress.enabled = 0") {
		t.Errorf("php.ini:\n%s", file(t, s, s.ini))
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed {
		t.Errorf("mitigation state %s %q", got.State, got.Cause)
	}
	if got := f.finding(s, "PHP2SHELL"); got.ID != upstream.ID || got.Status == scan.StatusGone {
		t.Errorf("the upstream finding closed: %s", got.Status)
	}
	// The upstream advisory itself has no ready-made fix (PHP built by hand).
	if _, err := StartServer(ctx, f.d, upstream.ID); !errors.Is(err, ErrNeedsAgent) {
		t.Errorf("upstream: %v", err)
	}
}

func TestCLIConfigWarningIsAFailure(t *testing.T) {
	// php -c exits 0 on ini warnings: anything on its error output fails
	// the test, and Michel undoes the fix.
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	s.cliStderr = "PHP Warning: syntax error\n"
	list, _ := scan.NewRepo(f.st).ListServerFindings(context.Background(), s.t.ID)
	var cli scan.Finding
	for _, x := range list {
		if x.OSVID == "allow_url_include" && x.SAPI == "cli" {
			cli = x
		}
	}
	if cli.ID == "" {
		t.Fatal("no CLI finding")
	}
	ctx := context.Background()
	a, err := StartServer(ctx, f.d, cli.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := Approve(ctx, f.d, a.ID, f.proposal(a.ID).Hash); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, f.d, a.ID); !errors.Is(err, ErrServerRolledBack) {
		t.Fatalf("Apply: %v", err)
	}
	if got := file(t, s, s.cliIni); got != "[PHP]\nallow_url_include = On\n" {
		t.Errorf("cli php.ini not restored: %q", got)
	}
}

func TestBackupsPurgedAfter90Days(t *testing.T) {
	f := newServerFixture(t)
	ctx := context.Background()
	if err := f.d.addBackup(ctx, ServerBackup{AttemptID: "A1", TargetID: "T1", RemotePath: srvBackups + "c1/1", Content: []byte("old")}); err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(2 * 24 * time.Hour)
	if err := f.d.addBackup(ctx, ServerBackup{AttemptID: "A2", TargetID: "T1", RemotePath: srvBackups + "c2/1", Content: []byte("new")}); err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(89 * 24 * time.Hour) // the first is 91 days old, the second 89
	if err := Sweep(ctx, f.d); err != nil {
		t.Fatal(err)
	}
	old, _ := f.d.backups(ctx, "A1")
	kept, kerr := f.d.backups(ctx, "A2")
	if kerr != nil {
		t.Fatal(kerr)
	}
	if len(old) != 0 || len(kept) != 1 || string(kept[0].Content) != "new" {
		t.Errorf("after purge: %d old, %d kept", len(old), len(kept))
	}
	f.clock = f.clock.Add(2 * 24 * time.Hour)
	if n, err := PurgeServerBackups(ctx, f.d); err != nil || n != 1 {
		t.Errorf("PurgeServerBackups: %d %v", n, err)
	}
}

func TestServerAuditHasNoConfigContent(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	ctx := context.Background()
	// A fix that rolls back (stderr and site down) and one that is proven.
	f.siteDown = func(d *demoServer) bool { v, _ := d.srv.File(d.ini); return strings.Contains(v, "expose_php = 0") }
	a, _ := f.startApproved(s, "expose_php")
	_ = Apply(ctx, f.d, a.ID)
	f.siteDown = nil
	a, _ = f.startApproved(s, "expose_php")
	if err := Apply(ctx, f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	rows, err := f.st.DB().Query(`SELECT action, evidence FROM audit_event WHERE action LIKE 'server_fix.%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var action, ev string
		if err := rows.Scan(&action, &ev); err != nil {
			t.Fatal(err)
		}
		n++
		for _, bad := range []string{"expose_php", "[PHP]", "engine", "memory_limit", "fichiers remis", "correction", "/etc/php", "On", "sudo", "stderr"} {
			if bad == "correction" && strings.Contains(ev, "correction_id") {
				ev2 := strings.ReplaceAll(ev, "correction_id", "")
				if strings.Contains(ev2, bad) {
					t.Errorf("%s holds %q: %s", action, bad, ev)
				}
				continue
			}
			if strings.Contains(ev, bad) {
				t.Errorf("%s holds %q: %s", action, bad, ev)
			}
		}
	}
	if n < 8 {
		t.Errorf("only %d server_fix events", n)
	}
}

func TestServerExitCodesAndKeys(t *testing.T) {
	for code, want := range map[int]error{3: ErrServerWrongUser, 4: ErrServerAlreadyApplied, 5: ErrServerLineMoved, 6: ErrServerLink,
		7: ErrServerUnsafe, 8: ErrServerRollbackFailed, 9: ErrServerRolledBack, 1: ErrServerRolledBack, 2: ErrServerRolledBack} {
		// A refusal (3 to 7) comes with its own line; a failure after the
		// change with the rollback's.
		stderr := []byte(scriptRolledBack)
		if lines := serverfix.ExitLines(code); len(lines) > 0 {
			stderr = []byte(lines[0])
		}
		got := classifyExit(code, stderr, false)
		if !errors.Is(got, want) {
			t.Errorf("exit %d: %v", code, got)
		}
		key := ErrorKey(got)
		if !strings.HasPrefix(key, "fix.server.") {
			t.Errorf("exit %d: key %q", code, key)
		}
		for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
			if text := Explain(lang, got); text == "" || text == key {
				t.Errorf("exit %d %s: no text for %s", code, lang, key)
			}
		}
	}
	if classifyExit(0, nil, false) != nil {
		t.Error("exit 0 is an error")
	}
	d := Deps{Lang: i18n.EN}
	if d.causeOf(ErrServerRolledBack) != CauseRolledBack {
		t.Error("the rolled back cause is not the digest's code")
	}
	if CauseRolledBack != "rolled_back" {
		t.Error("CauseRolledBack changed")
	}
}

// TestSweepNeverRunsAServerFix: an approved server fix waits for its run;
// a restart of Michel never runs it, nor fails it.
func TestSweepNeverRunsAServerFix(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	if err := Sweep(context.Background(), f.d); err != nil {
		t.Fatal(err)
	}
	if got := f.attempt(a.ID); got.State != StateApproved || sent(s) != 0 {
		t.Errorf("state %s, sent %d", got.State, sent(s))
	}
}
