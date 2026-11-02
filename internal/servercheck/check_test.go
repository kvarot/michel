package servercheck

import (
	"archive/zip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/collect"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/serverrules"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

// host is the simulated server: what its commands print. The tests change
// it between two checks, as an administrator would outside Michel.
type host struct {
	mu      sync.Mutex
	phpV    string // php -v version
	iniJSON string // php -r output
	dpkg    string // dpkg-query output
	// fpm adds PHP-FPM 8.2 from the Debian package php8.2-fpm; fpmSlow
	// makes its -v run past the time limit; findBroken makes command -v
	// fail.
	fpm, fpmSlow, findBroken bool
	// noCommand is a login shell without `command` (tcsh): exit 1, nothing
	// printed.
	noCommand bool
	// userIni is the content of demoUserIni ("" = no such file);
	// userIniDenied makes it unreadable for the SSH user.
	userIni       string
	userIniDenied bool
}

const demoUserIni = "/var/www/demo/.user.ini"

const fpmBin = "/usr/sbin/php-fpm8.2"

// dpkgFPM is dpkgOut with the FPM package.
const dpkgFPM = dpkgOut + "php8.2-fpm\tphp8.2\t8.2.20-1+deb12u1\tamd64\n"

var (
	fixtureMu sync.Mutex
	fixtures  = map[string]string{}
)

// fpmFixture is an output kept by package collect for its own tests.
func fpmFixture(name string) string {
	fixtureMu.Lock()
	defer fixtureMu.Unlock()
	if s, ok := fixtures[name]; ok {
		return s
	}
	b, err := os.ReadFile(filepath.Join("..", "collect", "testdata", name))
	if err != nil {
		panic(err)
	}
	fixtures[name] = strings.ReplaceAll(string(b), "\r\n", "\n")
	return fixtures[name]
}

func (h *host) change(f func(h *host)) {
	h.mu.Lock()
	f(h)
	h.mu.Unlock()
}

func (h *host) flags() (fpm, slow, broken bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fpm, h.fpmSlow, h.findBroken
}

func (h *host) get() (string, string, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.phpV, h.iniJSON, h.dpkg
}

func (h *host) set(phpV, iniJSON string) {
	h.mu.Lock()
	h.phpV, h.iniJSON = phpV, iniJSON
	h.mu.Unlock()
}

const osRelease = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nVERSION_ID=\"12\"\nID=debian\n"

const dpkgOut = "openssl\topenssl\t3.0.11-1~deb12u1\tamd64\n" +
	"libc6\tglibc\t2.36-9\tamd64\n"

func newHost() *host {
	return &host{phpV: "8.3.35", iniJSON: `{"allow_url_include":"1","display_errors":"0"}`, dpkg: dpkgOut}
}

func (h *host) commands() map[string]sshtest.Handler {
	out := map[string]sshtest.Handler{}
	out["cat"] = func(e sshtest.Exec) int {
		if len(e.Args) == 2 && e.Args[1] == "/etc/os-release" {
			io.WriteString(e.Stdout, osRelease)
			return 0
		}
		return 1
	}
	out["uname"] = func(e sshtest.Exec) int { io.WriteString(e.Stdout, "6.1.0-21-amd64\n"); return 0 }
	out["command"] = func(e sshtest.Exec) int {
		fpm, _, broken := h.flags()
		if broken {
			io.WriteString(e.Stderr, "sh: cannot look\n")
			return 2
		}
		h.mu.Lock()
		tcsh := h.noCommand
		h.mu.Unlock()
		if tcsh {
			io.WriteString(e.Stderr, "command: Command not found.\n")
			return 1
		}
		for _, a := range e.Args[2:] {
			if a == "sh" {
				io.WriteString(e.Stdout, "/bin/sh\n")
			}
			if a == "php" {
				io.WriteString(e.Stdout, "/usr/bin/php\n")
			}
			if a == fpmBin && fpm {
				io.WriteString(e.Stdout, fpmBin+"\n")
			}
		}
		return 1 // some names are always missing
	}
	out[fpmBin] = func(e sshtest.Exec) int {
		_, slow, _ := h.flags()
		switch e.Args[1] {
		case "-v":
			if slow {
				<-e.Ctx.Done()
				return 1
			}
			io.WriteString(e.Stdout, fpmFixture("php-fpm8.2-v"))
		case "-i":
			io.WriteString(e.Stdout, fpmFixture("php-fpm8.2-i"))
		case "-tt":
			io.WriteString(e.Stderr, fpmFixture("php-fpm8.2-tt"))
		case "-m":
			io.WriteString(e.Stdout, "[PHP Modules]\nCore\n")
		default:
			return 1
		}
		return 0
	}
	out["readlink"] = func(e sshtest.Exec) int { io.WriteString(e.Stdout, e.Args[len(e.Args)-1]+"\n"); return 0 }
	out["head"] = func(e sshtest.Exec) int {
		p := e.Args[len(e.Args)-1]
		h.mu.Lock()
		ini, denied := h.userIni, h.userIniDenied
		h.mu.Unlock()
		switch {
		case p == demoUserIni && denied:
			fmt.Fprintf(e.Stderr, "head: cannot open '%s' for reading: Permission denied\n", p)
		case p == demoUserIni && ini != "":
			io.WriteString(e.Stdout, ini)
			return 0
		default:
			fmt.Fprintf(e.Stderr, "head: cannot open '%s' for reading: No such file or directory\n", p)
		}
		return 1
	}
	out["php"] = func(e sshtest.Exec) int {
		v, ini, _ := h.get()
		switch e.Args[1] {
		case "-v":
			fmt.Fprintf(e.Stdout, "PHP %s (cli) (built: Oct  1 2026 10:00:00) (NTS)\n", v)
		case "-m":
			io.WriteString(e.Stdout, "[PHP Modules]\nCore\n")
		case "-r":
			io.WriteString(e.Stdout, ini)
		default:
			return 1
		}
		return 0
	}
	out["dpkg-query"] = func(e sshtest.Exec) int { _, _, d := h.get(); io.WriteString(e.Stdout, d); return 0 }
	// The command line PHP is compiled; the FPM comes from its package.
	out["dpkg"] = func(e sshtest.Exec) int {
		if e.Args[len(e.Args)-1] == fpmBin {
			io.WriteString(e.Stdout, "php8.2-fpm: "+fpmBin+"\n")
			return 0
		}
		return 1
	}
	out["env"] = func(e sshtest.Exec) int {
		i := 1
		for i < len(e.Args) && strings.Contains(e.Args[i], "=") {
			i++
		}
		if i >= len(e.Args) {
			return 2
		}
		inner, ok := out[e.Args[i]]
		if !ok {
			return 127
		}
		e.Args = e.Args[i:]
		return inner(e)
	}
	return out
}

// testRules mirror the embedded PHP2Shell advisory and one risky setting,
// so the tests do not move when the embedded rules do.
func testRules() (serverrules.Set, error) {
	return serverrules.Set{
		Config: []serverrules.ConfigRule{{ID: "allow_url_include", Directive: "allow_url_include", Risky: "on", Changeable: "system",
			Advised: "0", Severity: "high", Key: "serverrules.allow_url_include"},
			{ID: "session_upload_progress_off", Directive: "session.upload_progress.enabled", Risky: "on", Changeable: "perdir",
				Advised: "0", Severity: "medium", MissingIsRisky: true, Context: []string{"sapi:fpm"},
				Mitigates: []string{"CVE-2026-109618"}, Mitigation: true, Key: "serverrules.session_upload_progress_off"},
			{ID: "display_errors_prod", Directive: "display_errors", Risky: "on", Changeable: "all", Advised: "0", Severity: "medium",
				Context: []string{"prod", "sapi:fpm"}, Key: "serverrules.display_errors_prod"}},
		Upstream: []serverrules.UpstreamAdvisory{{ID: "PHP2SHELL", Aliases: []string{"CVE-2026-109618", "CVE-2026-109619"}, Severity: "critical",
			CVSS: 9.2, Key: "serverrules.php2shell", Branches: []serverrules.BranchFix{{Branch: "8.3", Fixed: "8.3.36"}}}},
	}, nil
}

func advisory(id, pkg, fixed, score string) string {
	events := `{"introduced":"0"}`
	if fixed != "" {
		events += `,{"fixed":"` + fixed + `"}`
	}
	return `{"id":"` + id + `","aliases":["CVE-2026-9` + id[len(id)-4:] + `"],"severity":[{"type":"CVSS_V3","score":"` + score + `"}],` +
		`"affected":[{"package":{"ecosystem":"Debian:12","name":"` + pkg + `"},"ranges":[{"type":"ECOSYSTEM","events":[` + events + `]}]}]}`
}

// writeDB writes the Debian archive under root with the given advisories.
func writeDB(t *testing.T, root string, files map[string]string) {
	t.Helper()
	p := osvdb.ZipPath(root, "Debian")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(w, body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// baseDB: openssl fixed in a newer version (high), glibc not fixed yet
// (critical).
func baseDB() map[string]string {
	return map[string]string{
		"DSA-0000-1001.json": advisory("DSA-0000-1001", "openssl", "3.0.13-1~deb12u1", "7.5"),
		"DSA-0000-1002.json": advisory("DSA-0000-1002", "glibc", "", "9.8"),
	}
}

type env struct {
	t      *testing.T
	st     *store.Store
	deps   CheckDeps
	srcs   *source.Repo
	allow  []policy.AllowRule
	clock  time.Time
	mu     sync.Mutex
	alerts []AlertInput
}

func (e *env) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clock
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	e.clock = e.clock.Add(d)
	e.mu.Unlock()
}

func (e *env) takeAlerts() []AlertInput {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.alerts
	e.alerts = nil
	return out
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{t: t, st: st, clock: time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)}
	srcs := source.NewRepo(st)
	ctx := context.Background()
	if _, _, err := source.Sync(ctx, srcs); err != nil {
		t.Fatal(err)
	}
	if err := srcs.SetEnabled(ctx, "osv.debian", true); err != nil {
		t.Fatal(err)
	}
	e.srcs = srcs
	root := t.TempDir()
	writeDB(t, root, baseDB())
	p := policy.Defaults()
	p.Sovereignty.Network.Allow = []policy.AllowRule{{Host: "127.0.0.1", Purpose: policy.PurposeTargetSSH}}
	gw := egress.New(p, nil)
	log := audit.NewLogger(st, e.now)
	e.deps = CheckDeps{
		Repo:  target.NewRepo(st),
		Store: st,
		Audit: log,
		SSH: sshx.Deps{Gateway: gw, Audit: log, KnownHosts: filepath.Join(t.TempDir(), "known_hosts"),
			Agent: func() (agent.ExtendedAgent, io.Closer, error) { return nil, nil, errors.New("no agent in this test") }, Now: e.now},
		Collect: collect.Deps{Now: e.now, Audit: log},
		OSVRoot: root,
		Sources: srcs,
		Rules:   testRules,
		Alert: func(_ context.Context, a AlertInput) {
			e.mu.Lock()
			e.alerts = append(e.alerts, a)
			e.mu.Unlock()
		},
		Now: e.now,
	}
	return e
}

// server starts a simulated server for h and registers it as a target.
func (e *env) server(name string, h *host, env target.Env) (*sshtest.Server, target.Target) {
	e.t.Helper()
	srv := sshtest.New(e.t, sshtest.Options{Commands: h.commands()})
	ag := srv.NewAgent(e.t)
	// One agent per test: every server of the test accepts the same key.
	prev := e.deps.SSH.Agent
	e.deps.SSH.Agent = func() (agent.ExtendedAgent, io.Closer, error) {
		return multiAgent{ag, prev}, nil, nil
	}
	hostname, port, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		e.t.Fatal(err)
	}
	pn, _ := strconv.Atoi(port)
	tg, err := e.deps.Repo.Add(context.Background(), target.Target{Name: name, Host: hostname, Port: pn, User: "deploy",
		HostKey: srv.HostKeyFingerprint(), Kind: target.KindVPS, Env: env, CheckInterval: target.DefaultCheckInterval})
	if err != nil {
		e.t.Fatal(err)
	}
	return srv, tg
}

// multiAgent offers the keys of its agents in turn.
type multiAgent struct {
	agent.ExtendedAgent
	next func() (agent.ExtendedAgent, io.Closer, error)
}

func (m multiAgent) Signers() ([]ssh.Signer, error) {
	s, err := m.ExtendedAgent.Signers()
	if err != nil {
		return nil, err
	}
	if nx, _, err := m.next(); err == nil && nx != nil {
		more, err := nx.Signers()
		if err == nil {
			s = append(s, more...)
		}
	}
	return s, nil
}

func (e *env) check(id string) CheckResult {
	e.t.Helper()
	res, err := Check(context.Background(), e.deps, id)
	if err != nil {
		e.t.Fatalf("Check: %v", err)
	}
	return res
}

func (e *env) findings(targetID string) map[string]scan.Finding {
	e.t.Helper()
	rows, err := e.st.DB().Query(`SELECT id, osv_id, status, kind, manifest_rel_path, severity_label, fixed_versions FROM finding WHERE project_id = ?`, targetID)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]scan.Finding{}
	for rows.Next() {
		var f scan.Finding
		var fixed string
		if err := rows.Scan(&f.ID, &f.OSVID, &f.Status, &f.Kind, &f.ManifestRelPath, &f.SeverityLabel, &fixed); err != nil {
			e.t.Fatal(err)
		}
		if fixed != "[]" {
			f.FixedVersions = []string{fixed}
		}
		out[f.OSVID] = f
	}
	return out
}

func (e *env) countAudit(action string) int {
	e.t.Helper()
	var n int
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM audit_event WHERE action = ?`, action).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func osvIDs(fs []scan.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.OSVID)
	}
	slices.Sort(out)
	return out
}

func TestCheckCreatesFindingsAndAlertsUrgent(t *testing.T) {
	e := newEnv(t)
	_, tg := e.server("srv-demo", newHost(), target.EnvProd)
	res := e.check(tg.ID)
	if res.New != 4 || res.Still != 0 || res.Gone != 0 || !res.Touched || !res.ReleaseKnown || res.SourceToEnable != "" {
		t.Fatalf("result %+v", res)
	}
	fs := e.findings(tg.ID)
	for _, id := range []string{"PHP2SHELL", "allow_url_include", "DSA-0000-1001", "DSA-0000-1002"} {
		f, ok := fs[id]
		if !ok || f.Status != scan.StatusNew {
			t.Fatalf("%s: %+v (all %v)", id, f, fs)
		}
	}
	if fs["DSA-0000-1001"].Kind != scan.KindServerPackage || fs["allow_url_include"].Kind != scan.KindServerConfig {
		t.Fatalf("kinds %+v", fs)
	}
	alerts := e.takeAlerts()
	if len(alerts) != 1 || alerts[0].Kind != AlertNew || !alerts[0].Urgent || alerts[0].Target.ID != tg.ID {
		t.Fatalf("alerts %+v", alerts)
	}
	// The grave new findings: PHP2Shell (critical), allow_url_include and
	// openssl (high), glibc (critical, no fix yet).
	if got := osvIDs(alerts[0].New); !slices.Equal(got, []string{"DSA-0000-1001", "DSA-0000-1002", "PHP2SHELL", "allow_url_include"}) {
		t.Fatalf("alerted %v", got)
	}
	for _, f := range alerts[0].New {
		switch f.OSVID {
		case "PHP2SHELL":
			if !Urgent(tg, f) {
				t.Fatalf("PHP2Shell on prod is not urgent: %+v", f)
			}
		case "DSA-0000-1002":
			if Urgent(tg, f) {
				t.Fatalf("an unfixed distribution advisory without KEV is urgent: %+v", f)
			}
			f.KEV = true
			if !Urgent(tg, f) {
				t.Fatalf("an unfixed distribution advisory in KEV is not urgent: %+v", f)
			}
		}
	}
	got, err := e.deps.Repo.Get(context.Background(), tg.ID)
	if err != nil || !got.LastCheckAt.Equal(e.now()) {
		t.Fatalf("last check %v, %v", got.LastCheckAt, err)
	}
	inv, ok, err := e.deps.Repo.LatestInventory(context.Background(), tg.ID)
	if err != nil || !ok || len(inv.Packages) != 2 {
		t.Fatalf("inventory %+v %v %v", inv, ok, err)
	}
}

func TestCheckPreprodNotUrgent(t *testing.T) {
	e := newEnv(t)
	_, tg := e.server("srv-demo", newHost(), target.EnvPreprod)
	e.check(tg.ID)
	alerts := e.takeAlerts()
	if len(alerts) != 1 || alerts[0].Urgent {
		t.Fatalf("alerts %+v", alerts)
	}
	for _, f := range alerts[0].New {
		if Urgent(tg, f) {
			t.Fatalf("urgent on preprod: %+v", f)
		}
	}
}

func TestSecondCheckKeepsStatuses(t *testing.T) {
	e := newEnv(t)
	_, tg := e.server("srv-demo", newHost(), target.EnvProd)
	first := e.check(tg.ID)
	e.takeAlerts()
	e.advance(time.Hour)
	second := e.check(tg.ID)
	if second.New != 0 || second.Still != first.New || second.Gone != 0 {
		t.Fatalf("second %+v after %+v", second, first)
	}
	fs := e.findings(tg.ID)
	if len(fs) != first.New {
		t.Fatalf("duplicates: %d findings, %d first", len(fs), first.New)
	}
	for id, f := range fs {
		if f.Status != scan.StatusPending {
			t.Fatalf("%s: %s", id, f.Status)
		}
	}
	if a := e.takeAlerts(); len(a) != 0 {
		t.Fatalf("alerted again: %+v", a)
	}
}

func TestFindingGoneWhenFixedOutsideMichel(t *testing.T) {
	e := newEnv(t)
	h := newHost()
	_, tg := e.server("srv-demo", h, target.EnvProd)
	e.check(tg.ID)
	// The administrator upgrades PHP and turns allow_url_include off.
	h.set("8.3.36", `{"allow_url_include":"0","display_errors":"0"}`)
	e.advance(time.Hour)
	res := e.check(tg.ID)
	if res.Gone != 2 || res.Still != 2 || res.New != 0 {
		t.Fatalf("result %+v", res)
	}
	fs := e.findings(tg.ID)
	for id, want := range map[string]string{"PHP2SHELL": scan.StatusGone, "allow_url_include": scan.StatusGone,
		"DSA-0000-1001": scan.StatusPending, "DSA-0000-1002": scan.StatusPending} {
		if fs[id].Status != want {
			t.Fatalf("%s: %s, want %s", id, fs[id].Status, want)
		}
	}
}

func TestRematchWithoutConnection(t *testing.T) {
	e := newEnv(t)
	srv, tg := e.server("srv-demo", newHost(), target.EnvProd)
	e.check(tg.ID)
	e.takeAlerts()
	accepted, connects, collects := srv.Accepted(), e.countAudit("target.connect"), e.countAudit("target.collect")

	// A new advisory arrives with the next database update.
	db := baseDB()
	db["DSA-0000-1003.json"] = advisory("DSA-0000-1003", "openssl", "3.0.14-1~deb12u1", "9.8")
	writeDB(t, e.deps.OSVRoot, db)
	e.advance(time.Hour)
	n, err := Rematch(context.Background(), e.deps)
	if err != nil || n != 1 {
		t.Fatalf("Rematch = %d, %v", n, err)
	}
	if srv.Accepted() != accepted || e.countAudit("target.connect") != connects || e.countAudit("target.collect") != collects {
		t.Fatalf("the rematch connected: accepted %d→%d, connect events %d→%d", accepted, srv.Accepted(), connects, e.countAudit("target.connect"))
	}
	fs := e.findings(tg.ID)
	if fs["DSA-0000-1003"].Status != scan.StatusNew || fs["PHP2SHELL"].Status != scan.StatusPending {
		t.Fatalf("findings %+v", fs)
	}
	alerts := e.takeAlerts()
	if len(alerts) != 1 || !alerts[0].Urgent || !slices.Equal(osvIDs(alerts[0].New), []string{"DSA-0000-1003"}) {
		t.Fatalf("alerts %+v", alerts)
	}
	got, _ := e.deps.Repo.Get(context.Background(), tg.ID)
	if got.LastCheckAt.Equal(e.now()) {
		t.Fatal("a rematch is not a check: the last check date moved")
	}
}

func TestSchedulerRunsDueOnly(t *testing.T) {
	e := newEnv(t)
	dueSrv, due := e.server("srv-demo-due", newHost(), target.EnvProd)
	freshSrv, fresh := e.server("srv-demo-fresh", newHost(), target.EnvProd)
	if err := e.deps.Repo.SetLastCheckAt(context.Background(), fresh.ID, e.now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Scheduler(ctx, e.deps, time.Hour)
		close(done)
	}()
	deadline := time.Now().Add(20 * time.Second)
	for {
		got, err := e.deps.Repo.Get(context.Background(), due.ID)
		if err == nil && !got.LastCheckAt.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("the due server was not checked")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if dueSrv.Accepted() == 0 || freshSrv.Accepted() != 0 {
		t.Fatalf("accepted: due %d, fresh %d", dueSrv.Accepted(), freshSrv.Accepted())
	}
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

func TestHostKeyChangedCheckFailsClearly(t *testing.T) {
	e := newEnv(t)
	h := newHost()
	_, tg := e.server("srv-demo", h, target.EnvProd)
	e.check(tg.ID)
	e.takeAlerts()
	before := e.findings(tg.ID)
	last, _ := e.deps.Repo.Get(context.Background(), tg.ID)

	// The server now shows another key, and would look fixed if read.
	if err := e.deps.Repo.SetHostKey(context.Background(), tg.ID, otherFingerprint(t)); err != nil {
		t.Fatal(err)
	}
	h.set("8.3.36", `{"allow_url_include":"0"}`)
	e.advance(time.Hour)
	res, err := Check(context.Background(), e.deps, tg.ID)
	var chg sshx.ErrHostKeyChanged
	if !errors.As(err, &chg) {
		t.Fatalf("want ErrHostKeyChanged, got %v", err)
	}
	if res.Touched || res.New+res.Still+res.Gone != 0 {
		t.Fatalf("result %+v", res)
	}
	after := e.findings(tg.ID)
	if len(after) != len(before) {
		t.Fatalf("findings %d → %d", len(before), len(after))
	}
	for id, f := range before {
		if after[id].Status != f.Status {
			t.Fatalf("%s: %s → %s", id, f.Status, after[id].Status)
		}
	}
	if a := e.takeAlerts(); len(a) != 0 {
		t.Fatalf("a failed check alerted: %+v", a)
	}
	got, _ := e.deps.Repo.Get(context.Background(), tg.ID)
	if !got.LastCheckAt.Equal(last.LastCheckAt) {
		t.Fatalf("last check moved on a failed check: %v → %v", last.LastCheckAt, got.LastCheckAt)
	}
}

func TestCheckProposesDistroSource(t *testing.T) {
	e := newEnv(t)
	_, tg := e.server("srv-demo", newHost(), target.EnvProd)
	e.check(tg.ID)

	// The Debian source is turned off: the check proposes it again and keeps
	// what it found before, since it cannot judge the packages now.
	if err := e.srcs.SetEnabled(context.Background(), "osv.debian", false); err != nil {
		t.Fatal(err)
	}
	e.advance(time.Hour)
	res := e.check(tg.ID)
	if res.SourceToEnable != "osv.debian" || res.Gone != 0 || res.Clean() {
		t.Fatalf("result %+v", res)
	}
	if fs := e.findings(tg.ID); fs["DSA-0000-1001"].Status != scan.StatusNew {
		t.Fatalf("an os finding changed without a database: %+v", fs["DSA-0000-1001"])
	}

	// A server first checked without the source has no os finding and is
	// not clean.
	e2 := newEnv(t)
	if err := e2.srcs.SetEnabled(context.Background(), "osv.debian", false); err != nil {
		t.Fatal(err)
	}
	h := newHost()
	h.set("8.3.36", `{"allow_url_include":"0"}`)
	_, tg2 := e2.server("srv-demo", h, target.EnvProd)
	res = e2.check(tg2.ID)
	if res.SourceToEnable != "osv.debian" || res.New != 0 || res.Clean() {
		t.Fatalf("result %+v", res)
	}
	// Enabled but never downloaded: the same proposal.
	if err := e2.srcs.SetEnabled(context.Background(), "osv.debian", true); err != nil {
		t.Fatal(err)
	}
	e2.deps.OSVRoot = t.TempDir()
	res = e2.check(tg2.ID)
	if res.SourceToEnable != "osv.debian" || res.Clean() {
		t.Fatalf("result %+v", res)
	}
}

func TestCleanNeedsAJudgedRelease(t *testing.T) {
	for _, c := range []struct {
		r    CheckResult
		want bool
	}{
		{CheckResult{Touched: true, ReleaseKnown: true}, true},
		{CheckResult{Touched: true, ReleaseKnown: false}, false},
		{CheckResult{Touched: true, ReleaseKnown: true, Unjudged: 1}, false},
		{CheckResult{Touched: true, ReleaseKnown: true, Still: 1}, false},
		{CheckResult{Touched: true, ReleaseKnown: true, Unseen: 1}, false},
		{CheckResult{ReleaseKnown: true}, false},
	} {
		if got := c.r.Clean(); got != c.want {
			t.Fatalf("%+v: Clean = %v", c.r, got)
		}
	}
}

// fpmHost runs a fixed command line PHP and the Debian PHP-FPM 8.2: its only
// PHP finding is the PHP2Shell mitigation opened by the distribution
// advisory of phpDB.
func fpmHost() *host {
	h := newHost()
	h.fpm, h.dpkg = true, dpkgFPM
	h.set("8.3.36", `{"allow_url_include":"0"}`)
	return h
}

func phpDB() map[string]string {
	db := baseDB()
	db["DSA-0000-2001.json"] = `{"id":"DSA-0000-2001","aliases":["CVE-2026-109618"],"severity":[{"type":"CVSS_V3","score":"9.8"}],` +
		`"affected":[{"package":{"ecosystem":"Debian:12","name":"php8.2"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.2.21-1"}]}]}]}`
	return db
}

func (e *env) status(targetID, osvID string) string {
	e.t.Helper()
	f, ok := e.findings(targetID)[osvID]
	if !ok {
		return "absent"
	}
	return f.Status
}

func TestDistroMitigationKeptWhenPackagesCannotBeJudged(t *testing.T) {
	e := newEnv(t)
	writeDB(t, e.deps.OSVRoot, phpDB())
	_, tg := e.server("srv-demo", fpmHost(), target.EnvProd)
	e.check(tg.ID)
	if st := e.status(tg.ID, "session_upload_progress_off"); st != scan.StatusNew {
		t.Fatalf("the distribution advisory did not open the mitigation: %s", st)
	}
	e.takeAlerts()

	// Source off, then archive missing: nothing can be judged, nothing closes.
	if err := e.srcs.SetEnabled(context.Background(), "osv.debian", false); err != nil {
		t.Fatal(err)
	}
	e.advance(time.Hour)
	if res := e.check(tg.ID); res.Gone != 0 {
		t.Fatalf("source off: %+v", res)
	}
	if err := e.srcs.SetEnabled(context.Background(), "osv.debian", true); err != nil {
		t.Fatal(err)
	}
	root := e.deps.OSVRoot
	e.deps.OSVRoot = t.TempDir()
	e.advance(time.Hour)
	if res := e.check(tg.ID); res.Gone != 0 {
		t.Fatalf("archive missing: %+v", res)
	}
	for _, id := range []string{"session_upload_progress_off", "DSA-0000-2001"} {
		if st := e.status(tg.ID, id); st == scan.StatusGone {
			t.Fatalf("%s closed without a judgement", id)
		}
	}
	e.deps.OSVRoot = root
	e.advance(time.Hour)
	e.check(tg.ID)
	if a := e.takeAlerts(); len(a) != 0 {
		t.Fatalf("the findings flapped and alerted again: %+v", a)
	}
}

func TestTimedOutFPMProbeKeepsItsFindings(t *testing.T) {
	e := newEnv(t)
	writeDB(t, e.deps.OSVRoot, phpDB())
	h := fpmHost()
	_, tg := e.server("srv-demo", h, target.EnvProd)
	e.check(tg.ID)
	e.takeAlerts()

	h.change(func(h *host) { h.fpmSlow = true })
	e.deps.SSH.CommandTimeout = 300 * time.Millisecond
	e.advance(time.Hour)
	res := e.check(tg.ID)
	if res.Gone != 0 || e.status(tg.ID, "session_upload_progress_off") == scan.StatusGone {
		t.Fatalf("a timed-out php-fpm -v closed findings: %+v", res)
	}
	h.change(func(h *host) { h.fpmSlow = false })
	e.deps.SSH.CommandTimeout = 0
	e.advance(time.Hour)
	e.check(tg.ID)
	if a := e.takeAlerts(); len(a) != 0 {
		t.Fatalf("alerted again: %+v", a)
	}
}

func TestFailedDiscoveryKeepsPHPFindings(t *testing.T) {
	e := newEnv(t)
	h := newHost()
	_, tg := e.server("srv-demo", h, target.EnvProd)
	e.check(tg.ID)
	e.takeAlerts()

	h.change(func(h *host) { h.findBroken = true })
	e.advance(time.Hour)
	res := e.check(tg.ID)
	if res.Gone != 0 || res.Clean() {
		t.Fatalf("a failed command -v closed findings: %+v", res)
	}
	for _, id := range []string{"PHP2SHELL", "allow_url_include"} {
		if st := e.status(tg.ID, id); st == scan.StatusGone {
			t.Fatalf("%s closed", id)
		}
	}
	h.change(func(h *host) { h.findBroken = false })
	e.advance(time.Hour)
	e.check(tg.ID)
	if a := e.takeAlerts(); len(a) != 0 {
		t.Fatalf("alerted again: %+v", a)
	}
}

// Final wave I3: a login shell without `command` (exit 1, nothing printed)
// never reads as "no PHP": the PHP findings stay open, the server is not
// clean.
func TestShellWithoutCommandKeepsPHPFindings(t *testing.T) {
	e := newEnv(t)
	h := newHost()
	_, tg := e.server("srv-demo", h, target.EnvProd)
	e.check(tg.ID)
	e.takeAlerts()
	h.change(func(h *host) { h.noCommand = true })
	e.advance(time.Hour)
	res := e.check(tg.ID)
	if res.Gone != 0 || res.Clean() {
		t.Fatalf("a shell without command closed findings: %+v", res)
	}
	for _, id := range []string{"PHP2SHELL", "allow_url_include"} {
		if st := e.status(tg.ID, id); st == scan.StatusGone {
			t.Fatalf("%s closed", id)
		}
	}
}

func TestCheckRefusesInactiveTarget(t *testing.T) {
	e := newEnv(t)
	srv, tg := e.server("srv-demo", newHost(), target.EnvProd)
	tg.Active = false
	if err := e.deps.Repo.Update(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(context.Background(), e.deps, tg.ID); !errors.Is(err, ErrInactive) {
		t.Fatalf("err = %v", err)
	}
	if srv.Accepted() != 0 {
		t.Fatal("an inactive server was contacted")
	}
}

func TestUnknownPHPVersionUrgentOnProd(t *testing.T) {
	f := scan.Finding{OSVID: "PHP-VERSION-UNKNOWN", Ecosystem: "php-upstream", SeverityLabel: "high", Kind: scan.KindServerPackage}
	if !Urgent(target.Target{Env: target.EnvProd}, f) || Urgent(target.Target{Env: target.EnvPreprod}, f) {
		t.Fatal("PHP2Shell cannot be ruled out: urgent on prod only")
	}
}

func TestReappearedDecidedFindingDoesNotAlert(t *testing.T) {
	e := newEnv(t)
	h := newHost()
	_, tg := e.server("srv-demo", h, target.EnvProd)
	e.check(tg.ID)
	e.takeAlerts()
	id := ""
	for _, f := range e.findings(tg.ID) {
		if f.OSVID == "allow_url_include" {
			id = f.ID
		}
	}
	// The risk is accepted: a decision in force on the finding.
	if _, err := e.st.DB().Exec(`INSERT INTO decision (id, finding_id, project_id, action, author, created_at, seen_severity, seen_fixed_versions)
		VALUES ('01DECISIONDEMO', ?, ?, 'accept', 'cli', '2026-10-31T10:00:00Z', 'high', '[]')`, id, tg.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.DB().Exec(`UPDATE finding SET status = 'decided' WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	h.set("8.3.35", `{"allow_url_include":"0"}`)
	e.advance(time.Hour)
	e.check(tg.ID)
	h.set("8.3.35", `{"allow_url_include":"1"}`)
	e.advance(time.Hour)
	e.check(tg.ID)
	if st := e.status(tg.ID, "allow_url_include"); st != scan.StatusDecided {
		t.Fatalf("status %s", st)
	}
	if a := e.takeAlerts(); len(a) != 0 {
		t.Fatalf("an accepted finding that came back alerted: %+v", a)
	}
}

func TestStaleRematchDoesNotOverwriteANewerCheck(t *testing.T) {
	e := newEnv(t)
	h := newHost()
	_, tg := e.server("srv-demo", h, target.EnvProd)
	e.check(tg.ID)
	old, _, err := e.deps.Repo.LatestInventory(context.Background(), tg.ID)
	if err != nil {
		t.Fatal(err)
	}
	h.set("8.3.36", `{"allow_url_include":"0"}`)
	e.advance(time.Hour)
	e.check(tg.ID)
	e.takeAlerts()
	// A rematch that read the older inventory before this check stored the
	// newer one: it must not reopen what the check closed.
	res, err := judge(context.Background(), e.deps, tg, old)
	if err != nil {
		t.Fatal(err)
	}
	if res.Touched || e.status(tg.ID, "PHP2SHELL") != scan.StatusGone {
		t.Fatalf("a stale inventory was applied: %+v, PHP2SHELL %s", res, e.status(tg.ID, "PHP2SHELL"))
	}
	if a := e.takeAlerts(); len(a) != 0 {
		t.Fatalf("alerts %+v", a)
	}
}

func TestSchedulerLogNamesNoHost(t *testing.T) {
	err := fmt.Errorf("cannot connect to server srv-demo: %w", sshx.ErrHostKeyChanged{Want: "a", Got: "b"})
	if r := reasonOf(err); r != "host_key_changed" {
		t.Fatalf("reason %q", r)
	}
	err = fmt.Errorf("x: %w: deploy@192.0.2.10", sshx.ErrNoKeyAccepted)
	if r := reasonOf(err); strings.Contains(r, "192.0.2.10") || r != "no_key_accepted" {
		t.Fatalf("reason %q", r)
	}
}

func TestUnreadableUserIniKeepsFPMFindings(t *testing.T) {
	e := newEnv(t)
	writeDB(t, e.deps.OSVRoot, phpDB())
	h := fpmHost()
	h.change(func(h *host) { h.userIni = "display_errors = On\n" })
	_, tg := e.server("srv-demo", h, target.EnvProd)
	if err := e.deps.Repo.Link(context.Background(), target.Link{TargetID: tg.ID, ProjectID: "01PROJECTDEMO", RemoteDir: "/var/www/demo"}); err != nil {
		t.Fatal(err)
	}
	e.check(tg.ID)
	if st := e.status(tg.ID, "display_errors_prod"); st != scan.StatusNew {
		t.Fatalf("the .user.ini line did not open a finding: %s", st)
	}
	// Unreadable: what it said may still hold.
	h.change(func(h *host) { h.userIniDenied = true })
	e.advance(time.Hour)
	if res := e.check(tg.ID); res.Gone != 0 || e.status(tg.ID, "display_errors_prod") == scan.StatusGone {
		t.Fatalf("an unreadable .user.ini closed findings: %+v", res)
	}
	// Removed: that is a fix, the finding closes.
	h.change(func(h *host) { h.userIniDenied, h.userIni = false, "" })
	e.advance(time.Hour)
	e.check(tg.ID)
	if st := e.status(tg.ID, "display_errors_prod"); st != scan.StatusGone {
		t.Fatalf("a removed .user.ini kept its finding: %s", st)
	}
}

func TestSkippedAdvisoryKeepsDistroMitigations(t *testing.T) {
	e := newEnv(t)
	writeDB(t, e.deps.OSVRoot, phpDB())
	_, tg := e.server("srv-demo", fpmHost(), target.EnvProd)
	e.check(tg.ID)
	e.takeAlerts()
	// The PHP advisory file is now unreadable: it may still apply.
	db := phpDB()
	db["DSA-0000-2001.json"] = "{not json"
	writeDB(t, e.deps.OSVRoot, db)
	e.advance(time.Hour)
	res := e.check(tg.ID)
	if res.SkippedAdvisories != 1 || res.Gone != 0 || res.Clean() {
		t.Fatalf("result %+v", res)
	}
	for _, id := range []string{"session_upload_progress_off", "DSA-0000-2001"} {
		if st := e.status(tg.ID, id); st == scan.StatusGone {
			t.Fatalf("%s closed on a skipped advisory", id)
		}
	}
	writeDB(t, e.deps.OSVRoot, phpDB())
	e.advance(time.Hour)
	e.check(tg.ID)
	if a := e.takeAlerts(); len(a) != 0 {
		t.Fatalf("alerted again: %+v", a)
	}
}

func TestTargetLockIsTriedAndRespectsTheContext(t *testing.T) {
	unlock, ok := TryLock("srv-lock")
	if !ok {
		t.Fatal("a free server was busy")
	}
	if _, ok := TryLock("srv-lock"); ok {
		t.Error("a held server was free")
	}
	if _, ok := TryLock("other-lock"); !ok {
		t.Error("another server was busy")
	}
	// A waiting check gives up with its context instead of waiting for the holder.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := lockTarget(ctx, "srv-lock"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("waiting = %v", err)
	}
	unlock()
	u2, err := lockTarget(context.Background(), "srv-lock")
	if err != nil {
		t.Fatal(err)
	}
	u2()
	if u3, ok := TryLock("srv-lock"); !ok {
		t.Error("released server was busy")
	} else {
		u3()
	}
}

func TestCheckStopsQuietlyWhenTheServerLeftWhileItWaited(t *testing.T) {
	e := newEnv(t)
	srv, tg := e.server("srv-gone", newHost(), target.EnvProd)
	unlock, ok := TryLock(tg.ID)
	if !ok {
		t.Fatal("lock")
	}
	done := make(chan error, 1)
	go func() {
		_, err := Check(context.Background(), e.deps, tg.ID)
		done <- err
	}()
	time.Sleep(150 * time.Millisecond) // the check waits for the lock
	if err := e.deps.Repo.Remove(context.Background(), tg.ID); err != nil {
		t.Fatal(err)
	}
	unlock()
	if err := <-done; !errors.Is(err, target.ErrNotFound) {
		t.Errorf("check of a removed server = %v", err)
	}
	if n := srv.Accepted(); n != 0 {
		t.Errorf("the removed server was reached %d times", n)
	}
}
