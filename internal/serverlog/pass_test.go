package serverlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

// testClock is a clock the tests move by hand.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// alertLog records the alerts handed to Deps.Alert.
type alertLog struct {
	mu sync.Mutex
	in []AlertInput
}

func (a *alertLog) add(_ context.Context, in AlertInput) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.in = append(a.in, in)
}

func (a *alertLog) all() []AlertInput {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]AlertInput(nil), a.in...)
}

func (a *alertLog) kinds() []AlertKind {
	var out []AlertKind
	for _, in := range a.all() {
		out = append(out, in.Kind)
	}
	return out
}

func (a *alertLog) ofKind(k AlertKind) []AlertInput {
	var out []AlertInput
	for _, in := range a.all() {
		if in.Kind == k {
			out = append(out, in)
		}
	}
	return out
}

// passEnv is one server with a log file, a real `sh` behind a simulated SSH
// server, the repositories and a clock.
type passEnv struct {
	t       *testing.T
	mu      sync.Mutex
	shell   sshtest.ShellFunc // replaces the real sh when set
	s       *store.Store
	repo    *Repo
	targets *target.Repo
	tgt     target.Target
	src     Source
	host    *logHost
	file    string
	clock   *testClock
	alerts  *alertLog
	log     *audit.Logger
	deps    Deps
}

// newPassEnv builds a server of environment e with one active source of format
// f on a temporary file, the clock at 12:30 on 2026-11-02.
func newPassEnv(t *testing.T, e target.Env, f Format) *passEnv {
	t.Helper()
	needTools(t)
	h := &logHost{}
	real := h.realShell(os.Environ())
	pe := &passEnv{t: t}
	h.srv = sshtest.New(t, sshtest.Options{Shell: func(s *sshtest.Server, script string, out, errw io.Writer) int {
		pe.mu.Lock()
		sh := pe.shell
		pe.mu.Unlock()
		if sh != nil {
			return sh(s, script, out, errw)
		}
		return real(s, script, out, errw)
	}})
	ag := h.srv.NewAgent(t)
	p := policy.Defaults()
	p.Sovereignty.Network.Allow = []policy.AllowRule{{Host: "127.0.0.1", Purpose: policy.PurposeTargetSSH}}
	gw := egress.New(p, nil)
	host, port, err := net.SplitHostPort(h.srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	pn, _ := strconv.Atoi(port)

	s, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	targets := target.NewRepo(s)
	ctx := context.Background()
	tgt, err := targets.Add(ctx, target.Target{Name: "srv-demo", Host: host, Port: pn, User: "deploy", HostKey: h.srv.HostKeyFingerprint(),
		Kind: target.KindVPS, Env: e, Classification: policy.ClassInternal})
	if err != nil {
		t.Fatal(err)
	}
	repo := NewRepo(s)
	file := filepath.Join(t.TempDir(), "app.log")
	appendTo(t, file, "")
	src, err := repo.AddSource(ctx, Source{TargetID: tgt.ID, Path: shPath(file), Format: f, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	clock := &testClock{t: readNow}
	alerts := &alertLog{}
	log := audit.NewLogger(s, clock.Now)
	pe.s, pe.repo, pe.targets, pe.tgt, pe.src, pe.host, pe.file, pe.clock, pe.alerts, pe.log = s, repo, targets, tgt, src, h, file, clock, alerts, log
	pe.deps = Deps{Repo: repo, Targets: targets, Audit: log, Alert: alerts.add, Now: clock.Now, SSH: sshx.Deps{
		Gateway:    gw,
		KnownHosts: filepath.Join(t.TempDir(), "known_hosts"),
		Agent:      func() (agent.ExtendedAgent, io.Closer, error) { return ag, nil, nil },
		Now:        clock.Now,
	}}
	return pe
}

// run does one pass and fails the test on an error.
func (pe *passEnv) run() PassResult {
	pe.t.Helper()
	res, err := Pass(context.Background(), pe.deps, pe.tgt.ID)
	if err != nil {
		pe.t.Fatalf("Pass: %v", err)
	}
	return res
}

// activate does the first pass, which only locates the end of the file.
func (pe *passEnv) activate() {
	pe.t.Helper()
	if res := pe.run(); res.Records != 0 {
		pe.t.Fatalf("activation read %+v", res)
	}
}

func (pe *passEnv) write(lines ...string) {
	pe.t.Helper()
	appendTo(pe.t, pe.file, strings.Join(lines, "\n")+"\n")
}

func (pe *passEnv) settings() Settings {
	pe.t.Helper()
	st, err := pe.repo.Settings(context.Background(), pe.tgt.ID)
	if err != nil {
		pe.t.Fatal(err)
	}
	return st
}

func (pe *passEnv) save(st Settings) {
	pe.t.Helper()
	if err := pe.repo.SaveSettings(context.Background(), st); err != nil {
		pe.t.Fatal(err)
	}
}

func (pe *passEnv) signatures() []Signature {
	pe.t.Helper()
	out, err := pe.repo.Signatures(context.Background(), pe.tgt.ID)
	if err != nil {
		pe.t.Fatal(err)
	}
	return out
}

func (pe *passEnv) notes(kind string) []Note {
	pe.t.Helper()
	all, err := pe.repo.Notes(context.Background(), pe.tgt.ID)
	if err != nil {
		pe.t.Fatal(err)
	}
	var out []Note
	for _, n := range all {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	return out
}

// mono is a Monolog line at 12:05 on 2026-11-02.
func mono(level, class, file string, line int) string {
	return fmt.Sprintf("[2026-11-02 12:05:00] app.%s: boom [object] (%s(code: 0): x at /var/www/demo/src/%s:%d)", level, class, file, line)
}

func TestPassAppliesRoutes(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42), mono("ERROR", "RuntimeException", "Mail.php", 7), mono("WARNING", "LogicException", "Warn.php", 1))
	res := pe.run()
	if res.Records != 3 || res.Alerts != 1 || res.Reason != "" {
		t.Fatalf("result = %+v", res)
	}
	got := pe.alerts.all()
	if len(got) != 1 || got[0].Kind != AlertNew || len(got[0].Items) != 1 || got[0].Target.ID != pe.tgt.ID {
		t.Fatalf("alerts = %+v", got)
	}
	it := got[0].Items[0]
	if it.Level != LevelCritical || it.Type != "PDOException" || it.Location != "Invoice.php:42" || it.Count != 1 || it.Text != "" {
		t.Errorf("item = %+v", it)
	}
	if n := len(pe.signatures()); n != 3 {
		t.Errorf("the other levels are stored for the digest: %d signatures", n)
	}
	if sigs := pe.signatures(); sigs[0].LastAlertAt.IsZero() && sigs[1].LastAlertAt.IsZero() && sigs[2].LastAlertAt.IsZero() {
		t.Error("the told error is not marked")
	}
}

func TestPassRoutesFollowTheSettings(t *testing.T) {
	// In preprod nothing is immediate by default; the user can make errors so.
	pe := newPassEnv(t, target.EnvPreprod, FormatMonolog)
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	if pe.run(); len(pe.alerts.all()) != 0 {
		t.Fatalf("preprod told at once: %+v", pe.alerts.all())
	}
	st := pe.settings()
	st.Routes[LevelError] = RouteImmediate
	pe.save(st)
	pe.write(mono("ERROR", "RuntimeException", "Mail.php", 7))
	pe.run()
	if got := pe.alerts.all(); len(got) != 1 || got[0].Items[0].Type != "RuntimeException" {
		t.Fatalf("alerts = %+v", got)
	}
}

func TestPerSignatureIgnoredStaysSilent(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	pe.run()
	if len(pe.alerts.all()) != 1 {
		t.Fatalf("first: %v", pe.alerts.kinds())
	}
	if err := pe.repo.SetStatus(context.Background(), pe.signatures()[0].ID, StatusIgnored); err != nil {
		t.Fatal(err)
	}
	// 150 in an hour would be a spike; an ignored error is still silent.
	lines := make([]string, 150)
	for i := range lines {
		lines[i] = mono("CRITICAL", "PDOException", "Invoice.php", 42)
	}
	pe.write(lines...)
	pe.run()
	if len(pe.alerts.all()) != 1 {
		t.Fatalf("an ignored error alerted: %v", pe.alerts.kinds())
	}
	if sigs := pe.signatures(); sigs[0].Total != 151 || sigs[0].Status != StatusIgnored {
		t.Errorf("an ignored error is still counted: %+v", sigs[0])
	}
}

func TestNewSignaturesGroupedInOneAlert(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "A.php", 1), mono("CRITICAL", "PDOException", "B.php", 2), mono("CRITICAL", "RuntimeException", "C.php", 3), mono("CRITICAL", "RuntimeException", "C.php", 3))
	res := pe.run()
	got := pe.alerts.all()
	if res.Alerts != 1 || len(got) != 1 || got[0].Kind != AlertNew || len(got[0].Items) != 3 {
		t.Fatalf("want one alert of 3 errors, got %+v", got)
	}
	if first := got[0].Items[0]; first.Location != "C.php:3" || first.Count != 2 {
		t.Errorf("the most frequent of the same level comes first: %+v", got[0].Items)
	}
}

func TestReopenedErrorAlerts(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	pe.run()
	// Eight days without it: resolved. It comes back.
	pe.clock.Advance(8 * 24 * time.Hour)
	pe.run()
	if sigs := pe.signatures(); sigs[0].Status != StatusResolved {
		t.Fatalf("status = %s", sigs[0].Status)
	}
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	pe.clock.Advance(time.Minute)
	pe.run()
	if got := pe.alerts.ofKind(AlertReopened); len(got) != 1 || got[0].Items[0].Type != "PDOException" {
		t.Fatalf("alerts = %v", pe.alerts.kinds())
	}
}

func TestSpikeRealerts(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	pe.run()
	lines := make([]string, 150)
	for i := range lines {
		lines[i] = mono("CRITICAL", "PDOException", "Invoice.php", 42)
	}
	pe.write(lines...)
	pe.run()
	spikes := pe.alerts.ofKind(AlertSpike)
	if len(spikes) != 1 || len(spikes[0].Items) != 1 || spikes[0].Items[0].Count != 151 {
		t.Fatalf("spike alerts = %+v (all %v)", spikes, pe.alerts.kinds())
	}
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	pe.run()
	if n := len(pe.alerts.ofKind(AlertSpike)); n != 1 {
		t.Errorf("the same hour spiked again: %d", n)
	}
}

func TestHourlyCapThenOneMessage(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	var lines []string
	for i := 1; i <= 12; i++ {
		lines = append(lines, mono("CRITICAL", "PDOException", fmt.Sprintf("F%d.php", i), i))
	}
	pe.write(lines...)
	res := pe.run()
	news, caps := pe.alerts.ofKind(AlertNew), pe.alerts.ofKind(AlertCapReached)
	if len(news) != 1 || len(news[0].Items) != 10 || len(caps) != 1 || res.Alerts != 2 {
		t.Fatalf("want 10 errors then one cap message, got %v with %d items", pe.alerts.kinds(), len(news[0].Items))
	}
	// More errors in the same hour: nothing more, not even a second message.
	pe.clock.Advance(5 * time.Minute)
	pe.write(mono("CRITICAL", "PDOException", "G1.php", 1), mono("CRITICAL", "PDOException", "G2.php", 2))
	pe.run()
	if len(pe.alerts.all()) != 2 {
		t.Fatalf("alerts after the cap: %v", pe.alerts.kinds())
	}
	held := 0
	for _, g := range pe.signatures() {
		if g.LastAlertAt.IsZero() {
			held++
		}
	}
	if held != 4 {
		t.Errorf("the held errors stay for the digest, unmarked: %d", held)
	}
	// An hour later the room is back.
	pe.clock.Advance(time.Hour)
	pe.write(mono("CRITICAL", "PDOException", "H1.php", 1))
	pe.run()
	if got := pe.alerts.ofKind(AlertNew); len(got) != 2 || got[1].Items[0].Location != "H1.php:1" {
		t.Fatalf("after the hour: %v", pe.alerts.kinds())
	}
}

func TestCapIsTheSettingOfTheServer(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	st := pe.settings()
	st.MaxAlertsPerHour = 2
	pe.save(st)
	pe.activate()
	pe.write(mono("CRITICAL", "A", "A.php", 1), mono("CRITICAL", "B", "B.php", 1), mono("CRITICAL", "C", "C.php", 1))
	pe.run()
	if news := pe.alerts.ofKind(AlertNew); len(news) != 1 || len(news[0].Items) != 2 || len(pe.alerts.ofKind(AlertCapReached)) != 1 {
		t.Fatalf("alerts = %v", pe.alerts.kinds())
	}
}

var traps = []string{"jean.dupont@example.test", "198.51.100.23", "2001:db8::1", "1850175123456", "SELECT * FROM patient WHERE nom = 'Durand'", "https://example.test/reset?token=abc123"}

func TestAuditLogReadHasNoContent(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	var lines []string
	for _, m := range traps {
		lines = append(lines, fmt.Sprintf("[2026-11-02 12:05:00] app.CRITICAL: %s [object] (PDOException(code: 0): %s at /var/www/demo/src/Invoice.php:42)", m, m))
	}
	pe.write(lines...)
	pe.run()
	rows, err := pe.s.DB().Query(`SELECT target, result, evidence FROM audit_event WHERE action = 'log.read' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var reads []map[string]any
	for rows.Next() {
		var tg, result, ev string
		if err := rows.Scan(&tg, &result, &ev); err != nil {
			t.Fatal(err)
		}
		if tg != pe.tgt.ID || result != "ok" {
			t.Errorf("target %q result %q", tg, result)
		}
		for _, m := range traps {
			if strings.Contains(ev, m) {
				t.Errorf("the audit holds %q: %s", m, ev)
			}
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ev), &m); err != nil {
			t.Fatal(err)
		}
		reads = append(reads, m)
	}
	if len(reads) != 2 {
		t.Fatalf("one log.read per read (activation and pass), got %d", len(reads))
	}
	ev := reads[1]
	for _, k := range []string{"source", "from", "to", "volume", "records", "fingerprint"} {
		if _, ok := ev[k]; !ok {
			t.Errorf("log.read has no %q: %v", k, ev)
		}
	}
	if ev["source"] != pe.src.ID || ev["records"] != float64(1) || len(fmt.Sprint(ev["fingerprint"])) != 64 || ev["volume"].(float64) <= 0 {
		t.Errorf("log.read = %v", ev)
	}
	// The same result has the same fingerprint, a different one does not.
	a, b := fingerprint([]Record{rec(2, t0), rec(1, t0)}), fingerprint([]Record{rec(1, t0), rec(2, t0)})
	if a != b || a == fingerprint([]Record{rec(3, t0)}) {
		t.Error("fingerprint is not a function of the records")
	}
	for _, in := range pe.alerts.all() {
		for _, it := range in.Items {
			for _, m := range traps {
				if strings.Contains(it.Type+it.Location+it.Text, m) {
					t.Errorf("an alert holds %q: %+v", m, it)
				}
			}
		}
	}
}

func TestAlertTextOnlyWhenAllowed(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	line := func(n int) string {
		return fmt.Sprintf("[2026-11-02 12:05:00] app.CRITICAL: Payment declined for %q [object] (PDOException(code: 0): x at /var/www/demo/src/Pay%d.php:1)", "jean.dupont@example.test", n)
	}
	pe.write(line(1))
	pe.run()
	if it := pe.alerts.all()[0].Items[0]; it.Text != "" {
		t.Fatalf("default settings sent text: %q", it.Text)
	}
	ctx := context.Background()
	next := pe.settings()
	next.StoreText = true
	if err := ChangeSettings(ctx, pe.repo, pe.log, pe.tgt, next, true); err != nil {
		t.Fatal(err)
	}
	pe.write(line(2))
	pe.run()
	if it := pe.alerts.all()[1].Items[0]; it.Text != "" {
		t.Fatalf("kept text alone reached an alert: %q", it.Text)
	}
	next.AlertText = true
	if err := ChangeSettings(ctx, pe.repo, pe.log, pe.tgt, next, true); err != nil {
		t.Fatal(err)
	}
	pe.write(line(3))
	pe.run()
	it := pe.alerts.all()[2].Items[0]
	if !strings.Contains(it.Text, "Payment declined") || strings.Contains(it.Text, "dupont") || strings.Contains(it.Text, "example.test") {
		t.Fatalf("alert text = %q", it.Text)
	}
}

func TestVolumeFollowsErrorRoute(t *testing.T) {
	for _, tc := range []struct {
		route Route
		told  bool
	}{{RouteImmediate, true}, {RouteDigest, false}, {RouteIgnored, false}} {
		t.Run(string(tc.route), func(t *testing.T) {
			pe := newPassEnv(t, target.EnvProd, FormatMonolog)
			st := pe.settings()
			st.ReadCap = 2048
			st.Routes[LevelError] = tc.route
			pe.save(st)
			pe.activate()
			big := func() []string {
				lines := make([]string, 60)
				for i := range lines {
					lines[i] = mono("WARNING", "LogicException", "Warn.php", 1)
				}
				return lines
			}
			pe.write(big()...)
			pe.run()
			vol := pe.alerts.ofKind(AlertVolume)
			if (len(vol) == 1) != tc.told {
				t.Fatalf("route %s: alerts %v", tc.route, pe.alerts.kinds())
			}
			if tc.told && (len(vol[0].Items) != 1 || vol[0].Items[0].Count <= 0 || vol[0].Items[0].Level != LevelError) {
				t.Errorf("volume item = %+v", vol[0].Items)
			}
			if notes := pe.notes(NoteSkipped); len(notes) != 1 || notes[0].Amount <= 0 {
				t.Errorf("the skipped volume is a note for the page and the digest: %+v", notes)
			}
			// Still too big five minutes later: told once an hour.
			pe.clock.Advance(5 * time.Minute)
			pe.write(big()...)
			pe.run()
			if n := len(pe.alerts.ofKind(AlertVolume)); (n == 1) != tc.told {
				t.Errorf("volume alerts after the second read: %d", n)
			}
			if tc.told {
				pe.clock.Advance(time.Hour)
				pe.write(big()...)
				pe.run()
				if n := len(pe.alerts.ofKind(AlertVolume)); n != 2 {
					t.Errorf("an hour later the volume is told again: %d", n)
				}
			}
		})
	}
}

func TestPassWithoutAlertCallbackStillStores(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.deps.Alert = nil
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	if res := pe.run(); res.Alerts != 0 || res.Records != 1 {
		t.Fatalf("result = %+v", res)
	}
	if sigs := pe.signatures(); len(sigs) != 1 || !sigs[0].LastAlertAt.IsZero() {
		t.Errorf("nothing was told, nothing is marked: %+v", sigs)
	}
}

func TestPassStoresErrorsWithoutAType(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatPHP)
	pe.activate()
	pe.write("PHP Warning:  Undefined variable $x in /var/www/demo/a.php on line 3")
	if res := pe.run(); res.Records != 1 {
		t.Fatalf("result = %+v", res)
	}
	if sigs := pe.signatures(); len(sigs) != 1 || sigs[0].Type != "" || sigs[0].Location != "a.php:3" || sigs[0].Level != LevelWarning {
		t.Fatalf("signatures = %+v", sigs)
	}
}

func TestPassPrunesCursorsOfGoneFilesAndThePlaceholder(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatPHP)
	dir := t.TempDir()
	src, err := pe.repo.AddSource(context.Background(), Source{TargetID: pe.tgt.ID, Path: shPath(dir) + "/app-*.log", Format: FormatPHP, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	// Only this source: the one from newPassEnv would add its own positions.
	if err := pe.repo.UpdateSource(context.Background(), Source{ID: pe.src.ID, Path: pe.src.Path, Format: pe.src.Format, Active: false}); err != nil {
		t.Fatal(err)
	}
	cursors := func() []Cursor {
		cs, err := pe.repo.Cursors(context.Background(), src.ID)
		if err != nil {
			t.Fatal(err)
		}
		return cs
	}
	// Activation with no file: a placeholder.
	pe.run()
	if cs := cursors(); len(cs) != 1 || !strings.HasSuffix(cs[0].File, "/") {
		t.Fatalf("placeholder = %+v", cs)
	}
	line := "PHP Warning:  x in /var/www/demo/a.php on line 3\n"
	appendTo(t, filepath.Join(dir, "app-1.log"), line)
	appendTo(t, filepath.Join(dir, "app-2.log"), line)
	pe.run()
	cs := cursors()
	if len(cs) != 2 {
		t.Fatalf("the placeholder stays once real positions exist: %+v", cs)
	}
	for _, c := range cs {
		if strings.HasSuffix(c.File, "/") {
			t.Errorf("placeholder left: %+v", c)
		}
	}
	// A file is gone.
	if err := os.Remove(filepath.Join(dir, "app-1.log")); err != nil {
		t.Fatal(err)
	}
	appendTo(t, filepath.Join(dir, "app-2.log"), line)
	res := pe.run()
	cs = cursors()
	if len(cs) != 1 || !strings.HasSuffix(cs[0].File, "app-2.log") || res.Records != 1 {
		t.Fatalf("the position of a gone file stays: %+v, result %+v", cs, res)
	}
}

func TestPassKeepsCursorsWhenTheFileListIsCut(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatPHP)
	dir := t.TempDir()
	for i := 0; i < maxFilesCeiling+2; i++ {
		appendTo(t, filepath.Join(dir, fmt.Sprintf("app-%03d.log", i)), "x\n")
	}
	src, err := pe.repo.AddSource(context.Background(), Source{TargetID: pe.tgt.ID, Path: shPath(dir) + "/app-*.log", Format: FormatPHP, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := pe.repo.UpdateSource(context.Background(), Source{ID: pe.src.ID, Path: pe.src.Path, Format: pe.src.Format, Active: false}); err != nil {
		t.Fatal(err)
	}
	pe.run()
	before, _ := pe.repo.Cursors(context.Background(), src.ID)
	if len(before) != maxFilesCeiling {
		t.Fatalf("positions = %d", len(before))
	}
	// A listed file goes: the list is still cut, so nothing can be told gone.
	if err := os.Remove(filepath.Join(dir, "app-051.log")); err != nil {
		t.Fatal(err)
	}
	pe.run()
	after, _ := pe.repo.Cursors(context.Background(), src.ID)
	if len(after) < maxFilesCeiling {
		t.Fatalf("positions pruned from a cut list: %d", len(after))
	}
	if n := len(pe.notes(NoteTooManyFiles)); n != 1 {
		t.Errorf("too many files is one note that lasts, got %d", n)
	}
}

func TestPassReportsTheCause(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.deps.SSH.Agent = func() (agent.ExtendedAgent, io.Closer, error) { return nil, nil, sshx.ErrNoAgent }
	res, err := Pass(context.Background(), pe.deps, pe.tgt.ID)
	if err == nil || res.Reason != ReasonNoAgent {
		t.Fatalf("result %+v, err %v", res, err)
	}
}

func TestPassFailureKeepsThePositions(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	before, _ := pe.repo.Cursors(context.Background(), pe.src.ID)
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	// The server cannot run the filter any more.
	pe.setShell(func(_ *sshtest.Server, _ string, _ io.Writer, _ io.Writer) int { return 1 })
	res, err := Pass(context.Background(), pe.deps, pe.tgt.ID)
	if err == nil || res.Reason != ReasonError {
		t.Fatalf("result %+v, err %v", res, err)
	}
	after, _ := pe.repo.Cursors(context.Background(), pe.src.ID)
	if len(after) != 1 || len(before) != 1 || after[0].Offset != before[0].Offset {
		t.Errorf("a failed read moved a position: %+v -> %+v", before, after)
	}
	if len(pe.signatures()) != 0 {
		t.Error("a failed read stored errors")
	}
	var result, ev string
	if err := pe.s.DB().QueryRow(`SELECT result, evidence FROM audit_event WHERE action = 'log.read' ORDER BY id DESC LIMIT 1`).Scan(&result, &ev); err != nil || result != "failed" || !strings.Contains(ev, `"reason":"error"`) {
		t.Errorf("failed read audit = %q %s (%v)", result, ev, err)
	}
	// The next read, with a working server, reads what was waiting.
	pe.setShell(nil)
	pe.run()
	if len(pe.signatures()) != 1 {
		t.Error("the line waiting was not read after the failure")
	}
}

func TestPassInactiveServerIsNotRead(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	tg := pe.tgt
	tg.Active = false
	if err := pe.targets.Update(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	res, err := Pass(context.Background(), pe.deps, pe.tgt.ID)
	if !errors.Is(err, ErrInactive) || res.Reason != ReasonInactive || pe.host.srv.Accepted() != 0 {
		t.Fatalf("result %+v, err %v, connections %d", res, err, pe.host.srv.Accepted())
	}
}

func TestPassNeverRunsTwiceForOneServer(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	entered, release := make(chan struct{}), make(chan struct{})
	pe.setShell(func(_ *sshtest.Server, _ string, out io.Writer, _ io.Writer) int {
		close(entered)
		<-release
		io.WriteString(out, "N\n")
		return 0
	})
	slow := pe.deps
	done := make(chan error, 1)
	go func() { _, err := Pass(context.Background(), slow, pe.tgt.ID); done <- err }()
	<-entered
	res, err := Pass(context.Background(), slow, pe.tgt.ID)
	if !errors.Is(err, ErrPassRunning) || res.Reason != ReasonBusy {
		t.Errorf("second pass: %+v, %v", res, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Errorf("first pass: %v", err)
	}
}

func TestReturnAfterDaysOffIsOneAlertAndOneGap(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	// The computer was off for three days; the log went on.
	pe.clock.Advance(3 * 24 * time.Hour)
	var lines []string
	for i := 1; i <= 5; i++ {
		lines = append(lines, mono("CRITICAL", "PDOException", fmt.Sprintf("F%d.php", i), i))
	}
	pe.write(lines...)
	pe.run()
	if news := pe.alerts.all(); len(news) != 1 || news[0].Kind != AlertNew || len(news[0].Items) != 5 {
		t.Fatalf("alerts = %+v", news)
	}
	gaps := pe.notes(NoteGap)
	if len(gaps) != 1 || !gaps[0].From.Equal(readNow) || !gaps[0].To.Equal(readNow.Add(3*24*time.Hour)) || gaps[0].SourceID != pe.src.ID {
		t.Fatalf("gaps = %+v", gaps)
	}
	// Reading goes on at its rhythm: no second gap, no second alert.
	pe.clock.Advance(5 * time.Minute)
	pe.write(mono("CRITICAL", "PDOException", "F1.php", 1))
	pe.run()
	if len(pe.alerts.all()) != 1 || len(pe.notes(NoteGap)) != 1 {
		t.Errorf("alerts %v, gaps %d", pe.alerts.kinds(), len(pe.notes(NoteGap)))
	}
}

func TestShortSilenceIsNoGap(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	pe.clock.Advance(9 * time.Minute) // under twice the interval
	pe.run()
	pe.clock.Advance(25 * time.Minute) // under the floor of 30 minutes
	pe.run()
	if g := pe.notes(NoteGap); len(g) != 0 {
		t.Errorf("gaps = %+v", g)
	}
}

func TestOnlyTheIntervalMattersForTheGapOfASlowServer(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	st := pe.settings()
	st.Interval = 6 * time.Hour
	pe.save(st)
	pe.activate()
	pe.clock.Advance(7 * time.Hour) // a read every 6 hours, a little late
	pe.run()
	if g := pe.notes(NoteGap); len(g) != 0 {
		t.Errorf("a late read on a 6 hour rhythm is no gap: %+v", g)
	}
	pe.clock.Advance(13 * time.Hour)
	pe.run()
	if g := pe.notes(NoteGap); len(g) != 1 {
		t.Errorf("gaps = %+v", g)
	}
}

func TestUnseenIsOneNoteThatLasts(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	if err := os.Remove(pe.file); err != nil {
		t.Fatal(err)
	}
	pe.run()
	for i := 0; i < 4; i++ {
		pe.clock.Advance(5 * time.Minute)
		pe.run()
	}
	notes := pe.notes(NoteUnseen)
	if len(notes) != 1 || !notes[0].To.Equal(readNow.Add(20*time.Minute)) || !notes[0].From.Equal(readNow) {
		t.Fatalf("unseen notes = %+v", notes)
	}
}

func TestConcurrentPassesCountALineOnce(t *testing.T) {
	// Calls at the same time for one server: one reads, the others are refused.
	a := newPassEnv(t, target.EnvProd, FormatMonolog)
	a.activate()
	a.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = Pass(context.Background(), a.deps, a.tgt.ID)
		}()
	}
	wg.Wait()
	if sigs := a.signatures(); len(sigs) != 1 || sigs[0].Total != 1 {
		t.Fatalf("the line was counted %+v", sigs)
	}
}

// setShell makes the simulated server run sh instead of the real one; nil gives
// the real one back.
func (pe *passEnv) setShell(sh sshtest.ShellFunc) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.shell = sh
}
