package serverlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	for _, g := range pe.signatures() {
		if told := g.Level == LevelCritical; told == g.LastAlertAt.IsZero() {
			t.Errorf("only the told error is marked: %s %s, last alert %v", g.Level, g.Type, g.LastAlertAt)
		}
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

// The cap counts messages: a read with many errors is one message, all told.
func TestHourlyCapCountsMessagesNotErrors(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	var lines []string
	for i := 1; i <= 30; i++ {
		lines = append(lines, mono("CRITICAL", "PDOException", fmt.Sprintf("F%d.php", i), i))
	}
	pe.write(lines...)
	res := pe.run()
	news := pe.alerts.ofKind(AlertNew)
	if len(news) != 1 || len(news[0].Items) != 30 || len(pe.alerts.ofKind(AlertCapReached)) != 0 || res.Alerts != 1 {
		t.Fatalf("want one message with the 30 errors, got %v", pe.alerts.kinds())
	}
	for _, g := range pe.signatures() {
		if g.LastAlertAt.IsZero() {
			t.Errorf("%s is in the message but not marked as told", g.Location)
		}
	}
}

// 10 new criticals in a read do not silence the next reads of the hour: each
// gets its message, until the hour's messages are used. Then one "more errors"
// message, then silence, with what is held left to the digest.
func TestHourlyCapThenOneMessage(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	var lines []string
	for i := 1; i <= 10; i++ {
		lines = append(lines, mono("CRITICAL", "PDOException", fmt.Sprintf("F%d.php", i), i))
	}
	pe.write(lines...)
	pe.run()
	// Nine more reads in the same hour, each with a new critical: nine messages.
	for i := 1; i <= 9; i++ {
		pe.clock.Advance(time.Minute)
		loc := fmt.Sprintf("G%d.php", i)
		pe.write(mono("CRITICAL", "PDOException", loc, 1))
		pe.run()
		news := pe.alerts.ofKind(AlertNew)
		if len(news) != i+1 || len(news[i].Items) != 1 || news[i].Items[0].Location != loc+":1" {
			t.Fatalf("read %d of the hour: alerts = %v", i+1, pe.alerts.kinds())
		}
	}
	if n := len(pe.alerts.ofKind(AlertCapReached)); n != 0 {
		t.Fatalf("cap message before the cap: %d", n)
	}
	// The hour's messages are used: the whole next read is held, one message says so.
	pe.clock.Advance(time.Minute)
	pe.write(mono("CRITICAL", "PDOException", "H1.php", 1), mono("CRITICAL", "PDOException", "H2.php", 1))
	res := pe.run()
	if len(pe.alerts.ofKind(AlertNew)) != 10 || len(pe.alerts.ofKind(AlertCapReached)) != 1 || res.Alerts != 1 {
		t.Fatalf("after the cap: %v", pe.alerts.kinds())
	}
	// More errors in the same hour: nothing more, not even a second message.
	pe.clock.Advance(time.Minute)
	pe.write(mono("CRITICAL", "PDOException", "H3.php", 1))
	pe.run()
	if len(pe.alerts.all()) != 11 {
		t.Fatalf("alerts after the cap: %v", pe.alerts.kinds())
	}
	held := 0
	for _, g := range pe.signatures() {
		if g.LastAlertAt.IsZero() {
			held++
		}
	}
	if held != 3 {
		t.Errorf("the held errors stay for the digest, unmarked: %d", held)
	}
	// An hour later the room is back.
	pe.clock.Advance(time.Hour)
	pe.write(mono("CRITICAL", "PDOException", "J1.php", 1))
	pe.run()
	news := pe.alerts.ofKind(AlertNew)
	if len(news) != 11 || news[10].Items[0].Location != "J1.php:1" {
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
	if news := pe.alerts.ofKind(AlertNew); len(news) != 1 || len(news[0].Items) != 3 || len(pe.alerts.ofKind(AlertCapReached)) != 0 {
		t.Fatalf("first read: %v", pe.alerts.kinds())
	}
	pe.clock.Advance(time.Minute)
	pe.write(mono("CRITICAL", "D", "D.php", 1))
	pe.run()
	pe.clock.Advance(time.Minute)
	pe.write(mono("CRITICAL", "E", "E.php", 1))
	pe.run()
	if len(pe.alerts.ofKind(AlertNew)) != 2 || len(pe.alerts.ofKind(AlertCapReached)) != 1 {
		t.Fatalf("after two messages: %v", pe.alerts.kinds())
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
	const readCap = 2048
	st := pe.settings()
	st.ReadCap = readCap
	pe.save(st)
	pe.activate()
	// An error known from before, resolved since: it will come back.
	pe.write(mono("CRITICAL", "PDOException", "Back.php", 9))
	pe.run()
	for _, g := range pe.signatures() {
		if err := pe.repo.SetStatus(context.Background(), g.ID, StatusResolved); err != nil {
			t.Fatal(err)
		}
	}
	told := len(pe.alerts.all())

	// The computer was off for three days; the log went on, far past the cap. The
	// filter reads the end of it, so that is where the errors are.
	pe.clock.Advance(3 * 24 * time.Hour)
	var lines []string
	for i := 0; i < 80; i++ {
		lines = append(lines, mono("WARNING", "LogicException", "Warn.php", 1))
	}
	for i := 1; i <= 5; i++ {
		lines = append(lines, mono("CRITICAL", "PDOException", fmt.Sprintf("F%d.php", i), i))
	}
	lines = append(lines, mono("CRITICAL", "PDOException", "Back.php", 9))
	sizeBefore := fileSize(t, pe.file)
	pe.write(lines...)
	written := fileSize(t, pe.file) - sizeBefore
	if written <= readCap {
		t.Fatalf("the backlog is not over the cap: %d", written)
	}
	res := pe.run()

	// With the default routes the volume waits for the digest: the whole return
	// is one alert, the new and the reopened errors together.
	got := pe.alerts.all()[told:]
	if len(got) != 1 || res.Alerts != 1 || got[0].Kind != AlertNew || len(got[0].Items) != 6 {
		t.Fatalf("want one grouped alert, result %+v, alerts %+v", res, got)
	}
	kinds := map[AlertKind]int{}
	for _, it := range got[0].Items {
		kinds[it.Kind]++
	}
	if kinds[AlertNew] != 5 || kinds[AlertReopened] != 1 {
		t.Errorf("each item says its own reason: %v", kinds)
	}
	// The cap holds, and what it left is said.
	ev := lastLogRead(t, pe)
	volume, skipped := int64(ev["volume"].(float64)), int64(ev["skipped"].(float64))
	if volume <= 0 || volume > readCap || skipped <= 0 || volume+skipped != written {
		t.Errorf("read %d and skipped %d of %d, cap %d", volume, skipped, written, readCap)
	}
	if notes := pe.notes(NoteSkipped); len(notes) != 1 || notes[0].Amount != skipped {
		t.Errorf("skipped notes = %+v, want %d", notes, skipped)
	}
	gaps := pe.notes(NoteGap)
	if len(gaps) != 1 || !gaps[0].From.Equal(readNow) || !gaps[0].To.Equal(readNow.Add(3*24*time.Hour)) || gaps[0].SourceID != pe.src.ID {
		t.Fatalf("gaps = %+v", gaps)
	}
	// Reading goes on at its rhythm: no second gap, no second alert.
	pe.clock.Advance(5 * time.Minute)
	pe.write(mono("CRITICAL", "PDOException", "F1.php", 1))
	pe.run()
	if n := len(pe.alerts.all()) - told; n != 1 || len(pe.notes(NoteGap)) != 1 {
		t.Errorf("alerts %v, gaps %d", pe.alerts.kinds(), len(pe.notes(NoteGap)))
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

// lastLogRead is the evidence of the latest log.read event.
func lastLogRead(t *testing.T, pe *passEnv) map[string]any {
	t.Helper()
	var raw string
	if err := pe.s.DB().QueryRow(`SELECT evidence FROM audit_event WHERE action = 'log.read' ORDER BY id DESC LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// monoAt is a Monolog line of the given date.
func monoAt(at time.Time, level, class, file string, line int) string {
	return fmt.Sprintf("[%s] app.%s: boom [object] (%s(code: 0): x at /var/www/demo/src/%s:%d)", at.UTC().Format("2006-01-02 15:04:05"), level, class, file, line)
}

func repeated(n int, line string) []string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = line
	}
	return lines
}

// captureLog sends what the package logs to a buffer for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func renameTable(t *testing.T, s *store.Store, from, to string) {
	t.Helper()
	if _, err := s.DB().Exec(`ALTER TABLE ` + from + ` RENAME TO ` + to); err != nil {
		t.Fatal(err)
	}
}

// afterRead runs fn once, when the filter has answered and before Pass handles
// the answer.
func (pe *passEnv) afterRead(fn func()) {
	real := pe.host.realShell(os.Environ())
	var once sync.Once
	pe.setShell(func(s *sshtest.Server, script string, out, errw io.Writer) int {
		code := real(s, script, out, errw)
		once.Do(fn)
		return code
	})
}

func TestResolveStaysOnTheServerRead(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	ctx := context.Background()
	other, err := pe.targets.Add(ctx, target.Target{Name: "srv-other", Host: "192.0.2.9", User: "deploy", Kind: target.KindVPS, Env: target.EnvProd, Classification: policy.ClassInternal})
	if err != nil {
		t.Fatal(err)
	}
	src, err := pe.repo.AddSource(ctx, Source{TargetID: other.ID, Path: "/var/log/demo/app.log", Format: FormatMonolog, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := pe.repo.Apply(ctx, src, []Record{rec(1, readNow)}, readNow); err != nil {
		t.Fatal(err)
	}
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	pe.run()
	// Eight days on, this server is read and the other one is not.
	pe.clock.Advance(8 * 24 * time.Hour)
	pe.run()
	if sigs := pe.signatures(); sigs[0].Status != StatusResolved {
		t.Errorf("the server read: status = %s", sigs[0].Status)
	}
	sigs, err := pe.repo.Signatures(ctx, other.ID)
	if err != nil || len(sigs) != 1 || sigs[0].Status != StatusNew {
		t.Errorf("a server not read went resolved: %+v, %v", sigs, err)
	}
}

func TestOnePassIsOneAlertForItsErrors(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	ctx := context.Background()
	second := filepath.Join(t.TempDir(), "other.log")
	appendTo(t, second, "")
	if _, err := pe.repo.AddSource(ctx, Source{TargetID: pe.tgt.ID, Path: shPath(second), Format: FormatMonolog, Active: true}); err != nil {
		t.Fatal(err)
	}
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "Often.php", 1), mono("CRITICAL", "PDOException", "Back.php", 2))
	pe.run()
	for _, g := range pe.signatures() {
		if g.Location == "Back.php:2" {
			if err := pe.repo.SetStatus(ctx, g.ID, StatusResolved); err != nil {
				t.Fatal(err)
			}
		}
	}
	told := len(pe.alerts.all())
	pe.write(append(repeated(150, mono("CRITICAL", "PDOException", "Often.php", 1)), mono("CRITICAL", "PDOException", "Back.php", 2), mono("CRITICAL", "PDOException", "Fresh.php", 3))...)
	appendTo(t, second, mono("CRITICAL", "RuntimeException", "Second.php", 4)+"\n")
	res := pe.run()
	got := pe.alerts.all()[told:]
	if len(got) != 1 || res.Alerts != 1 {
		t.Fatalf("want one alert, got %d: %+v", len(got), got)
	}
	if got[0].Kind != AlertNew || len(got[0].Items) != 4 {
		t.Fatalf("alert = %+v", got[0])
	}
	want := map[string]AlertKind{"Often.php:1": AlertSpike, "Back.php:2": AlertReopened, "Fresh.php:3": AlertNew, "Second.php:4": AlertNew}
	for _, it := range got[0].Items {
		if it.Kind != want[it.Location] {
			t.Errorf("%s: kind %s, want %s", it.Location, it.Kind, want[it.Location])
		}
	}
	if first := got[0].Items[0]; first.Location != "Often.php:1" || first.Count != 151 {
		t.Errorf("the most frequent comes first, with the count of its hour: %+v", first)
	}
	for _, g := range pe.signatures() {
		if g.LastAlertAt.IsZero() {
			t.Errorf("not marked as told: %+v", g)
		}
	}
}

func TestGroupedAlertKindIsTheFirstPresent(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "Often.php", 1), mono("CRITICAL", "PDOException", "Back.php", 2))
	pe.run()
	for _, g := range pe.signatures() {
		if g.Location == "Back.php:2" {
			if err := pe.repo.SetStatus(context.Background(), g.ID, StatusResolved); err != nil {
				t.Fatal(err)
			}
		}
	}
	told := len(pe.alerts.all())
	pe.write(append(repeated(150, mono("CRITICAL", "PDOException", "Often.php", 1)), mono("CRITICAL", "PDOException", "Back.php", 2))...)
	pe.run()
	if got := pe.alerts.all()[told:]; len(got) != 1 || got[0].Kind != AlertReopened || len(got[0].Items) != 2 {
		t.Fatalf("alerts = %+v", got)
	}
}

func TestSpikeOfAnHourInsideAGapIsIgnored(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	pe.run()
	told := len(pe.alerts.all())
	// Three days off. The day before the return, the error burst; it is over.
	pe.clock.Advance(3 * 24 * time.Hour)
	pe.write(repeated(150, monoAt(pe.clock.Now().Add(-24*time.Hour), "CRITICAL", "PDOException", "Invoice.php", 42))...)
	pe.run()
	if got := pe.alerts.all()[told:]; len(got) != 0 {
		t.Fatalf("an old hour alerted as current: %+v", got)
	}
	if sigs := pe.signatures(); sigs[0].Total != 151 {
		t.Errorf("it is still counted: %+v", sigs[0])
	}
}

func TestSpikeOfTheRunningHourAfterAGapAlerts(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	pe.run()
	pe.clock.Advance(3 * 24 * time.Hour)
	now := pe.clock.Now()
	// An old burst too: the hour still running must not be hidden behind it.
	pe.write(append(repeated(150, monoAt(now.Add(-24*time.Hour), "CRITICAL", "PDOException", "Invoice.php", 42)),
		repeated(120, monoAt(now.Add(-time.Minute), "CRITICAL", "PDOException", "Invoice.php", 42))...)...)
	pe.run()
	got := pe.alerts.ofKind(AlertSpike)
	if len(got) != 1 || got[0].Items[0].Count != 120 {
		t.Fatalf("spike alerts = %+v (all %v)", got, pe.alerts.kinds())
	}
}

func TestSpikeCountIsTheHourThatSpiked(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	pe.run()
	pe.clock.Advance(20 * time.Minute)
	pe.run()
	pe.clock.Advance(20 * time.Minute) // 13:10: no gap
	pe.write(append(repeated(150, mono("CRITICAL", "PDOException", "Invoice.php", 42)),
		monoAt(pe.clock.Now().Add(-5*time.Minute), "CRITICAL", "PDOException", "Invoice.php", 42))...)
	pe.run()
	got := pe.alerts.ofKind(AlertSpike)
	if len(got) != 1 || got[0].Items[0].Count != 151 {
		t.Fatalf("spike alerts = %+v (all %v)", got, pe.alerts.kinds())
	}
}

func TestSpikeCountFailureIsLoggedAndTheAlertStays(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	buf := captureLog(t)
	p := &onePass{d: pe.deps, t: pe.tgt, st: pe.settings(), now: readNow, texts: map[string]string{}, counts: map[string]int64{"sig": 7}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the count cannot be read
	p.queue(ctx, pe.src, nil, nil, []Signature{{ID: "sig", Level: LevelCritical, SpikeHour: readNow.Truncate(time.Hour)}}, time.Time{})
	if len(p.cands) != 1 || p.cands[0].item.Count != 7 {
		t.Fatalf("candidates = %+v", p.cands)
	}
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "sig") {
		t.Errorf("log = %q", buf.String())
	}
}

func TestAuditFailureIsLoggedAndThePassGoesOn(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	pe.write(fmt.Sprintf("[2026-11-02 12:05:00] app.CRITICAL: %s [object] (PDOException(code: 0): x at /var/www/demo/src/Invoice.php:42)", traps[0]))
	buf := captureLog(t)
	renameTable(t, pe.s, "audit_event", "audit_event_off")
	res, err := Pass(context.Background(), pe.deps, pe.tgt.ID)
	renameTable(t, pe.s, "audit_event_off", "audit_event")
	if err != nil || res.Records != 1 || res.Reason != "" {
		t.Fatalf("result %+v, err %v", res, err)
	}
	logged := buf.String()
	if !strings.Contains(logged, "level=WARN") || !strings.Contains(logged, "log.read") || !strings.Contains(logged, pe.tgt.ID) {
		t.Errorf("the lost audit event is not said: %q", logged)
	}
	for _, m := range traps {
		if strings.Contains(logged, m) {
			t.Errorf("the log holds %q: %s", m, logged)
		}
	}
}

func TestAlertSurvivesAFailureAfterApply(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	// The errors get stored, then the positions cannot be saved.
	pe.afterRead(func() { renameTable(t, pe.s, "log_cursor", "log_cursor_off") })
	res, err := Pass(context.Background(), pe.deps, pe.tgt.ID)
	pe.setShell(nil)
	renameTable(t, pe.s, "log_cursor_off", "log_cursor")
	if err == nil || res.Reason != ReasonError {
		t.Fatalf("result %+v, err %v", res, err)
	}
	got := pe.alerts.ofKind(AlertNew)
	if len(got) != 1 || got[0].Items[0].Location != "Invoice.php:42" {
		t.Fatalf("the stored error was not told: %+v", pe.alerts.all())
	}
	if sigs := pe.signatures(); len(sigs) != 1 || sigs[0].LastAlertAt.IsZero() {
		t.Errorf("signatures = %+v", sigs)
	}
}

func TestAlertBookkeepingFailureIsStillAGoodRead(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	buf := captureLog(t)
	// The alert goes, then it cannot be marked as told.
	pe.deps.Alert = func(ctx context.Context, in AlertInput) {
		pe.alerts.add(ctx, in)
		renameTable(t, pe.s, "log_signature", "log_signature_off")
	}
	res, err := Pass(context.Background(), pe.deps, pe.tgt.ID)
	renameTable(t, pe.s, "log_signature_off", "log_signature")
	if err != nil || res.Reason != "" || res.Records != 1 || res.Alerts != 1 {
		t.Fatalf("result %+v, err %v", res, err)
	}
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("not logged: %q", buf.String())
	}
}

func TestResolveFailureIsStillAGoodRead(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.activate()
	buf := captureLog(t)
	pe.afterRead(func() { renameTable(t, pe.s, "log_signature", "log_signature_off") })
	res, err := Pass(context.Background(), pe.deps, pe.tgt.ID)
	pe.setShell(nil)
	renameTable(t, pe.s, "log_signature_off", "log_signature")
	if err != nil || res.Reason != "" {
		t.Fatalf("result %+v, err %v", res, err)
	}
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("not logged: %q", buf.String())
	}
}

func TestVolumeAlertIsHourlyEvenWhenEveryPassIsOverTheCap(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	st := pe.settings()
	st.ReadCap = 2048
	st.Routes[LevelError] = RouteImmediate
	pe.save(st)
	pe.activate()
	big := repeated(60, mono("WARNING", "LogicException", "Warn.php", 1))
	for i := 0; i <= 12; i++ { // every 5 minutes for an hour
		pe.write(big...)
		pe.run()
		pe.clock.Advance(5 * time.Minute)
	}
	if n := len(pe.alerts.ofKind(AlertVolume)); n != 2 {
		t.Fatalf("volume alerts in an hour of reads over the cap: %d, want the first and one an hour later", n)
	}
}

func TestVolumeItemsNameTheirSource(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	st := pe.settings()
	st.ReadCap = 2048
	st.Routes[LevelError] = RouteImmediate
	pe.save(st)
	second := filepath.Join(t.TempDir(), "other.log")
	appendTo(t, second, "")
	src2, err := pe.repo.AddSource(context.Background(), Source{TargetID: pe.tgt.ID, Path: shPath(second), Format: FormatMonolog, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	pe.activate()
	big := repeated(60, mono("WARNING", "LogicException", "Warn.php", 1))
	pe.write(big...)
	appendTo(t, second, strings.Join(big, "\n")+"\n")
	pe.run()
	got := pe.alerts.ofKind(AlertVolume)
	if len(got) != 1 || len(got[0].Items) != 2 {
		t.Fatalf("volume alerts = %+v", got)
	}
	ids := map[string]bool{got[0].Items[0].SourceID: true, got[0].Items[1].SourceID: true}
	if !ids[pe.src.ID] || !ids[src2.ID] {
		t.Errorf("items = %+v, sources %s and %s", got[0].Items, pe.src.ID, src2.ID)
	}
	for _, it := range got[0].Items {
		if strings.Contains(it.SourceID+it.Type+it.Location, "/") {
			t.Errorf("a server path reached an alert: %+v", it)
		}
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

// answer makes a simulated server that gives these lines back, whatever the
// filter asks: what a real server says when it cannot open its files, on any
// machine the tests run on.
func answer(lines ...string) sshtest.ShellFunc {
	return func(_ *sshtest.Server, _ string, out, _ io.Writer) int {
		io.WriteString(out, strings.Join(lines, "\n")+"\n")
		return 0
	}
}

func unseenLine(file, cause string) string { return "U\t" + file + "\t" + cause }

// locatedLine is what an activation says of a file it found, readable or not.
func locatedLine(file string) string { return "F\t" + file + "\t123\t0\t0\t0\t1" }

// readLineOf is what a read says of a file it opened and found nothing new in.
func readLineOf(file string) string { return "F\t" + file + "\t123\t0\t0\t0\t0" }

// A source of which no file could be read has failed its read, whatever the
// position saved: the cause is told, and all the rest is saved as for a read.
func TestPassFailsWhenNoFileCouldBeRead(t *testing.T) {
	for _, tc := range []struct{ cause, reason string }{
		{CauseDenied, ReasonDenied},
		{CauseTools, ReasonTools},
		{CauseOther, ReasonError},
	} {
		t.Run(tc.cause, func(t *testing.T) {
			pe := newPassEnv(t, target.EnvProd, FormatMonolog)
			pe.activate()
			ctx := context.Background()
			before, _ := pe.repo.Cursors(ctx, pe.src.ID)
			pe.clock.Advance(5 * time.Minute)
			pe.setShell(answer(unseenLine(pe.src.Path, tc.cause)))
			res, err := Pass(ctx, pe.deps, pe.tgt.ID)
			if !errors.Is(err, ErrReadFailed) || res.Reason != tc.reason || res.Unseen != 1 {
				t.Fatalf("result %+v, err %v", res, err)
			}
			if strings.Contains(err.Error(), pe.src.Path) {
				t.Errorf("the error names the file: %v", err)
			}
			after, _ := pe.repo.Cursors(ctx, pe.src.ID)
			if len(after) != 1 || after[0].Offset != before[0].Offset || !after[0].ReadAt.Equal(before[0].ReadAt) {
				t.Errorf("positions: %+v -> %+v", before, after)
			}
			if notes := pe.notes(NoteUnseen); len(notes) != 1 {
				t.Errorf("unseen notes = %+v", notes)
			}
			unseen, err := pe.repo.Unseen(ctx, pe.tgt.ID)
			if err != nil || len(unseen[pe.src.ID]) != 1 || unseen[pe.src.ID][0].Cause != tc.cause {
				t.Errorf("unseen rows = %+v, %v", unseen, err)
			}
			var result, ev string
			if err := pe.s.DB().QueryRow(`SELECT result, evidence FROM audit_event WHERE action = 'log.read' ORDER BY id DESC LIMIT 1`).Scan(&result, &ev); err != nil ||
				result != "failed" || !strings.Contains(ev, `"reason":"`+tc.reason+`"`) || strings.Contains(ev, pe.src.Path) {
				t.Errorf("audit = %q %s (%v)", result, ev, err)
			}
		})
	}
}

// At activation an unreadable file is located by its metadata: it comes with an
// F line as well as its U line, and still nothing could be read.
func TestPassFailsWhenTheOnlyFileIsLocatedButUnreadable(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	ctx := context.Background()
	pe.setShell(answer(locatedLine(pe.src.Path), unseenLine(pe.src.Path, CauseDenied)))
	res, err := Pass(ctx, pe.deps, pe.tgt.ID)
	if !errors.Is(err, ErrSourceDenied) || res.Reason != ReasonDenied {
		t.Fatalf("result %+v, err %v", res, err)
	}
	// The place in the file is kept, with no read date, as before.
	cs, _ := pe.repo.Cursors(ctx, pe.src.ID)
	if len(cs) != 1 || cs[0].FileID != "123" || !cs[0].ReadAt.IsZero() {
		t.Errorf("positions = %+v", cs)
	}
	if unseen, err := pe.repo.Unseen(ctx, pe.tgt.ID); err != nil || len(unseen[pe.src.ID]) != 1 {
		t.Errorf("unseen rows = %+v, %v", unseen, err)
	}
}

// The real filter on a file this user cannot read, at activation and after it.
func TestPassFailsOnARealDeniedFile(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	denyRead(t, pe.file)
	for i := 0; i < 2; i++ {
		res, err := Pass(context.Background(), pe.deps, pe.tgt.ID)
		if !errors.Is(err, ErrSourceDenied) || res.Reason != ReasonDenied || res.Records != 0 {
			t.Fatalf("pass %d: result %+v, err %v", i, res, err)
		}
	}
}

// A pattern with one file read and others not is a read that worked, with its
// note: what could be read was read.
func TestPassWithAFileReadStaysGood(t *testing.T) {
	cases := map[string]func(a, b string) []string{
		"after the activation": func(a, b string) []string { return []string{readLineOf(a), unseenLine(b, CauseDenied)} },
		"at the activation": func(a, b string) []string {
			return []string{locatedLine(a), locatedLine(b), unseenLine(b, CauseDenied)}
		},
	}
	for name, lines := range cases {
		t.Run(name, func(t *testing.T) {
			pe := newPassEnv(t, target.EnvProd, FormatMonolog)
			dir := pe.src.Path[:strings.LastIndex(pe.src.Path, "/")]
			pe.src.Path = dir + "/*.log"
			if err := pe.repo.UpdateSource(context.Background(), pe.src); err != nil {
				t.Fatal(err)
			}
			pe.setShell(answer(lines(dir+"/a.log", dir+"/b.log")...))
			res := pe.run()
			if res.Unseen != 1 {
				t.Errorf("result %+v", res)
			}
			if notes := pe.notes(NoteUnseen); len(notes) != 1 {
				t.Errorf("unseen notes = %+v", notes)
			}
		})
	}
}

// Nothing there is a wait, not a failure: an absent file, nothing found at the
// activation. A link or a folder in place of the file is told on the sheet.
func TestPassWithNothingToOpenStaysGood(t *testing.T) {
	for _, cause := range []string{CauseAbsent, CauseLink, CauseNotFile} {
		t.Run(cause, func(t *testing.T) {
			pe := newPassEnv(t, target.EnvProd, FormatMonolog)
			pe.setShell(answer(unseenLine(pe.src.Path, cause)))
			pe.run()
		})
	}
	t.Run("nothing found", func(t *testing.T) {
		pe := newPassEnv(t, target.EnvProd, FormatMonolog)
		pe.setShell(answer("N"))
		pe.run()
	})
}

// Several causes for a source that read nothing: refused rights say the most.
func TestPassReasonOfMixedCauses(t *testing.T) {
	for _, tc := range []struct {
		causes []string
		reason string
	}{
		{[]string{CauseAbsent, CauseDenied}, ReasonDenied},
		{[]string{CauseOther, CauseDenied}, ReasonDenied},
		{[]string{CauseOther, CauseTools}, ReasonTools},
		{[]string{CauseLink, CauseOther}, ReasonError},
	} {
		t.Run(strings.Join(tc.causes, "+"), func(t *testing.T) {
			pe := newPassEnv(t, target.EnvProd, FormatMonolog)
			dir := pe.src.Path[:strings.LastIndex(pe.src.Path, "/")]
			pe.src.Path = dir + "/*.log"
			if err := pe.repo.UpdateSource(context.Background(), pe.src); err != nil {
				t.Fatal(err)
			}
			pe.setShell(answer(unseenLine(dir+"/a.log", tc.causes[0]), unseenLine(dir+"/b.log", tc.causes[1])))
			res, err := Pass(context.Background(), pe.deps, pe.tgt.ID)
			if !errors.Is(err, ErrReadFailed) || res.Reason != tc.reason {
				t.Fatalf("result %+v, err %v", res, err)
			}
		})
	}
}

// twoSources adds a second source on its own file, whose reads the simulated
// server refuses while deny is true. The other source is read for real.
func twoSources(t *testing.T, pe *passEnv, deny *atomic.Bool) (Source, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "other.log")
	appendTo(t, file, "")
	src, err := pe.repo.AddSource(context.Background(), Source{TargetID: pe.tgt.ID, Path: shPath(file), Format: FormatMonolog, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	real := pe.host.realShell(os.Environ())
	pe.setShell(func(s *sshtest.Server, script string, out, errw io.Writer) int {
		if deny.Load() && strings.Contains(script, src.Path) {
			return answer(unseenLine(src.Path, CauseDenied))(s, script, out, errw)
		}
		return real(s, script, out, errw)
	})
	return src, file
}

// One source that fails does not make the others unread: the pass says which
// failed, and why, and that the others were read.
func TestPassNamesTheSourcesThatFailed(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	var deny atomic.Bool
	src2, _ := twoSources(t, pe, &deny)
	pe.activate()
	deny.Store(true)
	res, err := Pass(context.Background(), pe.deps, pe.tgt.ID)
	if err == nil {
		t.Fatal("a source failed and the pass did not")
	}
	if res.Read != 1 || len(res.Failed) != 1 || res.Failed[0] != (FailedSource{Label: src2.Path, Reason: ReasonDenied}) {
		t.Errorf("result %+v", res)
	}
	deny.Store(false)
	res = pe.run()
	if res.Read != 2 || len(res.Failed) != 0 {
		t.Errorf("after the rights came back: %+v", res)
	}
}

// A connection that fails has tried no source: none is named, none was read.
func TestPassFailedConnectionNamesNoSource(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	pe.deps.SSH.Agent = func() (agent.ExtendedAgent, io.Closer, error) { return nil, nil, sshx.ErrNoAgent }
	res, err := Pass(context.Background(), pe.deps, pe.tgt.ID)
	if err == nil || res.Read != 0 || len(res.Failed) != 0 {
		t.Fatalf("result %+v, err %v", res, err)
	}
}

// A source that fails keeps its errors as they are, but the others of the server
// are resolved all the same, so that an error of theirs that returns is told as
// back. A source not read in the pass resolves nothing.
func TestResolveGoesPerSource(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	ctx := context.Background()
	var deny atomic.Bool
	src2, file2 := twoSources(t, pe, &deny)
	off, err := pe.repo.AddSource(ctx, Source{TargetID: pe.tgt.ID, Path: "/var/log/demo/off.log", Format: FormatMonolog, Active: false})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := pe.repo.Apply(ctx, off, []Record{rec(1, readNow)}, readNow); err != nil {
		t.Fatal(err)
	}
	pe.activate()
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	appendTo(t, file2, mono("CRITICAL", "PDOException", "Invoice.php", 42)+"\n")
	pe.run()
	status := func() map[string]Status {
		out := map[string]Status{}
		for _, g := range pe.signatures() {
			out[g.SourceID] = g.Status
		}
		return out
	}
	if got := status(); len(got) != 3 {
		t.Fatalf("signatures = %v", got)
	}
	// Eight days on, the second source cannot be read.
	pe.clock.Advance(8 * 24 * time.Hour)
	deny.Store(true)
	if _, err := Pass(ctx, pe.deps, pe.tgt.ID); err == nil {
		t.Fatal("the pass did not fail")
	}
	got := status()
	if got[pe.src.ID] != StatusResolved {
		t.Errorf("the source read: status = %s", got[pe.src.ID])
	}
	if got[src2.ID] == StatusResolved {
		t.Error("the source that failed was resolved: it was not seen")
	}
	if got[off.ID] == StatusResolved {
		t.Error("a source not read was resolved")
	}
	// The error of the source read comes back while the other still fails: told.
	pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
	pe.clock.Advance(time.Minute)
	if _, err := Pass(ctx, pe.deps, pe.tgt.ID); err == nil {
		t.Fatal("the pass did not fail")
	}
	if told := pe.alerts.ofKind(AlertReopened); len(told) != 1 {
		t.Errorf("alerts = %v", pe.alerts.kinds())
	}
	// The other one is read again: nothing was lost, its errors resolve now.
	deny.Store(false)
	pe.clock.Advance(8 * 24 * time.Hour)
	pe.run()
	if got := status(); got[src2.ID] != StatusResolved {
		t.Errorf("after the read: status = %s", got[src2.ID])
	}
}

// A server where nothing listens is a refused connection, told as such; the
// cause of a timeout of the connection is the timeout one. Anything else stays
// the general cause.
func TestPassReportsARefusedConnection(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	tg := pe.tgt
	tg.Port = port
	if err := pe.targets.Update(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	res, err := Pass(context.Background(), pe.deps, pe.tgt.ID)
	if err == nil || res.Reason != ReasonRefused || res.Read != 0 {
		t.Fatalf("result %+v, err %v", res, err)
	}
}

func TestReasonOfTellsTheNetworkApart(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("x: %w", sshx.ErrConnectionRefused), ReasonRefused},
		{fmt.Errorf("x: %w", sshx.ErrConnectTimeout), ReasonTimeout},
		{fmt.Errorf("x: %w", sshx.ErrNoKeyAccepted), ReasonNoKeyAccepted},
		{errors.New("ssh: handshake failed: EOF"), ReasonError},
	} {
		if got := reasonOf(tc.err); got != tc.want {
			t.Errorf("reasonOf(%v) = %s, want %s", tc.err, got, tc.want)
		}
	}
}

// byPath makes a simulated server that answers each source by its own lines.
func byPath(lines map[string][]string) sshtest.ShellFunc {
	return func(_ *sshtest.Server, script string, out, _ io.Writer) int {
		for path, ls := range lines {
			if strings.Contains(script, path) {
				io.WriteString(out, strings.Join(ls, "\n")+"\n")
				return 0
			}
		}
		return 1
	}
}

// A source whose file is gone (or a link, a folder) was not read: it is no
// "read" source for the alert, and its errors are not closed.
func TestAbsentSourceIsNotReadAndResolvesNothing(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	ctx := context.Background()
	var deny atomic.Bool
	src2, _ := twoSources(t, pe, &deny)
	if _, _, _, err := pe.repo.Apply(ctx, src2, []Record{rec(1, readNow)}, readNow); err != nil {
		t.Fatal(err)
	}
	pe.activate()
	pe.clock.Advance(8 * 24 * time.Hour)
	pe.setShell(byPath(map[string][]string{
		pe.src.Path: {unseenLine(pe.src.Path, CauseDenied)},
		src2.Path:   {unseenLine(src2.Path, CauseAbsent)},
	}))
	res, err := Pass(ctx, pe.deps, pe.tgt.ID)
	if err == nil || res.Read != 0 || len(res.Failed) != 1 {
		t.Fatalf("result %+v, err %v", res, err)
	}
	for _, g := range pe.signatures() {
		if g.SourceID == src2.ID && g.Status == StatusResolved {
			t.Error("the error of a source that was not read was closed")
		}
	}
}

// A source read in part (a file refused, the list cut, the cap reached) closes
// nothing: an error held only by what was not read is not gone.
func TestPartialReadResolvesNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		lines    func(a, b string) []string
		resolved bool
	}{
		"whole":        {func(a, b string) []string { return []string{readLineOf(a)} }, true},
		"file refused": {func(a, b string) []string { return []string{readLineOf(a), unseenLine(b, CauseDenied)} }, false},
		"file absent":  {func(a, b string) []string { return []string{readLineOf(a), unseenLine(b, CauseAbsent)} }, true},
		"list cut":     {func(a, b string) []string { return []string{readLineOf(a), "M"} }, false},
		"cap reached":  {func(a, b string) []string { return []string{"F\t" + a + "\t123\t0\t5\t0\t0"} }, false},
	} {
		t.Run(name, func(t *testing.T) {
			pe := newPassEnv(t, target.EnvProd, FormatMonolog)
			dir := pe.src.Path[:strings.LastIndex(pe.src.Path, "/")]
			pe.src.Path = dir + "/*.log"
			if err := pe.repo.UpdateSource(context.Background(), pe.src); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := pe.repo.Apply(context.Background(), pe.src, []Record{rec(1, readNow)}, readNow); err != nil {
				t.Fatal(err)
			}
			pe.clock.Advance(8 * 24 * time.Hour)
			pe.setShell(answer(tc.lines(dir+"/a.log", dir+"/b.log")...))
			pe.run()
			if got := pe.signatures()[0].Status == StatusResolved; got != tc.resolved {
				t.Errorf("resolved = %v, want %v", got, tc.resolved)
			}
		})
	}
}
