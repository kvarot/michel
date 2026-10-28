package digest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/store"
)

var now = time.Date(2026, 10, 23, 6, 30, 0, 0, time.UTC)

type fixture struct {
	t    *testing.T
	st   *store.Store
	proj project.Project
	n    int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &fixture{t: t, st: st}
	f.proj = f.addProject("demo", project.Project{})
	return f
}

func (f *fixture) addProject(name string, p project.Project) project.Project {
	f.t.Helper()
	p.Name, p.Path = name, f.t.TempDir()
	p, err := project.NewRepo(f.st).Add(context.Background(), p)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// finding is one seeded finding row.
type finding struct {
	project, pkg, osv, severity, status string
	firstSeen, changed                  time.Time
	installed                           string
	fixed                               []string
}

// seed inserts fi and returns its id.
func (f *fixture) seed(fi finding) string {
	f.t.Helper()
	f.n++
	id := fmt.Sprintf("F%03d", f.n)
	if fi.project == "" {
		fi.project = f.proj.ID
	}
	if fi.status == "" {
		fi.status = "new"
	}
	if fi.installed == "" {
		fi.installed = "1.0.0"
	}
	if fi.changed.IsZero() {
		fi.changed = fi.firstSeen
	}
	if fi.fixed == nil {
		fi.fixed = []string{"1.2.5"}
	}
	eco := "Packagist"
	if !strings.Contains(fi.pkg, "/") {
		eco = "npm"
	}
	fx, _ := json.Marshal(fi.fixed)
	if _, err := f.st.DB().Exec(`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, severity_label,
		installed_version, fixed_versions, status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, status_changed_at, summary)
		VALUES (?, ?, 'composer.lock', ?, ?, ?, ?, ?, ?, ?, 's1', 's1', ?, ?, ?, 'Remote code execution')`,
		id, fi.project, eco, fi.pkg, fi.osv, fi.severity, fi.installed, string(fx), fi.status,
		ts(fi.firstSeen), ts(fi.firstSeen), ts(fi.changed)); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// decision is one seeded decision row.
type decision struct {
	finding, action, reason string
	created, due, superAt   time.Time
}

func (f *fixture) decide(d decision) {
	f.t.Helper()
	f.n++
	due, sup := "", ""
	if !d.due.IsZero() {
		due = ts(d.due)
	}
	if !d.superAt.IsZero() {
		sup = ts(d.superAt)
	}
	if d.created.IsZero() {
		d.created = now.Add(-30 * 24 * time.Hour)
	}
	var projectID string
	if err := f.st.DB().QueryRow(`SELECT project_id FROM finding WHERE id = ?`, d.finding).Scan(&projectID); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.st.DB().Exec(`INSERT INTO decision (id, finding_id, project_id, action, justification, due_at, author, created_at,
		seen_severity, seen_fixed_versions, superseded_at, superseded_reason) VALUES (?,?,?,?,'dev only',?,'cli',?,'high','[]',?,?)`,
		fmt.Sprintf("D%03d", f.n), d.finding, projectID, d.action, due, ts(d.created), sup, d.reason); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) scanRow(projectID, status string, started time.Time) {
	f.t.Helper()
	f.n++
	if _, err := f.st.DB().Exec(`INSERT INTO scan (id, project_id, started_at, status) VALUES (?,?,?,?)`,
		fmt.Sprintf("S%03d", f.n), projectID, ts(started), status); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) compute(lang i18n.Lang, opt Options) Digest {
	f.t.Helper()
	d, err := Compute(context.Background(), f.st, now, lang, opt)
	if err != nil {
		f.t.Fatal(err)
	}
	return d
}

func projectNamed(t *testing.T, d Digest, name string) ProjectDigest {
	t.Helper()
	for _, p := range d.Projects {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("project %s missing from %+v", name, d.Projects)
	return ProjectDigest{}
}

func TestComputeWindowFromLastRunOrDay(t *testing.T) {
	f := newFixture(t)
	f.seed(finding{pkg: "acme/lib", osv: "ACME-1", severity: "low", firstSeen: now.Add(-10 * 24 * time.Hour)})
	d := f.compute(i18n.EN, Options{})
	if !d.Since.Equal(now.Add(-24*time.Hour)) || !d.Until.Equal(now) || d.SinceLabel != "" {
		t.Errorf("without run: since %v until %v label %q", d.Since, d.Until, d.SinceLabel)
	}
	if p := projectNamed(t, d, "demo"); len(p.New) != 0 {
		t.Errorf("a finding older than the window is new: %+v", p.New)
	}
	old := now.Add(-20 * 24 * time.Hour)
	if err := NewRepo(f.st).Save(context.Background(), Run{Since: old.Add(-24 * time.Hour), Until: old, Lang: i18n.EN, CreatedAt: old}); err != nil {
		t.Fatal(err)
	}
	d = f.compute(i18n.EN, Options{})
	if !d.Since.Equal(old) || !strings.Contains(d.SinceLabel, "2026-10-03") {
		t.Errorf("after a run 20 days ago: since %v label %q", d.Since, d.SinceLabel)
	}
	if p := projectNamed(t, d, "demo"); len(p.New) != 1 || d.NewTotal != 1 {
		t.Errorf("nothing is lost after a long absence: %+v", p.New)
	}
	fr := f.compute(i18n.FR, Options{})
	if !strings.Contains(fr.SinceLabel, "depuis le 03/10") {
		t.Errorf("fr label %q", fr.SinceLabel)
	}
	given := now.Add(-30 * time.Hour)
	if d := f.compute(i18n.EN, Options{Since: given}); !d.Since.Equal(given) || d.SinceLabel != "" {
		t.Errorf("--since: %v %q", d.Since, d.SinceLabel)
	}
}

// dbDigest fingerprints every row of the tables Compute must not touch.
func dbDigest(t *testing.T, st *store.Store) string {
	t.Helper()
	h := sha256.New()
	for _, q := range []string{
		`SELECT id || '|' || status || '|' || status_changed_at || '|' || severity_label || '|' || first_seen_at FROM finding ORDER BY id`,
		`SELECT id || '|' || action || '|' || due_at || '|' || superseded_at || '|' || superseded_reason FROM decision ORDER BY id`,
		`SELECT id || '|' || action || '|' || hash FROM audit_event ORDER BY id`,
		`SELECT id || '|' || status FROM scan ORDER BY id`,
		`SELECT id FROM digest_run ORDER BY id`,
	} {
		rows, err := st.DB().Query(q)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintln(h, s)
			n++
		}
		rows.Close()
		fmt.Fprintf(h, "count %d\n", n)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestComputeIsPure(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	overdue := f.seed(finding{pkg: "acme/lib", osv: "ACME-1", severity: "high", status: "decided", firstSeen: now.Add(-5 * 24 * time.Hour)})
	f.decide(decision{finding: overdue, action: "defer", due: now.Add(-time.Hour)})
	f.seed(finding{pkg: "vuln-pkg", osv: "ACME-2", severity: "critical", firstSeen: now.Add(-time.Hour)})
	// A scan left running for hours: only the CLI sweeps it.
	f.scanRow(f.proj.ID, "running", now.Add(-5*time.Hour))
	log := audit.NewLogger(f.st, func() time.Time { return now })
	if _, err := log.Record(ctx, audit.Event{Actor: "test", Action: "test.seed", Result: "ok"}); err != nil {
		t.Fatal(err)
	}
	before := dbDigest(t, f.st)
	for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
		d := f.compute(lang, Options{})
		if p := projectNamed(t, d, "demo"); len(p.Due) != 1 || !p.Due[0].Overdue {
			t.Errorf("overdue deferral not listed: %+v", p.Due)
		}
	}
	if after := dbDigest(t, f.st); after != before {
		t.Error("Compute wrote to the store")
	}
}

func TestComputeNewAndGoneByPackage(t *testing.T) {
	f := newFixture(t)
	recent := now.Add(-2 * time.Hour)
	a := f.seed(finding{pkg: "acme/lib", osv: "ACME-2026-0002", severity: "medium", firstSeen: recent, fixed: []string{"1.3.0"}})
	b := f.seed(finding{pkg: "acme/lib", osv: "ACME-2026-0001", severity: "high", firstSeen: recent, fixed: []string{"1.2.5"}})
	f.seed(finding{pkg: "acme/old", osv: "ACME-2026-0009", severity: "critical", status: "pending", firstSeen: now.Add(-9 * 24 * time.Hour)})
	f.seed(finding{pkg: "vuln-pkg", osv: "ACME-2026-0101", severity: "low", firstSeen: recent})
	// New in the window but already gone: listed as gone only.
	g := f.seed(finding{pkg: "acme/gone", osv: "ACME-2026-0003", severity: "high", status: "gone", firstSeen: recent, changed: now.Add(-time.Hour)})
	f.seed(finding{pkg: "acme/longgone", osv: "ACME-2026-0004", severity: "high", status: "gone",
		firstSeen: now.Add(-9 * 24 * time.Hour), changed: now.Add(-3 * 24 * time.Hour)})

	d := f.compute(i18n.EN, Options{})
	p := projectNamed(t, d, "demo")
	if len(p.New) != 2 {
		t.Fatalf("new = %+v", p.New)
	}
	lib := p.New[0]
	if lib.Name != "acme/lib" || lib.Ecosystem != "Packagist" || lib.WorstSeverity != "high" || len(lib.OSVIDs) != 2 ||
		lib.OSVIDs[0] != "ACME-2026-0001" || len(lib.FindingIDs) != 2 || lib.FindingIDs[0] != b || lib.FindingIDs[1] != a ||
		lib.Installed != "1.0.0" || lib.Target != "1.2.5" || !strings.Contains(lib.What, "acme/lib") {
		t.Errorf("acme/lib = %+v", lib)
	}
	if p.New[1].Name != "vuln-pkg" || p.New[1].WorstSeverity != "low" {
		t.Errorf("second package = %+v", p.New[1])
	}
	if len(p.Gone) != 1 || p.Gone[0].Name != "acme/gone" || p.Gone[0].FindingIDs[0] != g {
		t.Errorf("gone = %+v", p.Gone)
	}
	if d.NewTotal != 3 || d.AttentionTotal != 1 {
		t.Errorf("new %d attention %d", d.NewTotal, d.AttentionTotal)
	}
	if p.Open["critical"] != 1 || p.Open["high"] != 1 || p.Open["medium"] != 1 || p.Open["low"] != 1 || p.Total != 4 || p.CriticalOpen != 1 {
		t.Errorf("counters open %v total %d critical %d", p.Open, p.Total, p.CriticalOpen)
	}
	if len(p.ProvenFixed) != 0 || len(p.ReportedFixed) != 0 {
		t.Errorf("plan 3 has no proven or reported fixes: %+v", p)
	}
	fr := projectNamed(t, f.compute(i18n.FR, Options{}), "demo")
	if fr.New[0].What == lib.What || !strings.Contains(fr.New[0].What, "acme/lib") {
		t.Errorf("the what sentence is not in French: %q", fr.New[0].What)
	}
}

func TestDigestListsSupersededDecisions(t *testing.T) {
	f := newFixture(t)
	old := now.Add(-9 * 24 * time.Hour)
	changed := f.seed(finding{pkg: "acme/lib", osv: "ACME-1", severity: "critical", status: "pending", firstSeen: old})
	redecided := f.seed(finding{pkg: "acme/other", osv: "ACME-2", severity: "high", status: "decided", firstSeen: old})
	before := f.seed(finding{pkg: "acme/third", osv: "ACME-3", severity: "high", status: "pending", firstSeen: old})
	f.decide(decision{finding: changed, action: "defer", due: now.Add(10 * 24 * time.Hour), superAt: now.Add(-time.Hour), reason: "severity_changed"})
	f.decide(decision{finding: redecided, action: "defer", due: now.Add(10 * 24 * time.Hour), superAt: now.Add(-time.Hour), reason: "redecided"})
	f.decide(decision{finding: redecided, action: "ignore", created: now.Add(-time.Hour)})
	f.decide(decision{finding: before, action: "fix", superAt: now.Add(-3 * 24 * time.Hour), reason: "fixed_version_changed"})

	for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
		d := f.compute(lang, Options{})
		p := projectNamed(t, d, "demo")
		if len(p.Superseded) != 1 {
			t.Fatalf("%s: superseded = %+v", lang, p.Superseded)
		}
		s := p.Superseded[0]
		if s.Package != "acme/lib" || s.OSVID != "ACME-1" || s.FindingID != changed || s.PreviousAction != "defer" ||
			s.Reason != "severity_changed" || s.Justification != "dev only" {
			t.Errorf("%s: superseded = %+v", lang, s)
		}
		if d.AttentionTotal != 1 || p.Decided["ignore"] != 1 || p.Total != 3 {
			t.Errorf("%s: attention %d decided %v total %d", lang, d.AttentionTotal, p.Decided, p.Total)
		}
		text, err := RenderText(d)
		if err != nil {
			t.Fatal(err)
		}
		want := map[i18n.Lang]string{i18n.EN: "acme/lib ACME-1: was deferred, the severity changed",
			i18n.FR: "acme/lib ACME-1 : était reportée, la gravité a changé"}[lang]
		if !strings.Contains(text, want) || strings.Contains(text, "ACME-2") || strings.Contains(text, "ACME-3") {
			t.Errorf("%s text lacks %q:\n%s", lang, want, text)
		}
	}
}

func TestComputeListsDueHorizon(t *testing.T) {
	f := newFixture(t)
	old := now.Add(-40 * 24 * time.Hour)
	overdue := f.seed(finding{pkg: "acme/a", osv: "ACME-1", severity: "high", status: "decided", firstSeen: old})
	soon := f.seed(finding{pkg: "acme/b", osv: "ACME-2", severity: "low", status: "decided", firstSeen: old})
	later := f.seed(finding{pkg: "acme/c", osv: "ACME-3", severity: "low", status: "decided", firstSeen: old})
	f.decide(decision{finding: overdue, action: "defer", due: now.Add(-time.Hour)})
	f.decide(decision{finding: soon, action: "defer", due: now.Add(2 * 24 * time.Hour)})
	f.decide(decision{finding: later, action: "defer", due: now.Add(10 * 24 * time.Hour)})
	d := f.compute(i18n.EN, Options{})
	p := projectNamed(t, d, "demo")
	if len(p.Due) != 2 || p.Due[0].FindingID != overdue || !p.Due[0].Overdue || p.Due[0].Package != "acme/a" ||
		p.Due[1].FindingID != soon || p.Due[1].Overdue || p.Due[1].DueAt != ts(now.Add(2*24*time.Hour)) {
		t.Errorf("due = %+v", p.Due)
	}
	if d.AttentionTotal != 2 || p.Decided["defer"] != 3 || p.Open["high"] != 1 || p.Open["low"] != 2 {
		t.Errorf("attention %d decided %v open %v", d.AttentionTotal, p.Decided, p.Open)
	}
	var status string
	if err := f.st.DB().QueryRow(`SELECT status FROM finding WHERE id = ?`, overdue).Scan(&status); err != nil || status != "decided" {
		t.Errorf("status = %s %v", status, err)
	}
	text, err := RenderText(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "acme/a ACME-1: deferred until 2026-10-23 (overdue)") ||
		!strings.Contains(text, "acme/b ACME-2: deferred until 2026-10-25\n") || strings.Contains(text, "acme/c") {
		t.Errorf("text:\n%s", text)
	}
}

func TestDaysWithoutCritical(t *testing.T) {
	f := newFixture(t)
	// The most recent critical counts, whatever its status.
	f.seed(finding{pkg: "acme/a", osv: "ACME-1", severity: "critical", status: "gone", firstSeen: now.Add(-9 * 24 * time.Hour)})
	f.seed(finding{pkg: "acme/b", osv: "ACME-2", severity: "critical", status: "gone", firstSeen: now.Add(-5*24*time.Hour - time.Hour)})
	f.seed(finding{pkg: "acme/c", osv: "ACME-3", severity: "high", firstSeen: now.Add(-time.Hour)})
	f.scanRow(f.proj.ID, "ok", now.Add(-30*24*time.Hour))
	f.scanRow(f.proj.ID, "partial", now.Add(-2*time.Hour))
	clean := f.addProject("project-a", project.Project{})
	f.scanRow(clean.ID, "ok", now.Add(-12*24*time.Hour-time.Hour))
	f.scanRow(clean.ID, "failed", now.Add(-time.Hour))
	f.addProject("project-b", project.Project{})

	d := f.compute(i18n.EN, Options{})
	demo, a, never := projectNamed(t, d, "demo"), projectNamed(t, d, "project-a"), projectNamed(t, d, "project-b")
	if demo.DaysWithoutCritical != 5 || demo.CriticalOpen != 0 || demo.LastScanStatus != "partial" {
		t.Errorf("demo = %d days, %d critical, %s", demo.DaysWithoutCritical, demo.CriticalOpen, demo.LastScanStatus)
	}
	if a.DaysWithoutCritical != 12 || a.LastScanStatus != "failed" {
		t.Errorf("project-a = %d days, %s", a.DaysWithoutCritical, a.LastScanStatus)
	}
	if never.DaysWithoutCritical != 0 || never.LastScanStatus != "never" {
		t.Errorf("never scanned = %d days, %s", never.DaysWithoutCritical, never.LastScanStatus)
	}
	if d.FailedScans != 1 {
		t.Errorf("failed scans = %d", d.FailedScans)
	}
	text, err := RenderText(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "5 days without a new critical") || !strings.Contains(text, "0 critical open") {
		t.Errorf("text:\n%s", text)
	}
}

func TestTitleAndWordFrenchAndEnglish(t *testing.T) {
	f := newFixture(t)
	empty := f.compute(i18n.EN, Options{})
	if empty.Title != "Michel found nothing new since the last digest" || empty.Word != "All quiet. Keep it that way." {
		t.Errorf("en clean: %q / %q", empty.Title, empty.Word)
	}
	emptyFR := f.compute(i18n.FR, Options{Assistant: "Ada"})
	if emptyFR.Title != "Ada n'a rien trouvé de nouveau depuis le dernier résumé" || emptyFR.Word != "Tout est calme. Garde ça comme ça." {
		t.Errorf("fr clean: %q / %q", emptyFR.Title, emptyFR.Word)
	}
	recent := now.Add(-time.Hour)
	f.seed(finding{pkg: "acme/a", osv: "ACME-1", severity: "high", firstSeen: recent})
	f.seed(finding{pkg: "acme/b", osv: "ACME-2", severity: "low", firstSeen: recent})
	f.seed(finding{pkg: "acme/b", osv: "ACME-3", severity: "medium", firstSeen: recent})
	en, fr := f.compute(i18n.EN, Options{}), f.compute(i18n.FR, Options{})
	if en.Title != "Michel found 3 new findings since the last digest, 1 needs your attention" || en.Word != "" || en.Assistant != "Michel" {
		t.Errorf("en: %q / %q / %q", en.Title, en.Word, en.Assistant)
	}
	if fr.Title != "Michel a trouvé 3 nouveautés depuis le dernier résumé, 1 mérite ton attention" || fr.Word != "" {
		t.Errorf("fr: %q / %q", fr.Title, fr.Word)
	}
	c := f.seed(finding{pkg: "acme/c", osv: "ACME-4", severity: "critical", status: "decided", firstSeen: now.Add(-9 * 24 * time.Hour)})
	f.decide(decision{finding: c, action: "defer", due: now.Add(time.Hour)})
	en = f.compute(i18n.EN, Options{Since: now.Add(-time.Minute)})
	if en.Title != "Michel found nothing new since the last digest, 1 needs your attention" || en.Word != "" {
		t.Errorf("en due only: %q / %q", en.Title, en.Word)
	}
}

func TestDigestCountsEmptyApartFromFailed(t *testing.T) {
	f := newFixture(t)
	empty := f.addProject("acme-empty", project.Project{})
	broken := f.addProject("acme-broken", project.Project{})
	f.scanRow(empty.ID, "empty", now.Add(-time.Hour))
	f.scanRow(broken.ID, "failed", now.Add(-time.Hour))
	ctx := context.Background()
	compute := func(at time.Time) Digest {
		t.Helper()
		d, err := Compute(ctx, f.st, at, i18n.FR, Options{})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := compute(now)
	if d.FailedScans != 1 || d.EmptyProjects != 1 || !d.ShowEmpty {
		t.Fatalf("first digest: failed %d empty %d show %t", d.FailedScans, d.EmptyProjects, d.ShowEmpty)
	}
	if p := projectNamed(t, d, "acme-empty"); p.LastScanStatus != "empty" {
		t.Errorf("status %q", p.LastScanStatus)
	}
	txt, err := RenderText(d)
	if err != nil {
		t.Fatal(err)
	}
	if want := i18n.N(i18n.FR, "digest.empty_projects", 1); !strings.Contains(txt, want) {
		t.Errorf("text lacks %q:\n%s", want, txt)
	}
	run := RunOf(d, now)
	if run.Summary["empty_projects"] != 1 {
		t.Errorf("summary %v", run.Summary)
	}
	if err := NewRepo(f.st).Save(ctx, run); err != nil {
		t.Fatal(err)
	}
	// Same count within the week: no daily noise.
	d = compute(now.Add(24 * time.Hour))
	if d.EmptyProjects != 1 || d.ShowEmpty {
		t.Fatalf("second digest: empty %d show %t", d.EmptyProjects, d.ShowEmpty)
	}
	if txt, _ := RenderText(d); strings.Contains(txt, i18n.N(i18n.FR, "digest.empty_projects", 1)) {
		t.Errorf("sentence shown again:\n%s", txt)
	}
	if err := NewRepo(f.st).Save(ctx, RunOf(d, now.Add(24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	// A week after it was last shown, it comes back once.
	if d := compute(now.Add(8 * 24 * time.Hour)); !d.ShowEmpty {
		t.Error("weekly reminder missing")
	}
	// A change of the count shows it at once.
	other := f.addProject("acme-other", project.Project{})
	f.scanRow(other.ID, "empty", now.Add(25*time.Hour))
	if d := compute(now.Add(26 * time.Hour)); d.EmptyProjects != 2 || !d.ShowEmpty {
		t.Errorf("count changed: empty %d show %t", d.EmptyProjects, d.ShowEmpty)
	}
}
