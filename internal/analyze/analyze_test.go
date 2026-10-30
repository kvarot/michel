package analyze

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/store"
)

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// phpProject builds a complete PHP project: lockfile, root manifest, vendor
// changelog, two call sites and one covering test.
func phpProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	copyTree(t, filepath.Join("testdata", "callsites", "php"), root)
	cl, err := os.ReadFile(filepath.Join("testdata", "changelog", "keepachangelog.md"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "vendor", "acme", "vuln", "CHANGELOG.md"), cl, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "composer.json"), []byte(`{"require":{"acme/vuln":"^1.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func phpFinding() scan.Finding {
	return scan.Finding{ID: "f1", ProjectID: "p1", ManifestRelPath: "composer.lock", Ecosystem: "Packagist",
		Package: "acme/vuln", OSVID: "ACME-1", InstalledVersion: "1.0.0", FixedVersions: []string{"1.0.1"},
		Status: "new", LastSeenAt: "2026-01-01T00:00:00Z"}
}

func TestAnalyzeEndToEndPhp(t *testing.T) {
	root := phpProject(t)
	a, err := Analyze(root, project.Project{Path: root}, phpFinding(), policy.Defaults().Risk, scan.DefaultExclude)
	if err != nil {
		t.Fatal(err)
	}
	if a.Path.Directness != Direct || !a.HasRootManifest || a.Upgrade.Jump != JumpPatch || a.Upgrade.Target != "1.0.1" {
		t.Errorf("path/upgrade: %+v %+v", a.Path, a.Upgrade)
	}
	if a.Calls.Count != 2 || a.Coverage.Count != 1 || !a.Changelog.Available {
		t.Errorf("calls=%d tests=%d changelog=%+v", a.Calls.Count, a.Coverage.Count, a.Changelog)
	}
	if a.Risk.Recommendation != RecAutoFix {
		t.Errorf("risk: %+v", a.Risk)
	}
}

func TestAnalyzeMissingLockfileIsNotFatal(t *testing.T) {
	root := phpProject(t)
	os.Remove(filepath.Join(root, "composer.lock"))
	a, err := Analyze(root, project.Project{Path: root}, phpFinding(), policy.Defaults().Risk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Path.Directness != Unknown || a.HasRootManifest || len(a.Notes) != 1 {
		t.Errorf("%+v notes=%v", a.Path, a.Notes)
	}
}

func TestIsCore(t *testing.T) {
	p := project.Project{CorePackages: []string{"Acme/Vuln"}}
	if !isCore(p, "Packagist", "acme/vuln") || isCore(p, "npm", "acme/vuln") || !isCore(p, "npm", "Acme/Vuln") {
		t.Error("core matching is case-insensitive for Packagist only")
	}
}

type testEnv struct {
	deps Deps
	st   *store.Store
	root string
	p    project.Project
	f    scan.Finding
	now  *time.Time
}

func newEnv(t *testing.T) testEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	e := testEnv{st: st, root: phpProject(t), now: &now}
	e.deps = Deps{Store: st, Audit: audit.NewLogger(st, func() time.Time { return *e.now }), Version: "v1",
		Now: func() time.Time { return *e.now }, Risk: policy.Defaults().Risk}
	e.p = project.Project{ID: "p1", Name: "demo", Path: e.root}
	e.f = phpFinding()
	return e
}

func TestRunSkipsFreshAnalysis(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	fs := []scan.Finding{e.f}
	r, err := Run(ctx, e.deps, e.p, fs, Options{})
	if err != nil || r.Analyzed != 1 || r.Failed != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	r, _ = Run(ctx, e.deps, e.p, fs, Options{})
	if r.Skipped != 1 || r.Analyzed != 0 {
		t.Errorf("second run: %+v", r)
	}
	r, _ = Run(ctx, e.deps, e.p, fs, Options{Force: true})
	if r.Analyzed != 1 || r.Skipped != 0 {
		t.Errorf("forced run: %+v", r)
	}
	// A finding seen again after the analysis, or a new Michel version, invalidates it.
	fs[0].LastSeenAt = "2026-03-01T00:00:00Z"
	if r, _ = Run(ctx, e.deps, e.p, fs, Options{}); r.Analyzed != 1 {
		t.Errorf("stale by last_seen_at: %+v", r)
	}
	*e.now = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	e.deps.Version = "v2"
	if r, _ = Run(ctx, e.deps, e.p, fs, Options{}); r.Analyzed != 1 {
		t.Errorf("stale by version: %+v", r)
	}
}

func TestRunAuditsStartAndFinish(t *testing.T) {
	e := newEnv(t)
	if _, err := Run(context.Background(), e.deps, e.p, []scan.Finding{e.f}, Options{}); err != nil {
		t.Fatal(err)
	}
	rows, err := e.st.DB().Query(`SELECT action, result FROM audit_event WHERE action LIKE 'analyze.%' ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var a, r string
		rows.Scan(&a, &r)
		got = append(got, a+":"+r)
	}
	if strings.Join(got, ",") != "analyze.start:ok,analyze.finish:ok" {
		t.Errorf("events %v", got)
	}
}

func TestRunCountsFailures(t *testing.T) {
	e := newEnv(t)
	// Closing the store makes every save fail while the run itself completes.
	e.deps.Audit = nil
	e.st.Close()
	r, err := Run(context.Background(), e.deps, e.p, []scan.Finding{e.f}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Failed != 1 || len(r.Errors) == 0 {
		t.Errorf("%+v", r)
	}
}

func TestSaveStripsSnippets(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, err := Analyze(e.root, e.p, e.f, e.deps.Risk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Calls.Sites) == 0 || a.Calls.Sites[0].Snippet == "" {
		t.Fatalf("fixture has no snippet to strip: %+v", a.Calls.Sites)
	}
	a.ComputedAt, a.MichelVersion = *e.now, "v1"
	a.Changelog.Excerpt = strings.Repeat("é", 5000)
	repo := NewRepo(e.st)
	if err := repo.Save(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := repo.Save(ctx, a); err != nil { // upsert
		t.Fatal(err)
	}
	var raw, excerpt string
	var allows *int
	if err := e.st.DB().QueryRow(`SELECT call_sites, changelog_excerpt, constraint_allows FROM analysis WHERE finding_id='f1'`).Scan(&raw, &excerpt, &allows); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "snippet") || !strings.Contains(raw, `"is_test"`) {
		t.Errorf("call_sites: %s", raw)
	}
	var sites []map[string]any
	if err := json.Unmarshal([]byte(raw), &sites); err != nil || len(sites) != len(a.Calls.Sites) {
		t.Errorf("decode: %v %d", err, len(sites))
	}
	if len(excerpt) > 4096 || len(excerpt)%2 != 0 {
		t.Errorf("excerpt %d bytes", len(excerpt))
	}
	got, ok, err := repo.Get(ctx, "f1")
	if err != nil || !ok || got.Path.Directness != Direct || got.Risk.Recommendation != a.Risk.Recommendation ||
		got.Calls.Count != a.Calls.Count || got.Calls.Sites[0].Snippet != "" || !got.ComputedAt.Equal(*e.now) {
		t.Errorf("round trip: %v %v %+v", ok, err, got)
	}
	if _, ok, _ := repo.Get(ctx, "nope"); ok {
		t.Error("unknown finding found")
	}
}

func TestConstraintAllowsRoundTrip(t *testing.T) {
	e := newEnv(t)
	repo := NewRepo(e.st)
	yes, no := true, false
	for i, want := range []*bool{nil, &no, &yes} {
		a := Analysis{FindingID: "f1", ComputedAt: *e.now, MichelVersion: "v1"}
		a.Upgrade.ConstraintAllows = want
		if err := repo.Save(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		got, ok, err := repo.Get(context.Background(), "f1")
		if err != nil || !ok {
			t.Fatalf("case %d: %v %v", i, ok, err)
		}
		if (want == nil) != (got.Upgrade.ConstraintAllows == nil) || (want != nil && *want != *got.Upgrade.ConstraintAllows) {
			t.Errorf("case %d: want %v got %v", i, want, got.Upgrade.ConstraintAllows)
		}
	}
}

func TestSaveGetPreservesFacts(t *testing.T) {
	e := newEnv(t)
	repo := NewRepo(e.st)
	yes := true
	in := Analysis{
		FindingID: "f1", ComputedAt: *e.now, MichelVersion: "v1",
		Path:            DepPath{Directness: Transitive, Via: []string{"a/b", "c/d"}, Constraint: "^1.0"},
		HasRootManifest: true,
		Upgrade:         Upgrade{Target: "2.0.0", Jump: JumpMajor, ConstraintAllows: &yes},
		Calls:           CallSites{Sites: []CallSite{{File: "src/A.php", Line: 3, IsTest: true}}, Count: 7, Quality: "psr4", Namespaces: []string{`Acme\Vuln`}},
		Coverage:        Coverage{TestFiles: []string{"tests/A.php"}, Count: 4, Method: "callsite"},
		Changelog:       Changelog{Source: "vendor/x/CHANGELOG.md", Excerpt: "## 2.0.0", Available: true, Breaking: true, BreakingLines: []string{"BREAKING: x"}},
		Risk:            Risk{Score: 55, Recommendation: RecHandoff, Warning: true, Terms: map[string]int{"major_jump": 30, "direct": 0}},
	}
	if err := repo.Save(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	out, ok, err := repo.Get(context.Background(), "f1")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	for name, pair := range map[string][2]any{
		"path": {in.Path, out.Path}, "upgrade": {in.Upgrade, out.Upgrade}, "calls": {in.Calls, out.Calls},
		"coverage": {in.Coverage, out.Coverage}, "changelog": {in.Changelog, out.Changelog},
		"risk": {in.Risk, out.Risk},
	} {
		if !reflect.DeepEqual(pair[0], pair[1]) {
			t.Errorf("%s differs:\n in  %+v\n out %+v", name, pair[0], pair[1])
		}
	}
	if !out.HasRootManifest || !out.ComputedAt.Equal(in.ComputedAt) || out.MichelVersion != "v1" {
		t.Errorf("scalars: %+v", out)
	}
	// Damaged JSON is an error, not silent empty data.
	if _, err := e.st.DB().Exec(`UPDATE analysis SET risk_terms='{oops' WHERE finding_id='f1'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.Get(context.Background(), "f1"); err == nil {
		t.Error("damaged JSON column must be an error")
	}
	// Run recomputes it instead of skipping.
	r, err := Run(context.Background(), e.deps, e.p, []scan.Finding{e.f}, Options{})
	if err != nil || r.Analyzed != 1 || r.Skipped != 0 {
		t.Errorf("recompute: %+v %v", r, err)
	}
}

func auditEvents(t *testing.T, e testEnv) map[string]map[string]any {
	t.Helper()
	rows, err := e.st.DB().Query(`SELECT action, result, evidence FROM audit_event WHERE action LIKE 'analyze.%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]map[string]any{}
	for rows.Next() {
		var a, res, ev string
		if err := rows.Scan(&a, &res, &ev); err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		if err := json.Unmarshal([]byte(ev), &m); err != nil {
			t.Fatal(err)
		}
		m["_result"] = res
		out[a] = m
	}
	return out
}

func TestRunIsolatesAFailingFinding(t *testing.T) {
	e := newEnv(t)
	good1, good2, bad := e.f, e.f, e.f
	good2.ID, good2.OSVID = "f2", "ACME-2"
	bad.ID = "f3"
	// A trigger makes the save of f3 fail, as a full disk or a locked row would.
	if _, err := e.st.DB().Exec(`CREATE TRIGGER boom BEFORE INSERT ON analysis WHEN NEW.finding_id = 'f3' BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatal(err)
	}
	r, err := Run(context.Background(), e.deps, e.p, []scan.Finding{good1, bad, good2}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Analyzed != 2 || r.Failed != 1 || len(r.Errors) != 1 {
		t.Fatalf("%+v", r)
	}
	ev := auditEvents(t, e)
	fin := ev["analyze.finish"]
	if fin == nil || fin["_result"] != "partial" {
		t.Fatalf("finish: %v", fin)
	}
	for k, want := range map[string]float64{"analyzed": 2, "skipped": 0, "failed": 1} {
		if fin[k] != want {
			t.Errorf("evidence %s = %v, want %v", k, fin[k], want)
		}
	}
	if _, ok := fin["duration_ms"]; !ok {
		t.Error("evidence lacks duration_ms")
	}
}

func TestRunLoadsOneGraphPerManifest(t *testing.T) {
	e := newEnv(t)
	loads := 0
	orig := loadGraph
	loadGraph = func(dir, eco, lock string) (*DepGraph, error) { loads++; return orig(dir, eco, lock) }
	t.Cleanup(func() { loadGraph = orig })
	f2, f3 := e.f, e.f
	f2.ID, f3.ID = "f2", "f3"
	f3.ManifestRelPath = "api/composer.lock"
	if _, err := Run(context.Background(), e.deps, e.p, []scan.Finding{e.f, f2, f3}, Options{}); err != nil {
		t.Fatal(err)
	}
	if loads != 2 {
		t.Errorf("LoadDepGraph called %d times, want 2 (one per manifest)", loads)
	}
}

func TestRunCancelledRecordsFinish(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, e.deps, e.p, []scan.Finding{e.f}, Options{}); err == nil {
		t.Fatal("want a cancellation error")
	}
	fin := auditEvents(t, e)["analyze.finish"]
	if fin == nil || fin["_result"] != "failed" || fin["reason"] != "cancelled" {
		t.Errorf("finish: %v", fin)
	}
}

// assertNoZeroField fails for every zero field of v (recursively in structs),
// so a field added later without persistence breaks the round-trip test.
func assertNoZeroField(t *testing.T, v reflect.Value, path string) {
	t.Helper()
	if v.Kind() == reflect.Struct && v.Type() != reflect.TypeOf(time.Time{}) {
		for i := 0; i < v.NumField(); i++ {
			assertNoZeroField(t, v.Field(i), path+"."+v.Type().Field(i).Name)
		}
		return
	}
	if v.IsZero() {
		t.Errorf("%s is zero: the round trip does not cover it", path)
	}
}

func TestSaveGetRoundTripEveryField(t *testing.T) {
	e := newEnv(t)
	repo := NewRepo(e.st)
	yes := true
	in := Analysis{
		FindingID: "f1", ProjectID: "p1", ComputedAt: *e.now, MichelVersion: "v1",
		Path:            DepPath{Directness: Transitive, Via: []string{"acme/lib", "acme/mid"}, Constraint: "^1.0"},
		HasRootManifest: true,
		Upgrade:         Upgrade{Target: "2.0.0", Jump: JumpMajor, ConstraintAllows: &yes},
		Calls: CallSites{
			Sites: []CallSite{{File: "src/A.php", Line: 3, IsTest: true}}, Count: 7, Quality: "psr4",
			Namespaces: []string{`Acme\Vuln`}, Unreadable: 2, UnreadablePaths: []string{"src/Big.php", "src/Locked.php"},
			TestFiles: []string{"tests/ATest.php"}, TestFileCount: 3, TestHitCount: 5, SourceFiles: []string{"src/A.php", "src/B.php"},
		},
		Coverage: Coverage{TestFiles: []string{"tests/ATest.php"}, Count: 4, Method: "reference",
			Skipped: []string{"index"}, Unreadable: 1},
		Changelog: Changelog{Source: "vendor/acme/vuln/CHANGELOG.md", Excerpt: "## 2.0.0", Available: true, Breaking: true,
			BreakingLines: []string{"BREAKING: x"}, Note: "no version headings"},
		Risk:       Risk{Score: 55, Recommendation: RecHandoff, Warning: true, Terms: map[string]int{"major_jump": 30, "exploited": 1}, Urgency: UrgencyUrgent},
		InputsHash: "abc123",
		Notes:      []string{"dependency graph unavailable: no lockfile"},
	}
	// Snippets are never stored: the only field left zero on purpose.
	probe := in
	probe.Calls.Sites = []CallSite{{File: "x", Line: 1, IsTest: true, Snippet: "x"}}
	assertNoZeroField(t, reflect.ValueOf(probe), "Analysis")

	if err := repo.Save(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	out, ok, err := repo.Get(context.Background(), "f1")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip differs:\n in  %+v\n out %+v", in, out)
	}
}

func TestRunUsesProjectExclusions(t *testing.T) {
	e := newEnv(t)
	e.p.Exclude = []string{"build"}
	if _, err := Run(context.Background(), e.deps, e.p, []scan.Finding{e.f}, Options{}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := NewRepo(e.st).Get(context.Background(), e.f.ID)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	want := InputsHash(e.deps.Risk, e.p, scan.EffectiveExclude(e.p), isCore(e.p, e.f.Ecosystem, e.f.Package))
	if got.InputsHash != want {
		t.Errorf("inputs hash %s, want the one built from the project's exclusions %s", got.InputsHash, want)
	}
}
