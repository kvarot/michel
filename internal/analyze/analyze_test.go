package analyze

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
