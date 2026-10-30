package project

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/store"
)

func newRepo(t *testing.T) *Repo {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return NewRepo(s)
}

func TestAddRejectsMissingPath(t *testing.T) {
	r := newRepo(t)
	missing, _ := filepath.Abs(filepath.Join(t.TempDir(), "nope"))
	_, err := r.Add(context.Background(), Project{Name: "a", Path: missing})
	if !errors.Is(err, ErrNotADirectory) {
		t.Fatalf("err = %v", err)
	}
	if _, err := r.Add(context.Background(), Project{Name: "a", Path: "relative/dir"}); !errors.Is(err, ErrNotADirectory) {
		t.Fatalf("relative: err = %v", err)
	}
}

func TestAddRejectsFile(t *testing.T) {
	r := newRepo(t)
	f := filepath.Join(t.TempDir(), "f.txt")
	writeFile(t, f)
	if _, err := r.Add(context.Background(), Project{Name: "a", Path: f}); !errors.Is(err, ErrNotADirectory) {
		t.Fatalf("err = %v", err)
	}
}

func TestAddDefaults(t *testing.T) {
	r := newRepo(t)
	dir := t.TempDir()
	p, err := r.Add(context.Background(), Project{Name: "shop", Path: dir})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == "" || p.SourceType != "local_path" || p.FixLevel != 1 || !p.Active ||
		p.Classification != policy.ClassSensitive || p.CreatedAt.IsZero() || p.Path != filepath.Clean(dir) {
		t.Errorf("p = %+v", p)
	}
	r.DefaultClassification = policy.ClassInternal
	q, err := r.Add(context.Background(), Project{Name: "two", Path: dir})
	if err != nil || q.Classification != policy.ClassInternal {
		t.Errorf("q = %+v err=%v", q, err)
	}
	got, err := r.Get(context.Background(), p.ID)
	if err != nil || got.Name != "shop" || got.CreatedAt.IsZero() {
		t.Errorf("got = %+v err=%v", got, err)
	}
}

func TestAddRejectsDuplicateName(t *testing.T) {
	r := newRepo(t)
	dir := t.TempDir()
	if _, err := r.Add(context.Background(), Project{Name: "shop", Path: dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(context.Background(), Project{Name: "shop", Path: dir}); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("err = %v", err)
	}
}

func TestAddValidation(t *testing.T) {
	r := newRepo(t)
	dir := t.TempDir()
	ctx := context.Background()
	if _, err := r.Add(ctx, Project{Name: "", Path: dir}); !errors.Is(err, ErrEmptyName) {
		t.Errorf("empty name: %v", err)
	}
	if _, err := r.Add(ctx, Project{Name: "a", Path: dir, FixLevel: 4}); !errors.Is(err, ErrInvalidFixLevel) {
		t.Errorf("fix level 4: %v", err)
	}
	if _, err := r.Add(ctx, Project{Name: "a", Path: dir, FixLevel: -1}); !errors.Is(err, ErrInvalidFixLevel) {
		t.Errorf("fix level -1: %v", err)
	}
	if _, err := r.Add(ctx, Project{Name: "a", Path: dir, Classification: "secret"}); !errors.Is(err, ErrInvalidClassification) {
		t.Errorf("classification: %v", err)
	}
	if _, err := r.Add(ctx, Project{Name: "a", Path: dir, SourceType: "git"}); !errors.Is(err, ErrInvalidSourceType) {
		t.Errorf("source type: %v", err)
	}
	if l, _ := r.List(ctx); len(l) != 0 {
		t.Errorf("rows written on rejection: %v", l)
	}
}

func TestDuplicateNameRaceViaConstraint(t *testing.T) {
	r := newRepo(t)
	dir := t.TempDir()
	ctx := context.Background()
	if _, err := r.Add(ctx, Project{Name: "shop", Path: dir}); err != nil {
		t.Fatal(err)
	}
	// Bypass the pre-check to prove the UNIQUE constraint maps to ErrDuplicateName.
	err := r.insert(ctx, Project{ID: "x", Name: "shop", SourceType: "local_path", Path: dir, Classification: policy.ClassPublic, Active: true})
	if !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("err = %v", err)
	}
}

func TestListOrderedAndRemove(t *testing.T) {
	r := newRepo(t)
	dir := t.TempDir()
	ctx := context.Background()
	for _, n := range []string{"zeta", "alpha"} {
		if _, err := r.Add(ctx, Project{Name: n, Path: dir}); err != nil {
			t.Fatal(err)
		}
	}
	l, err := r.List(ctx)
	if err != nil || len(l) != 2 || l[0].Name != "alpha" {
		t.Fatalf("l=%v err=%v", l, err)
	}
	if _, err := r.Remove(ctx, "alpha"); err != nil {
		t.Fatal(err)
	}
	// Remove is a soft delete: the project is still found, inactive.
	if p, err := r.Get(ctx, "alpha"); err != nil || p.Active {
		t.Errorf("get after remove: %+v %v", p, err)
	}
	if l, _ := r.List(ctx); len(l) != 2 || l[0].Active || !l[1].Active {
		t.Errorf("list after remove: %+v", l)
	}
	if _, err := r.Remove(ctx, "alpha"); err != nil {
		t.Errorf("second remove: %v", err)
	}
	if _, err := r.Remove(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown remove: %v", err)
	}
}

func TestRemoveByID(t *testing.T) {
	r := newRepo(t)
	ctx := context.Background()
	p, _ := r.Add(ctx, Project{Name: "a", Path: t.TempDir()})
	if _, err := r.Remove(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
}

// seedHistory inserts one scan, one manifest and one finding for projectID.
func seedHistory(t *testing.T, r *Repo, projectID, scanID string) {
	t.Helper()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO scan (id, project_id, started_at, status) VALUES (?, ?, '2026-10-22T12:00:00Z', 'ok')`, []any{scanID, projectID}},
		{`INSERT INTO scan_manifest (scan_id, rel_path, ecosystem) VALUES (?, 'composer.lock', 'Packagist')`, []any{scanID}},
		{`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, installed_version, status,
			first_seen_scan, last_seen_scan, first_seen_at, last_seen_at)
			VALUES (?, ?, 'composer.lock', 'Packagist', 'acme/x', 'ACME-1', '1.0.0', 'new', ?, ?, '2026-10-22T12:00:00Z', '2026-10-22T12:00:00Z')`,
			[]any{scanID + "-f", projectID, scanID, scanID}},
	} {
		if _, err := r.s.DB().Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func countRows(t *testing.T, r *Repo, table, where string, arg any) int {
	t.Helper()
	var n int
	if err := r.s.DB().QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE `+where, arg).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRemoveScannedProjectKeepsHistory(t *testing.T) {
	r := newRepo(t)
	ctx := context.Background()
	p, _ := r.Add(ctx, Project{Name: "a", Path: t.TempDir()})
	seedHistory(t, r, p.ID, "s1")
	if _, err := r.Remove(ctx, "a"); err != nil {
		t.Fatalf("remove after scan: %v", err)
	}
	if got, _ := r.Get(ctx, "a"); got.Active {
		t.Error("project still active")
	}
	if countRows(t, r, "scan", "project_id = ?", p.ID) != 1 || countRows(t, r, "scan_manifest", "scan_id = ?", "s1") != 1 ||
		countRows(t, r, "finding", "project_id = ?", p.ID) != 1 {
		t.Error("history was not kept")
	}
}

func TestPurgeDeletesProjectAndHistory(t *testing.T) {
	r := newRepo(t)
	ctx := context.Background()
	dir := t.TempDir()
	p, _ := r.Add(ctx, Project{Name: "a", Path: dir})
	other, _ := r.Add(ctx, Project{Name: "b", Path: dir})
	seedHistory(t, r, p.ID, "s1")
	seedHistory(t, r, other.ID, "s2")
	if _, err := r.Purge(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(ctx, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after purge: %v", err)
	}
	if countRows(t, r, "scan", "project_id = ?", p.ID) != 0 || countRows(t, r, "scan_manifest", "scan_id = ?", "s1") != 0 ||
		countRows(t, r, "finding", "project_id = ?", p.ID) != 0 {
		t.Error("history of the purged project remains")
	}
	if countRows(t, r, "scan", "project_id = ?", other.ID) != 1 || countRows(t, r, "scan_manifest", "scan_id = ?", "s2") != 1 ||
		countRows(t, r, "finding", "project_id = ?", other.ID) != 1 {
		t.Error("purge touched another project")
	}
}

func TestPurgeIsAllOrNothing(t *testing.T) {
	r := newRepo(t)
	ctx := context.Background()
	p, _ := r.Add(ctx, Project{Name: "a", Path: t.TempDir()})
	seedHistory(t, r, p.ID, "s1")
	if _, err := r.s.DB().Exec(`CREATE TRIGGER no_delete BEFORE DELETE ON project BEGIN SELECT RAISE(ABORT, 'locked'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Purge(ctx, "a"); err == nil {
		t.Fatal("expected purge to fail")
	}
	if countRows(t, r, "finding", "project_id = ?", p.ID) != 1 || countRows(t, r, "scan", "project_id = ?", p.ID) != 1 {
		t.Error("a failed purge deleted part of the history")
	}
}

func TestAddExplicitFixLevelZero(t *testing.T) {
	r := newRepo(t)
	p, err := r.Add(context.Background(), Project{Name: "a", Path: t.TempDir(), FixLevel: 0, FixLevelSet: true})
	if err != nil || p.FixLevel != 0 {
		t.Fatalf("p=%+v err=%v", p, err)
	}
}

func TestCorePackagesRoundTrip(t *testing.T) {
	r := newRepo(t)
	ctx := context.Background()
	added, err := r.Add(ctx, Project{Name: "shop", Path: t.TempDir(), CorePackages: []string{"symfony/http-kernel", "react"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(ctx, "shop")
	if err != nil || len(got.CorePackages) != 2 || got.CorePackages[0] != "symfony/http-kernel" || got.CorePackages[1] != "react" {
		t.Fatalf("got %+v err %v (added %+v)", got.CorePackages, err, added.CorePackages)
	}
	list, _ := r.List(ctx)
	if len(list) != 1 || len(list[0].CorePackages) != 2 {
		t.Fatalf("list = %+v", list)
	}
	other, err := r.Add(ctx, Project{Name: "bare", Path: t.TempDir()})
	if err != nil || other.CorePackages == nil || other.RiskOverrides == nil {
		t.Fatalf("empty values must be non-nil: %+v err %v", other, err)
	}
}

func TestRiskOverridesRoundTrip(t *testing.T) {
	r := newRepo(t)
	ctx := context.Background()
	if _, err := r.Add(ctx, Project{Name: "shop", Path: t.TempDir(), RiskOverrides: map[string]int{"major_jump": 10, "no_tests": 5}}); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(ctx, "shop")
	if err != nil || got.RiskOverrides["major_jump"] != 10 || got.RiskOverrides["no_tests"] != 5 || len(got.RiskOverrides) != 2 {
		t.Fatalf("got %+v err %v", got.RiskOverrides, err)
	}
}

func TestRiskOverridesRejectUnknownKey(t *testing.T) {
	r := newRepo(t)
	_, err := r.Add(context.Background(), Project{Name: "shop", Path: t.TempDir(), RiskOverrides: map[string]int{"majorjump": 10}})
	if !errors.Is(err, ErrInvalidRiskOverride) {
		t.Fatalf("err = %v", err)
	}
}

func TestUpdateChangesFields(t *testing.T) {
	r := newRepo(t)
	ctx := context.Background()
	p, err := r.Add(ctx, Project{Name: "shop", Path: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	p.CorePackages = []string{"a"}
	p.RiskOverrides = map[string]int{"direct": 0}
	p.FixLevel, p.TestCmd = 3, "go test"
	p.Classification = policy.ClassPublic
	if err := r.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, _ := r.Get(ctx, "shop")
	if got.FixLevel != 3 || got.TestCmd != "go test" || got.Classification != policy.ClassPublic ||
		len(got.CorePackages) != 1 || got.RiskOverrides["direct"] != 0 || len(got.RiskOverrides) != 1 {
		t.Fatalf("got %+v", got)
	}
	p.FixLevel = 9
	if err := r.Update(ctx, p); !errors.Is(err, ErrInvalidFixLevel) {
		t.Fatalf("err = %v", err)
	}
}

func TestExcludeRoundTrip(t *testing.T) {
	r := newRepo(t)
	ctx := context.Background()
	p, err := r.Add(ctx, Project{Name: "demo", Path: t.TempDir(), Exclude: []string{"b", "a", "a"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Exclude, []string{"a", "b"}) || !reflect.DeepEqual(p.Exclude, []string{"a", "b"}) {
		t.Errorf("exclude = %v (returned %v)", got.Exclude, p.Exclude)
	}
	for _, bad := range []string{"src/x", `src\x`, "..", "", "  "} {
		got.Exclude = []string{"ok", bad}
		if err := r.Update(ctx, got); !errors.Is(err, ErrInvalidExclude) {
			t.Errorf("update with %q: err = %v", bad, err)
		}
		if _, err := r.Add(ctx, Project{Name: "other", Path: t.TempDir(), Exclude: []string{bad}}); !errors.Is(err, ErrInvalidExclude) {
			t.Errorf("add with %q: err = %v", bad, err)
		}
	}
	got.Exclude = nil
	if err := r.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, err := r.Get(ctx, "demo"); err != nil || again.Exclude == nil || len(again.Exclude) != 0 {
		t.Errorf("cleared exclude = %#v err %v", again.Exclude, err)
	}
}

func TestPurgeDeletesDecisions(t *testing.T) {
	r := newRepo(t)
	ctx := context.Background()
	p, _ := r.Add(ctx, Project{Name: "a", Path: t.TempDir()})
	other, _ := r.Add(ctx, Project{Name: "b", Path: t.TempDir()})
	seedHistory(t, r, p.ID, "s1")
	seedHistory(t, r, other.ID, "s2")
	for _, d := range [][]any{{"d1", "s1-f", p.ID}, {"d2", "s1-f", p.ID}, {"d3", "s2-f", other.ID}} {
		if _, err := r.s.DB().Exec(`INSERT INTO decision (id, finding_id, project_id, action, author, created_at)
			VALUES (?, ?, ?, 'fix', 'cli', '2026-10-22T12:00:00Z')`, d...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Purge(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, r, "decision", "project_id = ?", p.ID); n != 0 {
		t.Errorf("%d decisions of the purged project remain", n)
	}
	if n := countRows(t, r, "decision", "project_id = ?", other.ID); n != 1 {
		t.Errorf("purge touched the decisions of another project: %d left", n)
	}
}

func TestTechRoundTrip(t *testing.T) {
	r := newRepo(t)
	ctx := context.Background()
	p, err := r.Add(ctx, Project{Name: "demo", Path: t.TempDir(), Tech: []string{"b", "a", "a"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Tech, []string{"a", "b"}) || !reflect.DeepEqual(p.Tech, []string{"a", "b"}) {
		t.Errorf("tech = %v (returned %v)", got.Tech, p.Tech)
	}
	if got.TechAuto == nil || len(got.TechAuto) != 0 {
		t.Errorf("tech_auto = %#v", got.TechAuto)
	}
	got.TechAuto = []string{"symfony", "php", "php"}
	if err := r.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := r.Get(ctx, "demo"); !reflect.DeepEqual(again.TechAuto, []string{"php", "symfony"}) {
		t.Errorf("tech_auto = %v", again.TechAuto)
	}
	got.Tech = []string{"Nginx!"}
	if err := r.Update(ctx, got); !errors.Is(err, ErrInvalidTech) {
		t.Errorf("update with an invalid tag: err = %v", err)
	}
	if _, err := r.Add(ctx, Project{Name: "other", Path: t.TempDir(), Tech: []string{"Nginx!"}}); !errors.Is(err, ErrInvalidTech) {
		t.Errorf("add with an invalid tag: err = %v", err)
	}
}
