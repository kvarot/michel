package project

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/store"
)

type regFixture struct {
	st      *store.Store
	repo    *Repo
	log     *audit.Logger
	folders Folders
}

func newRegFixture(t *testing.T) *regFixture {
	t.Helper()
	data := t.TempDir()
	s, err := store.Open(filepath.Join(data, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return &regFixture{st: s, repo: NewRepo(s), log: audit.NewLogger(s, time.Now), folders: Folders{DataDir: data, Home: t.TempDir()}}
}

func (f *regFixture) register(name, path string) (Project, error) {
	return Register(context.Background(), f.repo, f.log, RegisterRequest{Actor: "test", Name: name, Path: path, Folders: f.folders})
}

type regRow struct {
	actor, target, result string
	evidence              map[string]any
}

func (f *regFixture) rows(t *testing.T) []regRow {
	t.Helper()
	rs, err := f.st.DB().Query(`SELECT actor, target, result, evidence FROM audit_event WHERE action = 'project.add' ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []regRow
	for rs.Next() {
		var r regRow
		var ev string
		if err := rs.Scan(&r.actor, &r.target, &r.result, &ev); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(ev), &r.evidence); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func (f *regFixture) count(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.st.DB().QueryRow(`SELECT COUNT(*) FROM project`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRegisterAddsAndAudits(t *testing.T) {
	f := newRegFixture(t)
	dir := t.TempDir()
	p, err := f.register("  demo ", " "+dir+" ")
	if err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(dir)
	if p.Name != "demo" || p.Path != real || !p.Active || p.FixLevel != 1 {
		t.Errorf("project = %+v", p)
	}
	rows := f.rows(t)
	if len(rows) != 1 || rows[0].actor != "test" || rows[0].target != "demo" || rows[0].result != "ok" {
		t.Fatalf("audit = %+v", rows)
	}
	ev := rows[0].evidence
	if ev["path"] != real || ev["classification"] != string(p.Classification) || ev["fix_level"] != float64(1) || len(ev) != 3 {
		t.Errorf("evidence = %v", ev)
	}
}

func TestRegisterKeepsTheOptionalFields(t *testing.T) {
	f := newRegFixture(t)
	p, err := Register(context.Background(), f.repo, f.log, RegisterRequest{
		Actor: "cli", Name: "demo", Path: t.TempDir(), Folders: f.folders,
		Classification: "internal", FixLevel: 0, FixLevelSet: true, AutoFixMinor: true,
		TestCmd: "make test", InstallCmd: "npm ci", CorePackages: []string{"x"}, Exclude: []string{"tmp"}, Tech: []string{"nginx"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Classification != "internal" || p.FixLevel != 0 || !p.AutoFixMinor || p.TestCmd != "make test" || p.InstallCmd != "npm ci" ||
		strings.Join(p.CorePackages, ",") != "x" || strings.Join(p.Exclude, ",") != "tmp" || strings.Join(p.Tech, ",") != "nginx" {
		t.Errorf("project = %+v", p)
	}
	if ev := f.rows(t)[0].evidence; ev["fix_level"] != float64(0) || ev["classification"] != "internal" {
		t.Errorf("evidence = %v", ev)
	}
}

// Every refusal leaves a trace with its key, and no project.
func TestRegisterRefusalsAreAuditedWithTheirKey(t *testing.T) {
	f := newRegFixture(t)
	file := filepath.Join(t.TempDir(), "composer.lock")
	writeFile(t, file)
	inData := filepath.Join(f.folders.DataDir, "inside")
	if err := os.Mkdir(inData, 0o700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, path, key string
		req             func(*RegisterRequest)
	}{
		{name: "", path: t.TempDir(), key: "api.project.bad_name"},
		{name: "a/b", path: t.TempDir(), key: "api.project.bad_name"},
		{name: "demo", path: "some/folder", key: "api.project.relative_path"},
		{name: "demo", path: "", key: "api.project.relative_path"},
		{name: "demo", path: f.folders.DataDir, key: "api.project.forbidden_path"},
		{name: "demo", path: inData, key: "api.project.forbidden_path"},
		{name: "demo", path: f.folders.Home, key: "api.project.forbidden_path"},
		{name: "demo", path: file, key: "api.project.not_dir"},
		{name: "demo", path: filepath.Join(t.TempDir(), "missing"), key: "api.project.not_dir"},
		{name: "demo", path: t.TempDir(), key: "cli.project.add.bad_classification", req: func(r *RegisterRequest) { r.Classification = "secret" }},
		{name: "demo", path: t.TempDir(), key: "cli.project.add.bad_fix_level", req: func(r *RegisterRequest) { r.FixLevel, r.FixLevelSet = 9, true }},
		{name: "demo", path: t.TempDir(), key: "cli.project.add.bad_exclude", req: func(r *RegisterRequest) { r.Exclude = []string{"a/b"} }},
		{name: "demo", path: t.TempDir(), key: "cli.project.add.bad_tech", req: func(r *RegisterRequest) { r.Tech = []string{"Nginx!"} }},
	}
	for _, c := range cases {
		req := RegisterRequest{Actor: "test", Name: c.name, Path: c.path, Folders: f.folders}
		if c.req != nil {
			c.req(&req)
		}
		_, err := Register(context.Background(), f.repo, f.log, req)
		var re *RefusalError
		if !errors.As(err, &re) || re.Key != c.key {
			t.Errorf("%q %q: err = %v, want the key %s", c.name, c.path, err, c.key)
		}
		if errors.As(err, new(*AuditError)) {
			t.Errorf("%q: an audit failure is reported: %v", c.path, err)
		}
	}
	rows := f.rows(t)
	if len(rows) != len(cases) {
		t.Fatalf("audit rows = %d, want %d", len(rows), len(cases))
	}
	for i, r := range rows {
		if r.result != "denied" || r.actor != "test" || r.evidence["reason"] != cases[i].key || r.evidence["path"] != cases[i].path || len(r.evidence) != 2 {
			t.Errorf("row %d = %+v", i, r)
		}
	}
	if n := f.count(t); n != 0 {
		t.Errorf("projects = %d", n)
	}
}

// What was asked is kept in the audit, bounded and without control characters.
func TestRegisterRefusalAuditIsBounded(t *testing.T) {
	f := newRegFixture(t)
	long := "/" + strings.Repeat("x", 5000) + "\x1b[31m"
	if _, err := f.register(strings.Repeat("n", 100)+"\n", long); err == nil {
		t.Fatal("refused expected")
	}
	r := f.rows(t)[0]
	path, _ := r.evidence["path"].(string)
	if len([]rune(path)) > maxPathLen || strings.ContainsRune(path, '\x1b') || len([]rune(r.target)) > maxProjectName || strings.ContainsRune(r.target, '\n') {
		t.Errorf("row = %d runes of path, target %q", len([]rune(path)), r.target)
	}
}

// A second active project on the same folder is refused, whatever the case on
// systems that fold it; a removed project frees its folder.
func TestRegisterRefusesASecondProjectOnTheSameFolder(t *testing.T) {
	f := newRegFixture(t)
	dir := t.TempDir()
	if _, err := f.register("demo", dir); err != nil {
		t.Fatal(err)
	}
	_, err := f.register("other", dir)
	var re *RefusalError
	if !errors.As(err, &re) || re.Key != "api.project.duplicate" || !errors.Is(err, ErrDuplicateFolder) {
		t.Fatalf("same folder: err = %v", err)
	}
	_, err = f.register("demo", t.TempDir())
	if !errors.As(err, &re) || re.Key != "api.project.duplicate" || !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("same name: err = %v", err)
	}
	if _, err := f.repo.Remove(context.Background(), "demo"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.register("other", dir); err != nil {
		t.Errorf("a removed project keeps its folder: %v", err)
	}
	rows := f.rows(t)
	if len(rows) != 4 || rows[1].result != "denied" || rows[1].evidence["reason"] != "api.project.duplicate" || rows[3].result != "ok" {
		t.Errorf("audit = %+v", rows)
	}
}

// No project without its trace: the audit fails, the project goes.
func TestRegisterPurgesWhenTheAuditFails(t *testing.T) {
	f := newRegFixture(t)
	if _, err := f.st.DB().Exec(`CREATE TRIGGER fail_add BEFORE INSERT ON audit_event WHEN NEW.action = 'project.add'
		BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`); err != nil {
		t.Fatal(err)
	}
	_, err := f.register("demo", t.TempDir())
	var ae *AuditError
	if !errors.As(err, &ae) || !strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("err = %v", err)
	}
	if n := f.count(t); n != 0 {
		t.Errorf("projects = %d, want the project purged", n)
	}
	// A refusal whose trace fails says both.
	_, err = f.register("", t.TempDir())
	var re *RefusalError
	if !errors.As(err, &ae) || !errors.As(err, &re) || re.Key != "api.project.bad_name" {
		t.Errorf("refusal: err = %v", err)
	}
}

// A storage error is audited error, and is no refusal.
func TestRegisterStorageErrorIsAuditedError(t *testing.T) {
	f := newRegFixture(t)
	if _, err := f.st.DB().Exec(`CREATE TRIGGER boom BEFORE INSERT ON project BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_, err := f.register("demo", dir)
	if err == nil || errors.As(err, new(*RefusalError)) || errors.As(err, new(*AuditError)) {
		t.Fatalf("err = %v", err)
	}
	rows := f.rows(t)
	if len(rows) != 1 || rows[0].result != "error" || rows[0].evidence["path"] != dir || !strings.Contains(rows[0].evidence["reason"].(string), "disk on fire") {
		t.Errorf("audit = %+v", rows)
	}
}

// A caller that goes away right after the store write (Ctrl-C, a closed page)
// does not cost the trace: the audit row is written and the project stays.
func TestRegisterAndUpdateKeepTheirTraceWhenTheCallerGoesAway(t *testing.T) {
	f := newRegFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	// The logger reads its clock once the store write is done: cancel there.
	f.log = audit.NewLogger(f.st, func() time.Time { cancel(); return time.Now() })
	if _, err := Register(ctx, f.repo, f.log, RegisterRequest{Actor: "test", Name: "demo", Path: t.TempDir(), Folders: f.folders}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if rows := f.rows(t); len(rows) != 1 || rows[0].result != "ok" {
		t.Errorf("add rows = %+v", rows)
	}
	if n := f.count(t); n != 1 {
		t.Errorf("projects = %d", n)
	}
	ctx, cancel = context.WithCancel(context.Background())
	three := 3
	if _, err := Update(ctx, f.repo, f.log, UpdateRequest{Actor: "test", Name: "demo", Patch: Patch{FixLevel: &three}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if rows := f.updateRows(t); len(rows) != 1 || rows[0].result != "ok" {
		t.Errorf("update rows = %+v", rows)
	}
}
