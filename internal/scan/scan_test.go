package scan

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/store"
)

var osvRoot string

// testEcos are the ecosystems of the test databases.
var testEcos = []string{"Packagist", "npm"}

// buildOSVDB zips testdata/advisories/<eco>/*.json into <root>/osv-scalibr/<eco>/all.zip,
// one flat entry per advisory, the layout osv-scalibr's local matcher reads
// (it loads every entry whose name ends in ".json").
func buildOSVDB(root string) error {
	for _, eco := range testEcos {
		files, err := filepath.Glob(filepath.Join("testdata", "advisories", eco, "*.json"))
		if err != nil || len(files) == 0 {
			return fmt.Errorf("no advisories for %s: %v", eco, err)
		}
		zp := osvdb.ZipPath(root, eco)
		if err := os.MkdirAll(filepath.Dir(zp), 0o755); err != nil {
			return err
		}
		out, err := os.Create(zp)
		if err != nil {
			return err
		}
		zw := zip.NewWriter(out)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				return err
			}
			w, err := zw.Create(filepath.Base(f))
			if err != nil {
				return err
			}
			if _, err := w.Write(b); err != nil {
				return err
			}
		}
		if err := zw.Close(); err != nil {
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
	}
	return nil
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "michel-osvdb")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	osvRoot = dir
	if err := buildOSVDB(dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type env struct {
	deps Deps
	gw   *egress.Gateway
	proj project.Project
	repo *Repo
	st   *store.Store
}

func copyDir(t *testing.T, src, dst string) {
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

func newEnv(t *testing.T, fixtures ...string) env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := func() time.Time { return time.Now() }
	lg := audit.NewLogger(st, now)
	gw := egress.New(policy.Defaults(), lg.EgressSink())
	root := t.TempDir()
	for _, f := range fixtures {
		copyDir(t, filepath.Join("testdata", f), root)
	}
	p, err := project.NewRepo(st).Add(context.Background(), project.Project{Name: "demo", Path: root})
	if err != nil {
		t.Fatal(err)
	}
	return env{deps: Deps{Store: st, Audit: lg, Gateway: gw, Now: now, Version: "test"}, gw: gw, proj: p, repo: NewRepo(st), st: st}
}

func (e env) run(t *testing.T) Result {
	t.Helper()
	r, err := Run(context.Background(), e.deps, e.proj, Options{OSVRoot: osvRoot})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return r
}

func (e env) statuses(t *testing.T) map[string]string {
	t.Helper()
	fs, err := e.repo.ListFindings(context.Background(), e.proj.ID, "all")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range fs {
		out[f.OSVID] = f.Status
	}
	return out
}

func TestRunOfflineProducesZeroEgress(t *testing.T) {
	e := newEnv(t, "project-a")
	r := e.run(t)
	if n := len(e.gw.Attempts()); n != 0 {
		t.Fatalf("egress attempts = %d, want 0: %+v", n, e.gw.Attempts())
	}
	if r.Status != ScanOK || len(r.Errors) != 0 {
		t.Fatalf("status %s errors %v", r.Status, r.Errors)
	}
	if len(r.Manifests) != 2 {
		t.Fatalf("manifests = %+v", r.Manifests)
	}
	for _, m := range r.Manifests {
		if m.Findings < 1 || m.LockSHA256 == "" || m.Packages < 1 {
			t.Errorf("manifest %+v", m)
		}
	}
	if r.Manifests[0].RelPath != "composer.lock" || r.Manifests[1].RelPath != "web/package-lock.json" {
		t.Errorf("rel paths = %s, %s", r.Manifests[0].RelPath, r.Manifests[1].RelPath)
	}
	// 9.8 critical + 4.3 medium (composer), 7.5 high (npm); the acme/other advisory must not match.
	if r.BySeverity["critical"] != 1 || r.BySeverity["medium"] != 1 || r.BySeverity["high"] != 1 || r.New != 3 {
		t.Errorf("by severity %v new %d", r.BySeverity, r.New)
	}
	fs, _ := e.repo.ListFindings(context.Background(), e.proj.ID, "")
	if len(fs) != 3 || fs[0].SeverityLabel != "critical" || fs[0].Package != "acme/vuln" ||
		len(fs[0].FixedVersions) != 1 || fs[0].FixedVersions[0] != "1.0.1" || fs[0].InstalledVersion != "1.0.0" {
		t.Errorf("findings = %+v", fs)
	}
}

func TestRunStatusTransitions(t *testing.T) {
	e := newEnv(t, "project-a")
	lock := filepath.Join(e.proj.Path, "composer.lock")
	original, err := os.ReadFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	r := e.run(t)
	if r.New != 3 || r.Still != 0 || r.Gone != 0 {
		t.Fatalf("scan 1: %+v", r)
	}
	for id, s := range e.statuses(t) {
		if s != StatusNew {
			t.Errorf("scan 1: %s is %s", id, s)
		}
	}
	r = e.run(t)
	if r.New != 0 || r.Still != 3 {
		t.Fatalf("scan 2: %+v", r)
	}
	for id, s := range e.statuses(t) {
		if s != StatusPending {
			t.Errorf("scan 2: %s is %s", id, s)
		}
	}
	fixed := []byte(`{"content-hash":"x","packages":[{"name":"acme/vuln","version":"1.0.2"},{"name":"acme/safe","version":"2.0.0"}],"packages-dev":[]}`)
	if err := os.WriteFile(lock, fixed, 0o644); err != nil {
		t.Fatal(err)
	}
	r = e.run(t)
	if r.Gone != 2 || r.Still != 1 {
		t.Fatalf("scan 3: %+v", r)
	}
	st := e.statuses(t)
	if st["ACME-2026-0001"] != StatusGone || st["ACME-2026-0002"] != StatusGone || st["ACME-2026-0101"] != StatusPending {
		t.Errorf("scan 3: %v", st)
	}
	if fs, _ := e.repo.ListFindings(context.Background(), e.proj.ID, ""); len(fs) != 1 {
		t.Errorf("default listing should hide gone findings, got %d", len(fs))
	}
	if err := os.WriteFile(lock, original, 0o644); err != nil {
		t.Fatal(err)
	}
	r = e.run(t)
	if r.New != 0 || r.Reappeared != 2 || r.Still != 1 {
		t.Fatalf("scan 4: %+v", r)
	}
	for id, s := range e.statuses(t) {
		if s != StatusPending {
			t.Errorf("scan 4: %s is %s", id, s)
		}
	}
	var first, last string
	if err := e.st.DB().QueryRow(`SELECT first_seen_scan, last_seen_scan FROM finding WHERE osv_id='ACME-2026-0001'`).Scan(&first, &last); err != nil {
		t.Fatal(err)
	}
	if first == last || first == "" {
		t.Errorf("first_seen_scan %q last_seen_scan %q", first, last)
	}
}

func TestRunMissingDatabaseFailsBeforeNetwork(t *testing.T) {
	e := newEnv(t, "project-a")
	_, err := Run(context.Background(), e.deps, e.proj, Options{OSVRoot: t.TempDir()})
	if !errors.Is(err, osvdb.ErrDatabaseMissing) {
		t.Fatalf("err = %v", err)
	}
	if n := len(e.gw.Attempts()); n != 0 {
		t.Errorf("attempts = %d", n)
	}
	var n int
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM scan`).Scan(&n); err != nil || n != 0 {
		t.Errorf("scan rows = %d, err %v", n, err)
	}
}

func TestRunContinuesOnCorruptManifest(t *testing.T) {
	e := newEnv(t, "project-a")
	if err := os.MkdirAll(filepath.Join(e.proj.Path, "legacy"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join("testdata", "project-b", "composer.lock"))
	if err := os.WriteFile(filepath.Join(e.proj.Path, "legacy", "composer.lock"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	r := e.run(t)
	if len(r.Errors) != 1 || r.Status != ScanPartial {
		t.Fatalf("status %s errors %v", r.Status, r.Errors)
	}
	if len(r.Manifests) != 3 {
		t.Fatalf("manifests = %+v", r.Manifests)
	}
	var bad, good int
	for _, m := range r.Manifests {
		if m.RelPath == "legacy/composer.lock" {
			bad++
			if m.Err == nil || m.LockSHA256 == "" {
				t.Errorf("corrupt manifest = %+v", m)
			}
		} else if m.Err == nil && m.Findings > 0 {
			good++
		}
	}
	if bad != 1 || good != 2 {
		t.Errorf("bad %d good %d", bad, good)
	}
	var status, mErr string
	if err := e.st.DB().QueryRow(`SELECT status FROM scan WHERE id=?`, r.ScanID).Scan(&status); err != nil || status != "partial" {
		t.Errorf("scan.status = %q, err %v", status, err)
	}
	if err := e.st.DB().QueryRow(`SELECT error FROM scan_manifest WHERE scan_id=? AND rel_path='legacy/composer.lock'`, r.ScanID).Scan(&mErr); err != nil || mErr == "" {
		t.Errorf("manifest error = %q, %v", mErr, err)
	}
	// A manifest that becomes unreadable must not close the findings it used to hold.
	if err := os.WriteFile(filepath.Join(e.proj.Path, "composer.lock"), []byte(`{broken`), 0o644); err != nil {
		t.Fatal(err)
	}
	r = e.run(t)
	if r.Gone != 0 {
		t.Errorf("findings of an unreadable manifest were closed: %+v", r)
	}
	var cnt int
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM finding WHERE status='gone'`).Scan(&cnt); err != nil || cnt != 0 {
		t.Errorf("gone = %d, %v", cnt, err)
	}
}

func TestRunOnlyCorruptManifest(t *testing.T) {
	e := newEnv(t, "project-b")
	r := e.run(t)
	if r.Status != ScanPartial || len(r.Errors) != 1 || len(r.Manifests) != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestRunSkipsInstalledDependencies(t *testing.T) {
	e := newEnv(t, "project-a")
	for _, dir := range []string{"node_modules/dep", "vendor/acme/lib"} {
		d := filepath.Join(e.proj.Path, filepath.FromSlash(dir))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(filepath.Join("testdata", "project-a", "composer.lock"))
		if err := os.WriteFile(filepath.Join(d, "composer.lock"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := e.run(t)
	if len(r.Manifests) != 2 || r.New != 3 {
		t.Errorf("manifests %+v new %d", r.Manifests, r.New)
	}
}

func TestRunEmptyIsNotAnError(t *testing.T) {
	e := newEnv(t, "project-a")
	e.run(t)
	for _, f := range []string{"composer.lock", filepath.Join("web", "package-lock.json")} {
		if err := os.Remove(filepath.Join(e.proj.Path, f)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Run(context.Background(), e.deps, e.proj, Options{OSVRoot: osvRoot})
	if err != nil || r.Status != ScanEmpty {
		t.Fatalf("err %v status %s", err, r.Status)
	}
	// An empty or unmounted folder proves nothing about what was fixed.
	for id, s := range e.statuses(t) {
		if s != StatusNew {
			t.Errorf("%s is %s, want it untouched", id, s)
		}
	}
	var status string
	if err := e.st.DB().QueryRow(`SELECT status FROM scan WHERE id=?`, r.ScanID).Scan(&status); err != nil || status != "empty" {
		t.Errorf("scan row %q %v", status, err)
	}
	var ev, result string
	if err := e.st.DB().QueryRow(`SELECT evidence, result FROM audit_event WHERE action='scan.finish' ORDER BY rowid DESC LIMIT 1`).Scan(&ev, &result); err != nil ||
		!strings.Contains(ev, `"reason":"no_manifests"`) || result != ScanEmpty {
		t.Errorf("evidence %q result %q %v", ev, result, err)
	}
}

func TestRunSkipsSymlinkedLockfile(t *testing.T) {
	e := newEnv(t, "project-a")
	outside := filepath.Join(t.TempDir(), "composer.lock")
	b, _ := os.ReadFile(filepath.Join("testdata", "project-a", "composer.lock"))
	if err := os.WriteFile(outside, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.proj.Path, "linked"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(e.proj.Path, "linked", "composer.lock")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	r := e.run(t)
	for _, m := range r.Manifests {
		if strings.HasPrefix(m.RelPath, "linked/") {
			t.Errorf("symlinked lockfile was recorded: %+v", m)
		}
	}
	var n int
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM scan_manifest WHERE rel_path LIKE 'linked/%'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("rows %d %v", n, err)
	}
}

func TestRelPathOutsideRootIsAnError(t *testing.T) {
	root := filepath.Join(t.TempDir(), "proj")
	if _, err := relPath(root, filepath.Join(filepath.Dir(root), "other", "composer.lock")); err == nil {
		t.Error("expected an error for a path outside the project")
	}
	if rel, err := relPath(root, filepath.Join(root, "a", "composer.lock")); err != nil || rel != "a/composer.lock" {
		t.Errorf("rel %q err %v", rel, err)
	}
}

func TestProjectScannerConfigIsNotApplied(t *testing.T) {
	e := newEnv(t, "project-a")
	if r := e.run(t); r.New != 3 || len(r.Warnings) != 0 {
		t.Fatalf("scan 1: %+v", r)
	}
	cfg := filepath.Join(e.proj.Path, "web", ScannerConfigName)
	if err := os.WriteFile(cfg, []byte("[[IgnoredVulns]]\nid = \"ACME-2026-0101\"\nreason = \"hidden\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := e.run(t)
	if r.Gone != 0 || r.Still != 3 {
		t.Fatalf("scan 2: the project config hid a finding: %+v", r)
	}
	if s := e.statuses(t)["ACME-2026-0101"]; s == "" || s == StatusGone {
		t.Fatalf("ACME-2026-0101 status = %q", s)
	}
	if len(r.Warnings) != 1 || r.Warnings[0] != "web/osv-scanner.toml" {
		t.Fatalf("warnings = %v", r.Warnings)
	}
	var ev string
	if err := e.st.DB().QueryRow(`SELECT evidence FROM audit_event WHERE action = 'scan.finish' ORDER BY rowid DESC LIMIT 1`).Scan(&ev); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ev, `"ignored_config_files":["web/osv-scanner.toml"]`) {
		t.Fatalf("scan.finish evidence = %s", ev)
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(e.st.Path()), OverrideConfigName))
	if err != nil || string(b) != overrideContent {
		t.Fatalf("override file: %q %v", b, err)
	}
}

func TestOverrideConfigIsRestoredWhenEdited(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, OverrideConfigName)
	if err := os.WriteFile(path, []byte("[[IgnoredVulns]]\nid = \"ACME-2026-0101\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ensureOverrideConfig(dir)
	if err != nil || got != path {
		t.Fatalf("path %s err %v", got, err)
	}
	if b, _ := os.ReadFile(path); string(b) != overrideContent {
		t.Fatalf("content = %q", b)
	}
}

// treeDigest is the SHA-256 of every path, size and modification time under
// root: equal digests mean nothing was created, removed or written there.
func treeDigest(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		fmt.Fprintf(h, "%s\x00%d\x00%d\x00%v\n", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano(), info.Mode())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestScanNeverWritesUnderProject(t *testing.T) {
	e := newEnv(t, "project-a")
	before := treeDigest(t, e.proj.Path)
	e.run(t)
	e.run(t)
	if after := treeDigest(t, e.proj.Path); after != before {
		t.Error("the project folder changed during the scan")
	}
}

func TestScanSetsStatusChangedAt(t *testing.T) {
	e := newEnv(t, "project-a")
	clock := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	e.deps.Now = func() time.Time { return clock }
	changedAt := func(osvID string) (changed, lastSeen, status string) {
		t.Helper()
		if err := e.st.DB().QueryRow(`SELECT status_changed_at, last_seen_at, status FROM finding WHERE osv_id=?`, osvID).
			Scan(&changed, &lastSeen, &status); err != nil {
			t.Fatal(err)
		}
		return
	}
	at := func(c time.Time) string { return c.Format(time.RFC3339) }

	t1 := clock
	e.run(t) // new
	if c, last, _ := changedAt("ACME-2026-0001"); c != last || c != at(t1) {
		t.Fatalf("scan 1: status_changed_at %q last_seen_at %q", c, last)
	}
	clock = clock.Add(time.Hour)
	t2 := clock
	e.run(t) // new -> pending: a status change
	if c, _, s := changedAt("ACME-2026-0001"); s != StatusPending || c != at(t2) {
		t.Fatalf("scan 2: %s at %q", s, c)
	}
	clock = clock.Add(time.Hour)
	e.run(t) // pending -> pending: no change
	if c, last, _ := changedAt("ACME-2026-0001"); c != at(t2) || last == at(t2) {
		t.Fatalf("scan 3 (no change): status_changed_at %q last_seen_at %q", c, last)
	}
	fixed := []byte(`{"content-hash":"x","packages":[{"name":"acme/vuln","version":"1.0.2"},{"name":"acme/safe","version":"2.0.0"}],"packages-dev":[]}`)
	if err := os.WriteFile(filepath.Join(e.proj.Path, "composer.lock"), fixed, 0o644); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Hour)
	t4 := clock
	e.run(t) // the composer findings disappear
	if c, _, s := changedAt("ACME-2026-0001"); s != StatusGone || c != at(t4) {
		t.Errorf("scan 4 (gone): %s at %q, want %q", s, c, at(t4))
	}
	if c, _, s := changedAt("ACME-2026-0101"); s != StatusPending || c != at(t2) {
		t.Errorf("scan 4 (still present): %s at %q, want %q", s, c, at(t2))
	}
}

func TestScanPanicIsRecordedAsFailed(t *testing.T) {
	e := newEnv(t, "project-a")
	afterScanHook = func() { panic("boom") }
	t.Cleanup(func() { afterScanHook = nil })
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_, _ = Run(context.Background(), e.deps, e.proj, Options{OSVRoot: osvRoot})
	}()
	if recovered != "boom" {
		t.Fatalf("the panic was not passed on: %v", recovered)
	}
	var status, errText, finished string
	if err := e.st.DB().QueryRow(`SELECT status, error, finished_at FROM scan`).Scan(&status, &errText, &finished); err != nil {
		t.Fatal(err)
	}
	if status != ScanFailed || !strings.Contains(errText, "panic") || !strings.Contains(errText, "boom") || finished == "" {
		t.Errorf("scan row = %q %q %q", status, errText, finished)
	}
	var result string
	if err := e.st.DB().QueryRow(`SELECT result FROM audit_event WHERE action='scan.finish'`).Scan(&result); err != nil || result != ScanFailed {
		t.Errorf("scan.finish result %q err %v", result, err)
	}
}

func TestEffectiveExcludeMergesDefaults(t *testing.T) {
	saved := append([]string{}, DefaultExclude...)
	got := EffectiveExclude(project.Project{Exclude: []string{"vendor", "build"}})
	want := []string{".git", "build", "node_modules", "vendor"}
	if !slices.Equal(got, want) {
		t.Errorf("EffectiveExclude = %v, want %v", got, want)
	}
	if !slices.Equal(DefaultExclude, saved) {
		t.Errorf("DefaultExclude was changed: %v", DefaultExclude)
	}
	if got := EffectiveExclude(project.Project{}); !slices.Equal(got, []string{".git", "node_modules", "vendor"}) {
		t.Errorf("without project exclusions: %v", got)
	}
}

func TestRunSkipsProjectExcludedFolders(t *testing.T) {
	e := newEnv(t, "project-a")
	e.proj.Exclude = []string{"web"}
	r := e.run(t)
	if len(r.Manifests) != 1 || r.Manifests[0].RelPath != "composer.lock" || r.New != 2 {
		t.Errorf("manifests %+v new %d", r.Manifests, r.New)
	}
}

// buildOSVDBWith builds a test database like buildOSVDB in a fresh folder,
// with the advisories named in replace (file name -> JSON) swapped in.
func buildOSVDBWith(t *testing.T, replace map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for _, eco := range testEcos {
		files, err := filepath.Glob(filepath.Join("testdata", "advisories", eco, "*.json"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no advisories for %s: %v", eco, err)
		}
		zp := osvdb.ZipPath(root, eco)
		if err := os.MkdirAll(filepath.Dir(zp), 0o755); err != nil {
			t.Fatal(err)
		}
		out, err := os.Create(zp)
		if err != nil {
			t.Fatal(err)
		}
		zw := zip.NewWriter(out)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if r, ok := replace[filepath.Base(f)]; ok {
				b = []byte(r)
			}
			w, err := zw.Create(filepath.Base(f))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(b); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := out.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// changedAdvisories makes ACME-2026-0001 medium instead of critical and
// gives ACME-2026-0002 a second fixed version.
var changedAdvisories = map[string]string{
	"ACME-2026-0001.json": `{"schema_version": "1.6.0", "id": "ACME-2026-0001", "modified": "2026-10-20T00:00:00Z",
		"summary": "Remote code execution in acme/vuln",
		"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"}],
		"affected": [{"package": {"ecosystem": "Packagist", "name": "acme/vuln"},
			"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}]}`,
	"ACME-2026-0002.json": `{"schema_version": "1.6.0", "id": "ACME-2026-0002", "modified": "2026-10-20T00:00:00Z",
		"summary": "Information disclosure in acme/vuln",
		"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"}],
		"affected": [{"package": {"ecosystem": "Packagist", "name": "acme/vuln"},
			"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.2"}, {"introduced": "2.0.0"}, {"fixed": "2.0.5"}]}]}]}`,
}

// decideFinding stores a decision in force on the finding with osvID, with
// the snapshot of what is known now, and moves it to decided, as
// decide.Repo.Set does (package decide imports scan, so its tests cannot be
// used here). It returns the finding id.
func (e env) decideFinding(t *testing.T, osvID, action, dueAt string) string {
	t.Helper()
	db := e.st.DB()
	var id, sev, fixed string
	if err := db.QueryRow(`SELECT id, severity_label, fixed_versions FROM finding WHERE osv_id = ?`, osvID).Scan(&id, &sev, &fixed); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO decision (id, finding_id, project_id, action, due_at, author, created_at, seen_severity, seen_fixed_versions)
		VALUES (?, ?, ?, ?, ?, 'cli', '2026-10-01T00:00:00Z', ?, ?)`, "d-"+osvID, id, e.proj.ID, action, dueAt, sev, fixed); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE finding SET status = ?, status_changed_at = '2026-10-01T00:00:00Z' WHERE id = ?`, StatusDecided, id); err != nil {
		t.Fatal(err)
	}
	return id
}

// decisionState returns the superseded_at and superseded_reason of the
// decision stored by decideFinding.
func (e env) decisionState(t *testing.T, osvID string) (at, reason string) {
	t.Helper()
	if err := e.st.DB().QueryRow(`SELECT superseded_at, superseded_reason FROM decision WHERE id = ?`, "d-"+osvID).Scan(&at, &reason); err != nil {
		t.Fatal(err)
	}
	return
}

func (e env) findingChangedAt(t *testing.T, osvID string) string {
	t.Helper()
	var at string
	if err := e.st.DB().QueryRow(`SELECT status_changed_at FROM finding WHERE osv_id = ?`, osvID).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

type supersededEvent struct {
	actor, target string
	evidence      map[string]any
}

func (e env) supersededEvents(t *testing.T) []supersededEvent {
	t.Helper()
	rows, err := e.st.DB().Query(`SELECT actor, target, evidence FROM audit_event WHERE action = 'decision.superseded' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []supersededEvent
	for rows.Next() {
		var ev supersededEvent
		var raw string
		if err := rows.Scan(&ev.actor, &ev.target, &raw); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal([]byte(raw), &ev.evidence)
		out = append(out, ev)
	}
	return out
}

func TestDecidedFindingStaysDecidedWhenUnchanged(t *testing.T) {
	e := newEnv(t, "project-a")
	e.run(t)
	e.decideFinding(t, "ACME-2026-0001", "fix", "")
	r := e.run(t)
	if r.Superseded != 0 || r.Still != 3 {
		t.Errorf("result = %+v", r)
	}
	if st := e.statuses(t); st["ACME-2026-0001"] != StatusDecided || st["ACME-2026-0002"] != StatusPending {
		t.Errorf("statuses = %v", st)
	}
	if at := e.findingChangedAt(t, "ACME-2026-0001"); at != "2026-10-01T00:00:00Z" {
		t.Errorf("status_changed_at moved to %s", at)
	}
	if at, reason := e.decisionState(t, "ACME-2026-0001"); at != "" || reason != "" {
		t.Errorf("decision superseded: %s %s", at, reason)
	}
	actionable, err := e.repo.ListFindings(context.Background(), e.proj.ID, "actionable")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range actionable {
		if f.OSVID == "ACME-2026-0001" {
			t.Error("a decided finding is listed as actionable")
		}
	}
	if len(actionable) != 2 {
		t.Errorf("actionable = %d findings", len(actionable))
	}
	if decided, _ := e.repo.ListFindings(context.Background(), e.proj.ID, StatusDecided); len(decided) != 1 {
		t.Errorf("decided = %+v", decided)
	}
	if evs := e.supersededEvents(t); len(evs) != 0 {
		t.Errorf("events = %+v", evs)
	}
}

func TestDecisionSupersededOnSeverityOrFixChange(t *testing.T) {
	e := newEnv(t, "project-a")
	e.run(t)
	sevID := e.decideFinding(t, "ACME-2026-0001", "ignore", "")
	fixID := e.decideFinding(t, "ACME-2026-0002", "fix", "")
	r, err := Run(context.Background(), e.deps, e.proj, Options{OSVRoot: buildOSVDBWith(t, changedAdvisories)})
	if err != nil {
		t.Fatal(err)
	}
	if r.Superseded != 2 {
		t.Errorf("superseded = %d", r.Superseded)
	}
	st := e.statuses(t)
	if st["ACME-2026-0001"] != StatusPending || st["ACME-2026-0002"] != StatusPending {
		t.Errorf("statuses = %v", st)
	}
	if at := e.findingChangedAt(t, "ACME-2026-0002"); at == "2026-10-01T00:00:00Z" {
		t.Error("status_changed_at not updated")
	}
	if at, reason := e.decisionState(t, "ACME-2026-0001"); at == "" || reason != "severity_changed" {
		t.Errorf("ACME-2026-0001 decision: %q %q", at, reason)
	}
	if at, reason := e.decisionState(t, "ACME-2026-0002"); at == "" || reason != "fixed_version_changed" {
		t.Errorf("ACME-2026-0002 decision: %q %q", at, reason)
	}
	evs := e.supersededEvents(t)
	want := map[string][2]string{sevID: {"severity_changed", "ignore"}, fixID: {"fixed_version_changed", "fix"}}
	if len(evs) != 2 {
		t.Fatalf("events = %+v", evs)
	}
	for _, ev := range evs {
		w, ok := want[ev.target]
		if !ok || ev.actor != "scan" || ev.evidence["finding_id"] != ev.target || ev.evidence["project_id"] != e.proj.ID ||
			ev.evidence["reason"] != w[0] || ev.evidence["previous_action"] != w[1] {
			t.Errorf("event = %+v", ev)
		}
	}
}

// goneThenBack decides ACME-2026-0001, makes it disappear, then brings it back
// with the given database.
func goneThenBack(t *testing.T, osvRootBack string) (env, Result) {
	t.Helper()
	e := newEnv(t, "project-a")
	lock := filepath.Join(e.proj.Path, "composer.lock")
	original, err := os.ReadFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	e.run(t)
	e.decideFinding(t, "ACME-2026-0001", "fix", "")
	fixed := []byte(`{"content-hash":"x","packages":[{"name":"acme/vuln","version":"1.0.2"},{"name":"acme/safe","version":"2.0.0"}],"packages-dev":[]}`)
	if err := os.WriteFile(lock, fixed, 0o644); err != nil {
		t.Fatal(err)
	}
	if r := e.run(t); r.Gone != 2 || r.Superseded != 0 {
		t.Fatalf("gone scan: %+v", r)
	}
	if st := e.statuses(t); st["ACME-2026-0001"] != StatusGone {
		t.Fatalf("statuses after disappearance = %v", st)
	}
	if at, reason := e.decisionState(t, "ACME-2026-0001"); at != "" || reason != "" {
		t.Fatalf("the decision of a gone finding was superseded: %s %s", at, reason)
	}
	if err := os.WriteFile(lock, original, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := Run(context.Background(), e.deps, e.proj, Options{OSVRoot: osvRootBack})
	if err != nil {
		t.Fatal(err)
	}
	return e, r
}

func TestDecidedGoneThenBackUnchangedIsDecided(t *testing.T) {
	e, r := goneThenBack(t, osvRoot)
	if r.Reappeared != 2 || r.Superseded != 0 {
		t.Errorf("result = %+v", r)
	}
	if st := e.statuses(t); st["ACME-2026-0001"] != StatusDecided || st["ACME-2026-0002"] != StatusPending {
		t.Errorf("statuses = %v", st)
	}
	if at, reason := e.decisionState(t, "ACME-2026-0001"); at != "" || reason != "" {
		t.Errorf("decision superseded: %s %s", at, reason)
	}
}

func TestDecidedGoneThenBackChangedIsPending(t *testing.T) {
	e, r := goneThenBack(t, buildOSVDBWith(t, changedAdvisories))
	if r.Reappeared != 2 || r.Superseded != 1 {
		t.Errorf("result = %+v", r)
	}
	if st := e.statuses(t); st["ACME-2026-0001"] != StatusPending {
		t.Errorf("statuses = %v", st)
	}
	if at, reason := e.decisionState(t, "ACME-2026-0001"); at == "" || reason != "reappeared_changed" {
		t.Errorf("decision: %q %q", at, reason)
	}
	if evs := e.supersededEvents(t); len(evs) != 1 || evs[0].evidence["reason"] != "reappeared_changed" || evs[0].evidence["previous_action"] != "fix" {
		t.Errorf("events = %+v", evs)
	}
}

func TestScanExpiresDueDefer(t *testing.T) {
	e := newEnv(t, "project-a")
	clock := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	e.deps.Now = func() time.Time { return clock }
	e.run(t)
	id := e.decideFinding(t, "ACME-2026-0001", "defer", clock.Add(time.Hour).Format(time.RFC3339))
	clock = clock.Add(time.Hour) // due_at == now: reached
	r := e.run(t)
	if r.Superseded != 1 {
		t.Errorf("result = %+v", r)
	}
	if st := e.statuses(t); st["ACME-2026-0001"] != StatusPending {
		t.Errorf("statuses = %v", st)
	}
	if at := e.findingChangedAt(t, "ACME-2026-0001"); at != clock.Format(time.RFC3339) {
		t.Errorf("status_changed_at = %s", at)
	}
	if at, reason := e.decisionState(t, "ACME-2026-0001"); at != clock.Format(time.RFC3339) || reason != "due_reached" {
		t.Errorf("decision: %q %q", at, reason)
	}
	evs := e.supersededEvents(t)
	if len(evs) != 1 || evs[0].actor != "scan" || evs[0].target != id || evs[0].evidence["reason"] != "due_reached" ||
		evs[0].evidence["previous_action"] != "defer" || evs[0].evidence["project_id"] != e.proj.ID {
		t.Errorf("events = %+v", evs)
	}
}

func TestScanDoesNotExpireFutureDefer(t *testing.T) {
	e := newEnv(t, "project-a")
	clock := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	e.deps.Now = func() time.Time { return clock }
	e.run(t)
	e.decideFinding(t, "ACME-2026-0001", "defer", clock.Add(48*time.Hour).Format(time.RFC3339))
	clock = clock.Add(47 * time.Hour)
	if r := e.run(t); r.Superseded != 0 {
		t.Errorf("result = %+v", r)
	}
	if st := e.statuses(t); st["ACME-2026-0001"] != StatusDecided {
		t.Errorf("statuses = %v", st)
	}
	if at, reason := e.decisionState(t, "ACME-2026-0001"); at != "" || reason != "" {
		t.Errorf("decision: %q %q", at, reason)
	}
}

func TestScanWritesTechAuto(t *testing.T) {
	e := newEnv(t, "project-a")
	lock := `{"_readme": ["fixture"], "content-hash": "0000000000000000000000000000000b", "packages": [
    {"name": "acme/vuln", "version": "1.0.0"}, {"name": "symfony/console", "version": "7.1.0"}], "packages-dev": []}`
	if err := os.WriteFile(filepath.Join(e.proj.Path, "composer.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	before := treeDigest(t, e.proj.Path)
	e.run(t)
	if after := treeDigest(t, e.proj.Path); after != before {
		t.Error("the project folder changed during the scan")
	}
	techAuto := func() []string {
		t.Helper()
		p, err := project.NewRepo(e.st).Get(context.Background(), e.proj.ID)
		if err != nil {
			t.Fatal(err)
		}
		return p.TechAuto
	}
	if got := techAuto(); !slices.Equal(got, []string{"node", "php", "symfony"}) {
		t.Errorf("tech_auto = %v", got)
	}
	// symfony is gone from the lockfile: the next scan forgets it.
	if err := os.WriteFile(filepath.Join(e.proj.Path, "composer.lock"), []byte(strings.Replace(lock, "symfony/console", "acme/safe", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	e.run(t)
	if got := techAuto(); !slices.Equal(got, []string{"node", "php"}) {
		t.Errorf("tech_auto after the change = %v", got)
	}
	// A folder with nothing to scan proves nothing: tech_auto is kept.
	os.Remove(filepath.Join(e.proj.Path, "composer.lock"))
	os.RemoveAll(filepath.Join(e.proj.Path, "web"))
	if r := e.run(t); r.Status != ScanEmpty {
		t.Fatalf("status = %s", r.Status)
	}
	if got := techAuto(); !slices.Equal(got, []string{"node", "php"}) {
		t.Errorf("tech_auto after an empty scan = %v", got)
	}
}

func TestScanDirWritesNothing(t *testing.T) {
	e := newEnv(t, "project-a")
	count := func(table string) int {
		var n int
		if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	e.run(t)
	scans, findings, manifests := count("scan"), count("finding"), count("scan_manifest")
	statuses := e.statuses(t)
	before := treeDigest(t, e.proj.Path)
	got, err := ScanDir(context.Background(), e.deps, e.proj.Path, nil, Options{OSVRoot: osvRoot})
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if len(got) == 0 || len(got) != findings {
		t.Errorf("ScanDir found %d findings, the stored scan %d", len(got), findings)
	}
	for _, f := range got {
		if _, ok := statuses[f.OSVID]; !ok {
			t.Errorf("ScanDir found %s, unknown to the stored scan", f.OSVID)
		}
	}
	if count("scan") != scans || count("finding") != findings || count("scan_manifest") != manifests {
		t.Error("ScanDir wrote scan, finding or manifest rows")
	}
	if !maps.Equal(e.statuses(t), statuses) {
		t.Error("ScanDir changed finding statuses")
	}
	if treeDigest(t, e.proj.Path) != before {
		t.Error("ScanDir wrote under the scanned folder")
	}

	// Without a database for an ecosystem it needs, nothing runs.
	if _, err := ScanDir(context.Background(), e.deps, e.proj.Path, nil, Options{OSVRoot: t.TempDir()}); err == nil {
		t.Error("ScanDir ran without the databases")
	}
	// A folder with no lockfile proves nothing.
	if _, err := ScanDir(context.Background(), e.deps, t.TempDir(), nil, Options{OSVRoot: osvRoot}); !errors.Is(err, ErrNoManifests) {
		t.Errorf("ScanDir of an empty folder: %v, want ErrNoManifests", err)
	}
}
