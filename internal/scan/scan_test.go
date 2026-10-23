package scan

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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

// buildOSVDB zips testdata/advisories/<eco>/*.json into <root>/osv-scalibr/<eco>/all.zip,
// one flat entry per advisory, the layout osv-scalibr's local matcher reads
// (it loads every entry whose name ends in ".json").
func buildOSVDB(root string) error {
	for _, eco := range osvdb.Ecosystems {
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

func TestRunNoManifestsKeepsFindingsAndFails(t *testing.T) {
	e := newEnv(t, "project-a")
	e.run(t)
	for _, f := range []string{"composer.lock", filepath.Join("web", "package-lock.json")} {
		if err := os.Remove(filepath.Join(e.proj.Path, f)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Run(context.Background(), e.deps, e.proj, Options{OSVRoot: osvRoot})
	if !errors.Is(err, ErrNoManifests) || r.Status != ScanFailed {
		t.Fatalf("err %v status %s", err, r.Status)
	}
	for id, s := range e.statuses(t) {
		if s != StatusNew {
			t.Errorf("%s is %s, want it untouched", id, s)
		}
	}
	var status, msg string
	if err := e.st.DB().QueryRow(`SELECT status, error FROM scan WHERE id=?`, r.ScanID).Scan(&status, &msg); err != nil ||
		status != "failed" || msg != "no composer.lock or package-lock.json found under "+e.proj.Path {
		t.Errorf("scan row %q %q %v", status, msg, err)
	}
	var ev string
	if err := e.st.DB().QueryRow(`SELECT evidence FROM audit_event WHERE action='scan.finish' ORDER BY rowid DESC LIMIT 1`).Scan(&ev); err != nil ||
		!strings.Contains(ev, `"reason":"no_manifests"`) {
		t.Errorf("evidence %q %v", ev, err)
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
