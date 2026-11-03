package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
)

// addBody is the JSON of POST /projects: a Windows path holds backslashes.
func addBody(t *testing.T, path, name string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"path": path, "name": name})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAddProjectFromThePage(t *testing.T) {
	f := newFixture(t, nil)
	dir := t.TempDir()
	resp, body := f.do("POST", "/api/v1/projects", testToken, addBody(t, dir, "my site"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add = %d %s", resp.StatusCode, body)
	}
	var v ProjectView
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	if v.Name != "my site" || v.FixLevel != 1 || v.LastScanStatus != "never" || v.Scanning || v.LastFailure != nil {
		t.Errorf("view = %+v", v)
	}
	want := policy.Defaults().Sovereignty.DataClassification
	if v.Classification != string(want) {
		t.Errorf("classification = %q, want the default of the policy %q", v.Classification, want)
	}
	p, err := project.NewRepo(f.st).Get(context.Background(), "my site")
	if err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(dir)
	if p.Path != real || !p.Active || p.TestCmd != "" || p.InstallCmd != "" {
		t.Errorf("project = %+v", p)
	}
	rows := f.auditRows("project.add")
	if len(rows) != 1 || rows[0].actor != "web" || rows[0].target != "my site" || rows[0].evidence["classification"] != string(want) {
		t.Errorf("audit = %+v", rows)
	}
	var result string
	if err := f.st.DB().QueryRow(`SELECT result FROM audit_event WHERE action = 'project.add'`).Scan(&result); err != nil || result != "ok" {
		t.Errorf("result = %q, %v", result, err)
	}
	// The same name, or the same folder under another name, is told plainly.
	for _, b := range []string{addBody(t, dir, "other"), addBody(t, t.TempDir(), "my site")} {
		resp, body = f.do("POST", "/api/v1/projects?lang=fr", testToken, b)
		var eb FixErrorBody
		if resp.StatusCode != http.StatusConflict || json.Unmarshal([]byte(body), &eb) != nil || eb.Code != "api.project.duplicate" || eb.Hint == "" {
			t.Errorf("duplicate = %d %s", resp.StatusCode, body)
		}
	}
}

func refusedCode(t *testing.T, f *fixture, path, name string) (int, FixErrorBody, string) {
	t.Helper()
	resp, body := f.do("POST", "/api/v1/projects?lang=fr", testToken, addBody(t, path, name))
	var eb FixErrorBody
	if err := json.Unmarshal([]byte(body), &eb); err != nil {
		t.Fatalf("%q: %v\n%s", path, err, body)
	}
	return resp.StatusCode, eb, body
}

func TestAddProjectRefusesRelativePathAndFile(t *testing.T) {
	f := newFixture(t, nil)
	dir := t.TempDir()
	file := filepath.Join(dir, "composer.lock")
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(dir, "a")
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ path, code string }{
		{"", "api.project.relative_path"},
		{"some/folder", "api.project.relative_path"},
		{`..\..\Windows`, "api.project.relative_path"},
		{"../../etc", "api.project.relative_path"},
		// A ".." is refused even when the folder exists and the path is complete.
		{inside + string(filepath.Separator) + ".." + string(filepath.Separator) + "a", "api.project.relative_path"},
		{file, "api.project.not_dir"},
		{filepath.Join(dir, "missing"), "api.project.not_dir"},
	}
	for _, c := range cases {
		st, eb, body := refusedCode(t, f, c.path, "new")
		if st != http.StatusBadRequest || eb.Code != c.code || eb.Error == "" || eb.Hint == "" {
			t.Errorf("%q = %d %s", c.path, st, body)
		}
	}
	names := []string{"", " ", "a/b", `a\b`, "..", "a..b", "-x", "a\nb", "a<b>", strings.Repeat("x", 65)}
	for _, name := range names {
		st, eb, body := refusedCode(t, f, dir, name)
		if st != http.StatusBadRequest || eb.Code != "api.project.bad_name" || eb.Hint == "" {
			t.Errorf("name %q = %d %s", name, st, body)
		}
	}
	accepted := []string{"été 2026", "site_web-2.0", "x"}
	for _, name := range accepted {
		if st, _, body := refusedCode(t, f, t.TempDir(), name); st != http.StatusCreated {
			t.Errorf("name %q = %d %s", name, st, body)
		}
	}
	// Every refusal leaves a trace, and no project.
	var denied, n int
	_ = f.st.DB().QueryRow(`SELECT COUNT(*) FROM audit_event WHERE action = 'project.add' AND actor = 'web' AND result = 'denied'`).Scan(&denied)
	if denied != len(cases)+len(names) {
		t.Errorf("denied audit rows = %d, want %d", denied, len(cases)+len(names))
	}
	_ = f.st.DB().QueryRow(`SELECT COUNT(*) FROM project`).Scan(&n)
	if n != 1+len(accepted) {
		t.Errorf("projects = %d, want the demo and the %d accepted", n, len(accepted))
	}
}

// The folders of the system, a disk root, the home folder and Michel's own
// data never become a project by surprise: a later fix would copy them.
func TestAddProjectRefusesWhatIsNotAProject(t *testing.T) {
	home := t.TempDir()
	f := newFixtureWith(t, nil, func(f *fixture) { f.deps.Servers.Home = home })
	root := filepath.VolumeName(home) + string(filepath.Separator)
	inData := filepath.Join(f.dir, "inside")
	if err := os.Mkdir(inData, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := []string{root, home, filepath.Dir(home), f.dir, inData}
	var sysFound string
	for _, sys := range systemFolders() {
		if fi, err := os.Stat(sys); err != nil || !fi.IsDir() {
			continue
		}
		sysFound = sys
		paths = append(paths, sys)
		if entries, err := os.ReadDir(sys); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					paths = append(paths, filepath.Join(sys, e.Name()))
					break
				}
			}
		}
	}
	if sysFound == "" {
		t.Fatal("no system folder found on this computer")
	}
	if runtime.GOOS == "windows" {
		paths = append(paths, `\\example.test\share`, `//example.test/share`, sysFound+`.`, home+`:stream`)
	} else {
		paths = append(paths, "//etc")
	}
	for _, path := range paths {
		st, eb, body := refusedCode(t, f, path, "new")
		if st != http.StatusBadRequest || eb.Code != "api.project.forbidden_path" || eb.Hint == "" {
			t.Errorf("%q = %d %s", path, st, body)
		}
		if strings.Contains(body, path) || strings.Contains(body, strings.ReplaceAll(path, `\`, `\\`)) {
			t.Errorf("the answer holds the path: %s", body)
		}
	}
	// The folder under a link counts, not the name of the link.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(sysFound, link); err != nil {
		t.Logf("no symbolic link here: %v", err)
		return
	}
	if st, eb, body := refusedCode(t, f, link, "new"); st != http.StatusBadRequest || eb.Code != "api.project.forbidden_path" {
		t.Errorf("link = %d %s", st, body)
	}
}

func TestAddProjectAnswerHasNoAbsolutePath(t *testing.T) {
	f := newFixture(t, nil)
	dir := t.TempDir()
	for _, c := range []struct{ path, name string }{
		{dir, "good"},
		{dir, "bad/name"},
		{filepath.Join(dir, "missing"), "x"},
		{dir, "demo"},
		{"relative/" + filepath.Base(dir), "y"},
	} {
		_, body := f.do("POST", "/api/v1/projects", testToken, addBody(t, c.path, c.name))
		for _, banned := range []string{dir, filepath.ToSlash(dir), strings.ReplaceAll(dir, `\`, `\\`)} {
			if strings.Contains(body, banned) {
				t.Errorf("%+v: answer holds %q: %s", c, banned, body)
			}
		}
	}
	body := f.get("/api/v1/projects", nil)
	if strings.Contains(body, strings.ReplaceAll(dir, `\`, `\\`)) || strings.Contains(body, filepath.ToSlash(dir)) {
		t.Errorf("list holds the path: %s", body)
	}
}

// R13: the page never declares a command to run, nor a fix level.
func TestAddProjectCannotSetTestCmdOrLevel(t *testing.T) {
	f := newFixture(t, nil)
	dir := t.TempDir()
	for _, extra := range []string{`"test_cmd":"calc"`, `"install_cmd":"calc"`, `"fix_level":3`, `"auto_fix_minor":true`, `"classification":"public"`} {
		b, _ := json.Marshal(dir)
		resp, body := f.do("POST", "/api/v1/projects", testToken, `{"path":`+string(b)+`,"name":"new",`+extra+`}`)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d %s", extra, resp.StatusCode, body)
		}
	}
	if _, err := project.NewRepo(f.st).Get(context.Background(), "new"); !errors.Is(err, project.ErrNotFound) {
		t.Errorf("project = %v", err)
	}
	if rows := f.auditRows("project.add"); len(rows) != 0 {
		t.Errorf("audit = %+v", rows)
	}
}

// scanFixture is a fixture whose ScanProject waits for the test and returns
// what it is told.
type scanFixture struct {
	*fixture
	release chan error
	calls   atomic.Int32
	got     atomic.Value
}

func newScanFixture(t *testing.T) *scanFixture {
	t.Helper()
	sf := &scanFixture{release: make(chan error)}
	sf.fixture = newFixtureWith(t, nil, func(f *fixture) {
		f.deps.ScanProject = func(ctx context.Context, p project.Project) error {
			sf.calls.Add(1)
			sf.got.Store(p.Name)
			select {
			case err := <-sf.release:
				return err
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
	return sf
}

// viewOf is the project's view, with its state of the moment.
func (f *fixture) viewOf(lang, name string) ProjectView {
	f.t.Helper()
	var list []ProjectView
	f.get("/api/v1/projects?lang="+lang, &list)
	for _, v := range list {
		if v.Name == name {
			return v
		}
	}
	f.t.Fatalf("no project %s in %+v", name, list)
	return ProjectView{}
}

// waitEnd waits until the scan of the project is over.
func (f *fixture) waitEnd(lang, name string) ProjectView {
	f.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if v := f.viewOf(lang, name); !v.Scanning {
			return v
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.t.Fatal("the scan did not end")
	return ProjectView{}
}

func TestScanRunsInBackgroundOnce(t *testing.T) {
	f := newScanFixture(t)
	resp, body := f.do("POST", "/api/v1/projects/demo/scan", testToken, "")
	if resp.StatusCode != http.StatusAccepted || !strings.Contains(body, `"started":true`) {
		t.Fatalf("scan = %d %s", resp.StatusCode, body)
	}
	if v := f.viewOf("en", "demo"); !v.Scanning || v.LastFailure != nil {
		t.Errorf("while it runs: %+v", v)
	}
	resp, body = f.do("POST", "/api/v1/projects/demo/scan?lang=fr", testToken, "")
	var eb FixErrorBody
	if resp.StatusCode != http.StatusConflict || json.Unmarshal([]byte(body), &eb) != nil || eb.Code != "api.project.scan_running" ||
		eb.Error != i18n.T(i18n.FR, "api.project.scan_running") || eb.Hint == "" {
		t.Errorf("second click = %d %s", resp.StatusCode, body)
	}
	f.release <- nil
	if v := f.waitEnd("en", "demo"); v.LastFailure != nil {
		t.Errorf("after it ended: %+v", v)
	}
	if n := f.calls.Load(); n != 1 {
		t.Errorf("scans = %d", n)
	}
	if f.got.Load() != "demo" {
		t.Errorf("scanned %v", f.got.Load())
	}
	rows := f.auditRows("project.scan")
	if len(rows) != 1 || rows[0].actor != "web" || rows[0].target != "demo" {
		t.Errorf("audit = %+v", rows)
	}
	// Once ended, it can run again.
	if resp, body := f.do("POST", "/api/v1/projects/demo/scan", testToken, ""); resp.StatusCode != http.StatusAccepted {
		t.Errorf("again = %d %s", resp.StatusCode, body)
	}
	f.release <- nil
	f.waitEnd("en", "demo")
}

func TestScanOfUnknownProjectAndWithoutService(t *testing.T) {
	f := newScanFixture(t)
	if resp, body := f.do("POST", "/api/v1/projects/nobody/scan", testToken, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown = %d %s", resp.StatusCode, body)
	}
	if n := f.calls.Load(); n != 0 {
		t.Errorf("scans = %d", n)
	}
	plain := newFixture(t, nil)
	resp, body := plain.do("POST", "/api/v1/projects/demo/scan", testToken, "")
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "api.project.scan_unavailable") {
		t.Errorf("no service = %d %s", resp.StatusCode, body)
	}
}

// endWith starts a scan that ends with err and returns the project's view.
func endWith(t *testing.T, err error, lang string) ProjectView {
	t.Helper()
	f := newScanFixture(t)
	if resp, body := f.do("POST", "/api/v1/projects/demo/scan", testToken, ""); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("scan = %d %s", resp.StatusCode, body)
	}
	f.release <- err
	return f.waitEnd(lang, "demo")
}

func TestScanReportsMissingDatabase(t *testing.T) {
	v := endWith(t, osvdb.ErrDatabaseMissing, "fr")
	if v.LastFailure == nil || v.LastFailure.OK || v.LastFailure.Code != "api.project.no_database" || v.LastFailure.At == "" {
		t.Fatalf("view = %+v", v)
	}
	if !strings.Contains(v.LastFailure.Error, "liste des failles") || !strings.Contains(v.LastFailure.Hint, "Télécharge") {
		t.Errorf("failure = %+v", v.LastFailure)
	}
}

func TestScanReportsNothingToScan(t *testing.T) {
	v := endWith(t, ErrNothingToScan, "en")
	if v.LastFailure == nil || v.LastFailure.Code != "api.project.nothing_to_scan" || v.LastFailure.Hint == "" {
		t.Fatalf("view = %+v", v)
	}
}

// Whatever the scan said, its words never reach the page: only a code.
func TestScanFailureHoldsNoPath(t *testing.T) {
	v := endWith(t, errors.New(`open C:\secret-folder\composer.lock: denied`), "en")
	b, _ := json.Marshal(v)
	if v.LastFailure == nil || v.LastFailure.Code != "api.project.scan_failed" || strings.Contains(string(b), "secret-folder") {
		t.Errorf("view = %s", b)
	}
}

func TestProjectRunRoutesNeedTheToken(t *testing.T) {
	f := newScanFixture(t)
	dir := t.TempDir()
	for _, token := range []string{"", "wrong"} {
		for _, c := range []struct{ method, path, body string }{
			{"POST", "/api/v1/projects", addBody(t, dir, "new")},
			{"POST", "/api/v1/projects/demo/scan", ""},
		} {
			if resp, body := f.do(c.method, c.path, token, c.body); resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s with token %q = %d %s", c.path, token, resp.StatusCode, body)
			}
		}
	}
	if n := f.calls.Load(); n != 0 {
		t.Errorf("scans = %d", n)
	}
	if _, err := project.NewRepo(f.st).Get(context.Background(), "new"); !errors.Is(err, project.ErrNotFound) {
		t.Errorf("project = %v", err)
	}
}

// Every refusal has its sentence and its hint in both languages.
func TestProjectCodesHaveTheirSentences(t *testing.T) {
	for _, key := range []string{"api.project.not_dir", "api.project.relative_path", "api.project.duplicate", "api.project.bad_name",
		"api.project.forbidden_path", "api.project.no_database", "api.project.nothing_to_scan", "api.project.scan_failed",
		"api.project.scan_running", "api.project.scan_unavailable"} {
		if !i18n.Has(key) || !i18n.Has(key+"_hint") {
			t.Errorf("%s: sentence or hint missing", key)
		}
	}
}
