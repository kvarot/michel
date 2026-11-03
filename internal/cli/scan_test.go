package cli

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/osvdb"
)

const scanTestdata = "../scan/testdata"

func buildTestOSVDB(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, eco := range []string{"Packagist", "npm"} {
		files, err := filepath.Glob(filepath.Join(scanTestdata, "advisories", eco, "*.json"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no advisories for %s", eco)
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
			b, _ := os.ReadFile(f)
			w, _ := zw.Create(filepath.Base(f))
			w.Write(b)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		out.Close()
	}
	return root
}

// copyProject copies testdata/<name> to a fresh folder and returns it.
func copyProject(t *testing.T, name string) string {
	t.Helper()
	src, dst := filepath.Join(scanTestdata, name), t.TempDir()
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
	return dst
}

func TestScanAndFindingsEndToEnd(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	_, out, _, err := run(t, dir, "scan", "--project", "demo", "--osv-db", db)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, want := range []string{"project", "critical/high/medium/low/unknown", "demo", "1/1/1/0/0", "3/0",
		"Michel found 3 new findings in demo, 1 critical, analyzed 3 findings. Next: michel findings --project demo --severity critical"} {
		if !strings.Contains(out, want) {
			t.Errorf("scan output lacks %q:\n%s", want, out)
		}
	}
	_, out, _, err = run(t, dir, "findings", "--project", "demo", "--severity", "critical")
	if err != nil || !strings.Contains(out, "acme/vuln") || !strings.Contains(out, "ACME-2026-0001") ||
		!strings.Contains(out, "1.0.1") || strings.Contains(out, "vuln-pkg") {
		t.Errorf("findings: %v\n%s", err, out)
	}
	_, out, _, err = run(t, dir, "findings", "--project", "demo", "--status", "pending")
	if err != nil || strings.Contains(out, "ACME") {
		t.Errorf("no finding should be pending yet: %v\n%s", err, out)
	}
	_, out, _, err = run(t, dir, "scan", "--all", "--osv-db", db, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Results  []map[string]any `json:"results"`
		Failures []any            `json:"failures"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Results) != 1 || len(doc.Failures) != 0 || doc.Results[0]["status"] != "ok" || doc.Results[0]["new"].(float64) != 0 {
		t.Errorf("json = %v %s", err, out)
	}
	if rows := auditRows(t, dir, "scan.finish"); len(rows) != 2 || rows[0].result != "ok" {
		t.Errorf("scan.finish = %+v", rows)
	}
	if rows := auditRows(t, dir, "scan.manifest"); len(rows) != 4 {
		t.Errorf("scan.manifest = %d rows", len(rows))
	}
}

func TestScanNeedsProjectOrAll(t *testing.T) {
	_, _, _, err := run(t, t.TempDir(), "scan")
	if err == nil || !strings.Contains(err.Error(), "--project") || !strings.Contains(err.Error(), "--all") {
		t.Errorf("err = %v", err)
	}
}

func TestScanMissingDatabaseSaysWhatToDo(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := run(t, dir, "scan", "--project", "demo", "--osv-db", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "michel db update") {
		t.Errorf("err = %v", err)
	}
}

func TestScanCorruptManifestExitsOne(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-b"), "--name", "broken"); err != nil {
		t.Fatal(err)
	}
	_, out, errOut, err := run(t, dir, "scan", "--project", "broken", "--osv-db", db)
	if err == nil || ExitCode(err) != 1 {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(errOut, "cannot parse composer.lock") || !strings.Contains(out, "broken") {
		t.Errorf("stdout %q stderr %q", out, errOut)
	}
}

// addVanished registers a folder under name, then deletes the folder: its
// scan fails.
func addVanished(t *testing.T, dir, name string) {
	t.Helper()
	gone := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(gone, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "project", "add", gone, "--name", name); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(gone); err != nil {
		t.Fatal(err)
	}
}

func TestScanAllEmptyProjectExitZero(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	empty := t.TempDir()
	if _, _, _, err := run(t, dir, "project", "add", empty, "--name", "acme-empty"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	_, out, errOut, err := run(t, dir, "scan", "--all", "--osv-db", db)
	if err != nil {
		t.Fatalf("scan --all: %v\n%s\n%s", err, out, errOut)
	}
	if want := i18n.T(i18n.EN, "cli.scan.empty", "acme-empty", empty); !strings.Contains(out, want) {
		t.Errorf("stdout lacks %q:\n%s", want, out)
	}
	if !strings.Contains(out, "Michel found 3 new findings in demo") || strings.Contains(errOut, "error:") {
		t.Errorf("stdout %q stderr %q", out, errOut)
	}
	if rows := auditRows(t, dir, "scan.finish"); len(rows) != 2 {
		t.Errorf("scan.finish = %+v", rows)
	}
	_, out, _, err = run(t, dir, "scan", "--all", "--osv-db", db, "--json")
	if err != nil || !strings.Contains(out, `"status":"empty"`) || !strings.Contains(out, `"failures":[]`) {
		t.Errorf("json: %v\n%s", err, out)
	}
}

func TestScanAllDisabledEcosystemExitZero(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "source", "disable", "osv.npm"); err != nil {
		t.Fatal(err)
	}
	_, out, errOut, err := run(t, dir, "scan", "--all", "--osv-db", db)
	if err != nil {
		t.Fatalf("scan --all: %v\n%s\n%s", err, out, errOut)
	}
	if strings.Contains(errOut, "ecosystem disabled") || !strings.Contains(out, "Michel found 2 new findings in demo") {
		t.Errorf("stdout %q stderr %q", out, errOut)
	}
	if rows := auditRows(t, dir, "scan.finish"); len(rows) != 1 || rows[0].result != "partial" {
		t.Errorf("scan.finish = %+v", rows)
	}
}

func TestScanProjectEmptyExitOne(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	empty := t.TempDir()
	if _, _, _, err := run(t, dir, "project", "add", empty, "--name", "acme-empty"); err != nil {
		t.Fatal(err)
	}
	// The user aimed at this folder: nothing to scan there is worth an exit 1.
	_, out, _, err := run(t, dir, "scan", "--project", "acme-empty", "--osv-db", db)
	if ExitCode(err) != 1 {
		t.Fatalf("err = %v", err)
	}
	if want := i18n.T(i18n.EN, "cli.scan.empty", "acme-empty", empty); !strings.Contains(out, want) {
		t.Errorf("stdout lacks %q:\n%s", want, out)
	}
}

func TestScanJSONReportsPerProjectFailures(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "good"); err != nil {
		t.Fatal(err)
	}
	addVanished(t, dir, "vanished")
	_, out, _, err := run(t, dir, "scan", "--all", "--osv-db", db, "--json")
	if ExitCode(err) != 1 || err == nil {
		t.Fatalf("err = %v", err)
	}
	var doc struct {
		Results  []map[string]any    `json:"results"`
		Failures []map[string]string `json:"failures"`
	}
	if jerr := json.Unmarshal([]byte(out), &doc); jerr != nil {
		t.Fatal(jerr, out)
	}
	if len(doc.Results) != 1 || len(doc.Failures) != 1 || doc.Failures[0]["project"] != "vanished" ||
		!strings.Contains(doc.Failures[0]["error"], "cannot read the folder") {
		t.Errorf("doc = %+v", doc)
	}
}

func TestScanWarnsAboutProjectScannerConfig(t *testing.T) {
	dir, db, proj := t.TempDir(), buildTestOSVDB(t), copyProject(t, "project-a")
	if err := os.WriteFile(filepath.Join(proj, "web", "osv-scanner.toml"), []byte("[[IgnoredVulns]]\nid = \"ACME-2026-0101\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "project", "add", proj, "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	_, out, errOut, err := run(t, dir, "scan", "--project", "demo", "--osv-db", db)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	want := "Warning: " + filepath.Join(proj, "web", "osv-scanner.toml") + " contains osv-scanner ignore rules; Michel does not apply them. " +
		"Decide on findings with michel decide instead.\n"
	if !strings.Contains(errOut, want) {
		t.Errorf("stderr lacks the warning:\n%s", errOut)
	}
	if !strings.Contains(out, "Michel found 3 new findings in demo") {
		t.Errorf("the ignore rule was applied:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "osv-scanner-override.toml")); err != nil {
		t.Errorf("override config not in the data dir: %v", err)
	}
	if rows := auditRows(t, dir, "scan.finish"); len(rows) != 1 || rows[0].evidence["ignored_config_files"] == nil {
		t.Errorf("scan.finish = %+v", rows)
	}
}

func TestScanTextReportsFailuresPlainly(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	addVanished(t, dir, "vanished")
	_, out, errOut, err := run(t, dir, "scan", "--all", "--osv-db", db)
	if ExitCode(err) != 1 {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(errOut, "error: vanished: Michel cannot read the folder") || strings.Contains(errOut, "{vanished") {
		t.Errorf("stderr = %q", errOut)
	}
	if strings.Contains(out, "critical/high") || !strings.HasSuffix(out, "Michel could not scan any project. Read the errors above, fix them, then run the scan again.\n") {
		t.Errorf("stdout = %q", out)
	}

	// One project scanned, one failed: table, summary, then the failure count.
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "good"); err != nil {
		t.Fatal(err)
	}
	_, out, _, _ = run(t, dir, "scan", "--all", "--osv-db", db)
	if !strings.Contains(out, "critical/high") || !strings.Contains(out, "Michel found 3 new findings in good") ||
		!strings.HasSuffix(out, "Michel could not scan 1 project; read the errors above, fix them, then run the scan again.\n") {
		t.Errorf("stdout = %q", out)
	}
}

func TestScannerLogHandlerKeepsWarningsOnly(t *testing.T) {
	var buf strings.Builder
	h := scannerLogHandler(&buf)
	l := slog.New(h)
	l.Info("chatter")
	l.Warn("unknown key in config")
	if s := buf.String(); strings.Contains(s, "chatter") || !strings.Contains(s, "unknown key in config") {
		t.Errorf("log = %q", s)
	}
}

func TestFindingsHelpSaysGoneIsNotAFix(t *testing.T) {
	_, out, _, err := run(t, t.TempDir(), "findings", "--help")
	if err != nil || !strings.Contains(out, "no longer seen at the last scan, not proof of a fix") || strings.Contains(out, "fixed or removed") {
		t.Errorf("out=%q err=%v", out, err)
	}
}

// scanOutputWas is the output of michel scan captured on the code before
// scanOneProject was extracted (commit ebed3cf), then pasted here: comparing
// with a run of the new code would prove nothing.
var scanOutputWas = map[string]string{
	"first": `exit 0 
--- stdout
project  manifests  packages  findings  critical/high/medium/low/unknown  new/gone
demo     2          3         3         1/1/1/0/0                         3/0
Michel found 3 new findings in demo, 1 critical, analyzed 3 findings. Next: michel findings --project demo --severity critical
--- stderr
`,
	"again_no_analyze": `exit 0 
--- stdout
project  manifests  packages  findings  critical/high/medium/low/unknown  new/gone
demo     2          3         3         1/1/1/0/0                         0/0
Michel found no new findings in demo, analysis skipped. Next: michel findings --project demo
--- stderr
`,
	"empty": `exit 1 the scan did not complete cleanly
--- stdout
Nothing to scan in nothing: Michel found no composer.lock, package-lock.json, yarn.lock or pnpm-lock.yaml under <EMPTY>. This is not an error, and the earlier findings of the project are kept. If the project has dependencies, check the path with 'michel project list', and check that the lockfile is not under an excluded folder (node_modules, vendor, .git).
--- stderr
`,
	"corrupt": `exit 1 the scan did not complete cleanly
--- stdout
project  manifests  packages  findings  critical/high/medium/low/unknown  new/gone
broken   1          0         0         0/0/0/0/0                         0/0
Michel found no new findings in broken, analyzed 0 findings. Next: michel findings --project broken
--- stderr
warning: broken: cannot parse composer.lock: invalid character 't' looking for beginning of object key string. Fix or remove the file, then scan again; its earlier findings were kept.
`,
	"all": `exit 1 the scan did not complete cleanly
--- stdout
Nothing to scan in nothing: Michel found no composer.lock, package-lock.json, yarn.lock or pnpm-lock.yaml under <EMPTY>. This is not an error, and the earlier findings of the project are kept. If the project has dependencies, check the path with 'michel project list', and check that the lockfile is not under an excluded folder (node_modules, vendor, .git).
project  manifests  packages  findings  critical/high/medium/low/unknown  new/gone
broken   1          0         0         0/0/0/0/0                         0/0
demo     2          3         3         1/1/1/0/0                         0/0
Michel found no new findings in broken, analyzed 0 findings. Next: michel findings --project broken
Michel found no new findings in demo, analyzed 3 findings. Next: michel findings --project demo
--- stderr
warning: broken: cannot parse composer.lock: invalid character 't' looking for beginning of object key string. Fix or remove the file, then scan again; its earlier findings were kept.
`,
	"all_json": `exit 1 the scan did not complete cleanly
--- stdout
{"results":[{"scan_id":"<ID>","project":"broken","status":"partial","manifests":[{"rel_path":"composer.lock","ecosystem":"Packagist","lock_sha256":"<SHA>","packages":0,"findings":0,"error":"cannot parse composer.lock: invalid character 't' looking for beginning of object key string"}],"new":0,"still":0,"reappeared":0,"gone":0,"superseded":0,"by_severity":{},"errors":["cannot parse composer.lock: invalid character 't' looking for beginning of object key string"]},{"scan_id":"<ID>","project":"demo","status":"ok","manifests":[{"rel_path":"composer.lock","ecosystem":"Packagist","lock_sha256":"<SHA>","packages":2,"findings":2},{"rel_path":"web/package-lock.json","ecosystem":"npm","lock_sha256":"<SHA>","packages":1,"findings":1}],"new":0,"still":3,"reappeared":0,"gone":0,"superseded":0,"by_severity":{"critical":1,"high":1,"medium":1}},{"scan_id":"<ID>","project":"nothing","status":"empty","manifests":null,"new":0,"still":0,"reappeared":0,"gone":0,"superseded":0,"by_severity":{}}],"failures":[],"plugins":[]}
--- stderr
`,
	"no_database": `exit 1 Michel cannot scan demo: offline database missing for Packagist: run "michel db update". A scan never downloads anything; fetch the databases first
--- stdout
--- stderr
`,
	"french": `exit 0 
--- stdout
project  manifests  packages  findings  critical/high/medium/low/unknown  new/gone
demo     2          3         3         1/1/1/0/0                         0/0
Michel n'a trouvé aucune nouvelle faille dans demo, 3 failles analysées. Ensuite : michel findings --project demo
--- stderr
`,
	"plugin": `exit 0 
--- stdout
project  manifests  packages  findings  critical/high/medium/low/unknown  new/gone
demo     2          3         3         1/1/1/0/0                         3/0
Michel found 3 new findings in demo, 1 critical, analyzed 3 findings. Next: michel findings --project demo --severity critical
trivy found 1 new finding in demo. Next: michel findings --project demo
--- stderr
`,
	"plugin_json": `exit 0 
--- stdout
{"results":[{"scan_id":"<ID>","project":"demo","status":"ok","manifests":[{"rel_path":"composer.lock","ecosystem":"Packagist","lock_sha256":"<SHA>","packages":2,"findings":2},{"rel_path":"web/package-lock.json","ecosystem":"npm","lock_sha256":"<SHA>","packages":1,"findings":1}],"new":0,"still":3,"reappeared":0,"gone":0,"superseded":0,"by_severity":{"critical":1,"high":1,"medium":1}}],"failures":[],"plugins":[{"project":"demo","key":"plugin.trivy","run_id":"<ID>","new":0,"still":1,"gone":0,"skipped_known":0}]}
--- stderr
`,
}

// normScanOutput takes out what changes from one run to the next: the temporary
// folders, the ids and the times.
func normScanOutput(s string, folders map[string]string) string {
	for f, name := range folders {
		s = strings.ReplaceAll(s, f, name)
		s = strings.ReplaceAll(s, strings.ReplaceAll(f, "\\", "\\\\"), name)
	}
	s = regexp.MustCompile(`[0-9A-HJKMNP-TV-Z]{26}`).ReplaceAllString(s, "<ID>")
	s = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T[0-9:.]+Z`).ReplaceAllString(s, "<TIME>")
	s = regexp.MustCompile(`"lock_sha256":"[0-9a-f]{64}"`).ReplaceAllString(s, `"lock_sha256":"<SHA>"`)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var kept []string
	for _, l := range strings.SplitAfter(s, "\n") {
		// The scanner's own log lines and the policy line hold a time or a path
		// of this computer.
		if !strings.HasPrefix(l, "time=") && !strings.HasPrefix(l, "policy:") && !strings.HasPrefix(l, "politique") {
			kept = append(kept, l)
		}
	}
	return strings.Join(kept, "")
}

// With a plugin turned on, whose lines come after the summaries.
func TestScanOutputUnchangedWithAPlugin(t *testing.T) {
	dir, db, path := provableProject(t, true)
	folders := map[string]string{path: "<A>", db: "<DB>", dir: "<DATA>"}
	for _, c := range []struct {
		name string
		args []string
	}{
		{"plugin", []string{"scan", "--project", "demo", "--osv-db", db}},
		{"plugin_json", []string{"scan", "--project", "demo", "--osv-db", db, "--json"}},
	} {
		_, out, errOut, err := run(t, dir, c.args...)
		code, message := 0, ""
		if err != nil {
			code, message = ExitCode(err), normScanOutput(err.Error(), folders)
		}
		got := fmt.Sprintf("exit %d %s\n--- stdout\n%s--- stderr\n%s", code, message, normScanOutput(out, folders), normScanOutput(errOut, folders))
		if want := scanOutputWas[c.name]; got != want {
			t.Errorf("%s changed:\n%s\n--- it was\n%s", c.name, got, want)
		}
	}
}

func TestScanOutputUnchanged(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	a, b, empty := copyProject(t, "project-a"), copyProject(t, "project-b"), t.TempDir()
	folders := map[string]string{a: "<A>", b: "<B>", empty: "<EMPTY>", db: "<DB>", dir: "<DATA>"}
	for name, path := range map[string]string{"demo": a, "broken": b, "nothing": empty} {
		if _, _, _, err := run(t, dir, "project", "add", path, "--name", name); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name string
		args []string
	}{
		{"first", []string{"scan", "--project", "demo", "--osv-db", db}},
		{"again_no_analyze", []string{"scan", "--project", "demo", "--osv-db", db, "--no-analyze"}},
		{"empty", []string{"scan", "--project", "nothing", "--osv-db", db}},
		{"corrupt", []string{"scan", "--project", "broken", "--osv-db", db}},
		{"all", []string{"scan", "--all", "--osv-db", db}},
		{"all_json", []string{"scan", "--all", "--osv-db", db, "--json"}},
		{"no_database", []string{"scan", "--project", "demo", "--osv-db", t.TempDir()}},
		{"french", []string{"--lang", "fr", "scan", "--project", "demo", "--osv-db", db}},
	} {
		_, out, errOut, err := run(t, dir, c.args...)
		code, message := 0, ""
		if err != nil {
			code, message = ExitCode(err), normScanOutput(err.Error(), folders)
		}
		got := fmt.Sprintf("exit %d %s\n--- stdout\n%s--- stderr\n%s", code, message, normScanOutput(out, folders), normScanOutput(errOut, folders))
		if want := scanOutputWas[c.name]; got != want {
			t.Errorf("%s changed:\n%s\n--- it was\n%s", c.name, got, want)
		}
	}
}
