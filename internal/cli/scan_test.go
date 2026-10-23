package cli

import (
	"archive/zip"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/osvdb"
)

const scanTestdata = "../scan/testdata"

func buildTestOSVDB(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, eco := range osvdb.Ecosystems {
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

func TestScanJSONReportsPerProjectFailures(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "good"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "project", "add", t.TempDir(), "--name", "empty"); err != nil {
		t.Fatal(err)
	}
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
	if len(doc.Results) != 1 || len(doc.Failures) != 1 || doc.Failures[0]["project"] != "empty" ||
		!strings.Contains(doc.Failures[0]["error"], "michel project list") {
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
	if _, _, _, err := run(t, dir, "project", "add", t.TempDir(), "--name", "empty"); err != nil {
		t.Fatal(err)
	}
	_, out, errOut, err := run(t, dir, "scan", "--all", "--osv-db", db)
	if ExitCode(err) != 1 {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(errOut, "error: empty: Michel found no composer.lock") || strings.Contains(errOut, "{empty") {
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
