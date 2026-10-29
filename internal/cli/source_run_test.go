package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/store"
)

const codeqlReport = "../plugin/testdata/codeql.sarif"

func TestSourceRunWithInput(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := run(t, dir, "project", "add", t.TempDir(), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	// A plugin that is off reads nothing.
	if _, _, _, err := run(t, dir, "source", "run", "plugin.codeql", "--project", "demo", "--input", codeqlReport); err == nil ||
		!strings.Contains(err.Error(), "michel source enable plugin.codeql") {
		t.Errorf("off plugin: %v", err)
	}
	if _, _, _, err := run(t, dir, "source", "enable", "plugin.codeql"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "source", "run", "osv.npm", "--project", "demo", "--input", codeqlReport); err == nil ||
		!strings.Contains(err.Error(), "not a plugin") {
		t.Errorf("not a plugin: %v", err)
	}
	if _, _, _, err := run(t, dir, "source", "run", "plugin.codeql", "--project", "demo"); err == nil ||
		!strings.Contains(err.Error(), "--input") {
		t.Errorf("codeql without --input: %v", err)
	}
	_, out, _, err := run(t, dir, "source", "run", "plugin.codeql", "--project", "demo", "--input", codeqlReport)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "codeql found 2 new findings in demo. Next: michel findings --project demo") {
		t.Errorf("output = %q", out)
	}
	_, out, _, err = run(t, dir, "source", "run", "plugin.codeql", "--project", "demo", "--input", codeqlReport, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc["still"] != 2.0 || doc["new"] != 0.0 || doc["key"] != "plugin.codeql" {
		t.Errorf("json = %v %s", err, out)
	}
	if strings.Contains(out, "codeql.sarif") || strings.Contains(out, "report") {
		t.Errorf("the report path reached --json: %s", out)
	}
	_, out, _, err = run(t, dir, "findings", "--project", "demo")
	if err != nil || !strings.Contains(out, "js/sql-injection") || !strings.Contains(out, "src/db.js:42") || !strings.Contains(out, "codeql") {
		t.Errorf("findings: %v\n%s", err, out)
	}
	_, out, _, err = run(t, dir, "--lang", "fr", "source", "run", "plugin.codeql", "--project", "demo", "--input", codeqlReport)
	if err != nil || !strings.Contains(out, "codeql n'a trouvé aucune nouvelle faille dans demo") {
		t.Errorf("fr: %v %q", err, out)
	}
}

// buildFakeTool builds the plugin tests' fake tool under the name tool and
// puts it first on PATH.
func buildFakeTool(t *testing.T, tool string) {
	t.Helper()
	bin := t.TempDir()
	name := tool
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	out, err := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", filepath.Join(bin, name), "../plugin/testdata/faketool").CombinedOutput()
	if err != nil {
		t.Fatalf("go build faketool: %v\n%s", err, out)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestScanRunsEnabledPluginsAfterAnalysis(t *testing.T) {
	buildFakeTool(t, "trivy")
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "source", "enable", "plugin.trivy"); err != nil {
		t.Fatal(err)
	}
	_, out, errOut, err := run(t, dir, "scan", "--project", "demo", "--osv-db", db)
	if err != nil {
		t.Fatalf("scan: %v\n%s\n%s", err, out, errOut)
	}
	if !strings.Contains(out, "trivy found 1 new finding in demo") {
		t.Errorf("scan output = %s\nstderr %s", out, errOut)
	}
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	order := map[string]int{}
	rows, err := s.DB().Query(`SELECT rowid, action FROM audit_event WHERE action IN ('scan.finish', 'analyze.finish', 'plugin.run') ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var action string
		if err := rows.Scan(&id, &action); err != nil {
			t.Fatal(err)
		}
		order[action] = id
	}
	if order["plugin.run"] == 0 || order["plugin.run"] < order["analyze.finish"] || order["analyze.finish"] < order["scan.finish"] {
		t.Errorf("audit order = %v", order)
	}

	// A failing plugin is a warning, not a failed scan.
	t.Setenv("PATH", t.TempDir())
	_, _, errOut, err = run(t, dir, "scan", "--project", "demo", "--osv-db", db)
	if err != nil || !strings.Contains(errOut, "warning: demo: trivy") {
		t.Errorf("scan with trivy missing: %v\n%s", err, errOut)
	}
}
