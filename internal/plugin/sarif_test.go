package plugin

import (
	"os"
	"strings"
	"testing"
)

func parseFixture(t *testing.T, name, root string) []ExternalFinding {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out, err := ParseSARIF(f, root)
	if err != nil {
		t.Fatalf("ParseSARIF(%s): %v", name, err)
	}
	return out
}

func TestParseSARIFMapsLevelsAndSecuritySeverity(t *testing.T) {
	codeql := parseFixture(t, "codeql.sarif", `C:\x`)
	if len(codeql) != 2 {
		t.Fatalf("codeql: %d findings, want 2 (the one outside the project is refused): %+v", len(codeql), codeql)
	}
	sql := codeql[0]
	if sql.RuleID != "js/sql-injection" || sql.Severity != "high" || sql.CVSS != 0 || sql.Location != "src/db.js:42" ||
		sql.Fingerprint != "4f2a9c1e0b7d3a65:1" {
		t.Errorf("codeql error result = %+v", sql)
	}
	if strings.ContainsRune(sql.Message, '\x1b') || !strings.HasPrefix(sql.Message, "This query depends") {
		t.Errorf("message not sanitized: %q", sql.Message)
	}
	if u := codeql[1]; u.Severity != "low" || u.Fingerprint != "" || u.Location != "src/util.js:7" {
		t.Errorf("note from the rule's default level = %+v", u)
	}

	semgrep := parseFixture(t, "semgrep.sarif", `C:\x`)
	if len(semgrep) != 2 {
		t.Fatalf("semgrep: %d findings, want 2: %+v", len(semgrep), semgrep)
	}
	if e := semgrep[0]; e.Severity != "critical" || e.CVSS != 9.1 || e.Location != "src/a.php:12" {
		t.Errorf("security-severity 9.1 = %+v", e)
	}
	if w := semgrep[1]; w.Severity != "medium" || w.Location != "lib/b.php:3" {
		t.Errorf("file URI under the root = %+v", w)
	}
	for _, f := range append(codeql, semgrep...) {
		if f.Kind != "" {
			t.Errorf("ParseSARIF sets no kind, the provider does: %+v", f)
		}
	}
}

func TestParseSARIFRefusesGarbage(t *testing.T) {
	if _, err := ParseSARIF(strings.NewReader(`{"runs": 3}`), "/p"); err == nil {
		t.Error("a malformed report must be refused")
	}
	out, err := ParseSARIF(strings.NewReader(`{"version":"2.1.0","runs":[{"results":[
		{"ruleId":"r","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"/p/../etc/x"}}}]},
		{"ruleId":"r","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"/p/ok.go"}}}]}]}]}`), "/p")
	if err != nil || len(out) != 1 || out[0].Location != "ok.go" {
		t.Errorf("escaping path kept: %+v %v", out, err)
	}
}
