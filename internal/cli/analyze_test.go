package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAnalyzeCommandTable(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "scan", "--project", "demo", "--osv-db", db, "--no-analyze"); err != nil {
		t.Fatal(err)
	}
	_, out, _, err := run(t, dir, "analyze", "--project", "demo")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	for _, want := range []string{"project", "analyzed", "skipped", "failed", "duration", "demo",
		"Michel analyzed 3 findings in demo. Next: michel findings --project demo"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	_, out, _, err = run(t, dir, "analyze", "--project", "demo")
	if err != nil || !strings.Contains(out, "Michel analyzed 0 findings in demo (3 skipped, already fresh).") {
		t.Errorf("second run: %v\n%s", err, out)
	}
	_, out, _, err = run(t, dir, "analyze", "--all", "--force", "--json")
	var doc struct {
		Results []struct {
			Project  string
			Analyzed int
			Skipped  int
			Failed   int
		}
		Failures []any
	}
	if err != nil || json.Unmarshal([]byte(out), &doc) != nil || len(doc.Results) != 1 ||
		doc.Results[0].Project != "demo" || doc.Results[0].Analyzed != 3 || len(doc.Failures) != 0 {
		t.Errorf("json: %v\n%s", err, out)
	}
	if _, _, _, err = run(t, dir, "analyze"); err == nil {
		t.Error("analyze without target must fail")
	}
}

func TestScanRunsAnalyzeUnlessDisabled(t *testing.T) {
	db := buildTestOSVDB(t)
	for _, tc := range []struct {
		flag string
		want int
		text string
	}{{"", 1, ", analyzed 3 findings"}, {"--no-analyze", 0, ", analysis skipped"}} {
		dir := t.TempDir()
		if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
			t.Fatal(err)
		}
		args := []string{"scan", "--project", "demo", "--osv-db", db}
		if tc.flag != "" {
			args = append(args, tc.flag)
		}
		_, out, _, err := run(t, dir, args...)
		if err != nil || !strings.Contains(out, tc.text) {
			t.Errorf("%q: %v\n%s", tc.flag, err, out)
		}
		_, log, _, err := run(t, dir, "audit", "list")
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Count(log, "analyze.finish"); got != tc.want {
			t.Errorf("%q: analyze.finish events = %d, want %d\n%s", tc.flag, got, tc.want, log)
		}
	}
}
