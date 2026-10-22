package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/store"
)

type listedFinding struct {
	ID      string `json:"id"`
	Package string `json:"package"`
}

// scannedDemo registers project-a, scans it (with or without analysis) and
// returns the data dir and the finding ids.
func scannedDemo(t *testing.T, analyzeToo bool) (string, []listedFinding) {
	t.Helper()
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	args := []string{"scan", "--project", "demo", "--osv-db", db}
	if !analyzeToo {
		args = append(args, "--no-analyze")
	}
	if _, _, _, err := run(t, dir, args...); err != nil {
		t.Fatal(err)
	}
	_, out, _, err := run(t, dir, "findings", "--project", "demo", "--json")
	var list []listedFinding
	if err != nil || json.Unmarshal([]byte(out), &list) != nil || len(list) == 0 {
		t.Fatalf("findings: %v\n%s", err, out)
	}
	return dir, list
}

func TestFindingDetailShowsExplanation(t *testing.T) {
	dir, list := scannedDemo(t, true)
	_, out, _, err := run(t, dir, "finding", list[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{list[0].Package, "project demo", "What: ", "Impact: ", "Cost: ", "Facts", "Risk:", "Versions:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "michel analyze --project") {
		t.Errorf("analyzed finding must not hint to analyze:\n%s", out)
	}
	if strings.Contains(out, dir) {
		t.Errorf("output leaks the data dir:\n%s", out)
	}

	_, out, _, err = run(t, dir, "finding", list[0].ID[:8], "--lang", "fr")
	if err != nil || !strings.Contains(out, "Quoi : ") || !strings.Contains(out, "Coût : ") {
		t.Errorf("fr: %v\n%s", err, out)
	}

	_, out, _, err = run(t, dir, "finding", list[0].ID, "--json")
	var doc struct {
		Finding  struct{ ID string }
		Analysis *struct {
			FindingID string `json:"finding_id"`
		}
		Explanation struct{ What, Impact, Cost string }
	}
	if err != nil || json.Unmarshal([]byte(out), &doc) != nil || doc.Finding.ID != list[0].ID ||
		doc.Analysis == nil || doc.Analysis.FindingID != list[0].ID || doc.Explanation.What == "" || doc.Explanation.Cost == "" {
		t.Errorf("json: %v\n%s", err, out)
	}
}

func TestFindingDetailWithoutAnalysisHints(t *testing.T) {
	dir, list := scannedDemo(t, false)
	_, out, _, err := run(t, dir, "finding", list[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `Run "michel analyze --project demo" to complete this view.`) {
		t.Errorf("no hint:\n%s", out)
	}
	_, out, _, err = run(t, dir, "finding", list[0].ID, "--json")
	if err != nil || !strings.Contains(out, `"analysis":null`) {
		t.Errorf("analysis must be null: %v\n%s", err, out)
	}
}

func TestFindingUnknownId(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	_, _, _, err := run(t, dir, "finding", "zzzz")
	if err == nil || !strings.Contains(err.Error(), "No finding has the id") {
		t.Errorf("err = %v", err)
	}
}

func TestFindingPrefixAmbiguous(t *testing.T) {
	dir, list := scannedDemo(t, false)
	st, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	twin := list[0].ID[:8] + "00000000"
	_, err = st.DB().Exec(`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, aliases,
		severity_label, cvss_score, installed_version, fixed_versions, dep_groups, status, first_seen_scan, last_seen_scan,
		first_seen_at, last_seen_at, summary)
		SELECT ?, project_id, manifest_rel_path, ecosystem, package, 'TWIN-1', aliases, severity_label, cvss_score,
		installed_version, fixed_versions, dep_groups, status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, summary
		FROM finding WHERE id = ?`, twin, list[0].ID)
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = run(t, dir, "finding", list[0].ID[:8])
	if err == nil || !strings.Contains(err.Error(), "matches 2 findings") || !strings.Contains(err.Error(), "project demo") ||
		!strings.Contains(err.Error(), twin) {
		t.Errorf("err = %v", err)
	}
	// The full id still resolves.
	if _, out, _, err := run(t, dir, "finding", list[0].ID); err != nil || strings.Contains(out, "TWIN-1") {
		t.Errorf("exact id: %v\n%s", err, out)
	}
}

func TestLangFlagOverridesPolicy(t *testing.T) {
	dir, list := scannedDemo(t, true)
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("assistant:\n  lang: fr\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps, out, _, err := run(t, dir, "finding", list[0].ID)
	if err != nil || deps.Lang != "fr" || !strings.Contains(out, "Quoi : ") {
		t.Errorf("policy fr: %v lang=%s\n%s", err, deps.Lang, out)
	}
	deps, out, _, err = run(t, dir, "finding", list[0].ID, "--lang", "en")
	if err != nil || deps.Lang != "en" || !strings.Contains(out, "What: ") {
		t.Errorf("flag en: %v lang=%s\n%s", err, deps.Lang, out)
	}
	_, _, _, err = run(t, dir, "finding", list[0].ID, "--lang", "de")
	if err == nil || ExitCode(err) != 3 || !strings.Contains(err.Error(), "Unknown language") {
		t.Errorf("invalid lang: %v", err)
	}
}

func TestFindingsExplainIndentsWhatUnderEachRow(t *testing.T) {
	for _, analyzed := range []bool{true, false} {
		dir, list := scannedDemo(t, analyzed)
		_, out, _, err := run(t, dir, "findings", "--project", "demo", "--explain")
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		if len(lines) != 1+2*len(list) {
			t.Fatalf("analyzed=%v: %d lines for %d findings:\n%s", analyzed, len(lines), len(list), out)
		}
		for i := 2; i < len(lines); i += 2 {
			if !strings.HasPrefix(lines[i], "  ") || strings.HasPrefix(lines[i], "   ") {
				t.Errorf("sentence line %d is not indented by two spaces: %q", i, lines[i])
			}
		}
		_, plain, _, _ := run(t, dir, "findings", "--project", "demo")
		if strings.Count(plain, "\n") != 1+len(list) {
			t.Errorf("plain table changed:\n%s", plain)
		}
	}
}

func TestFindingFactsHaveNoRawEnums(t *testing.T) {
	dir, list := scannedDemo(t, true)
	for _, l := range []string{"en", "FR"} {
		_, out, _, err := run(t, dir, "finding", list[0].ID, "--lang", l)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range []string{"auto_fix", "handoff", "report_only", "no_tests", "(low)", "(patch)"} {
			if strings.Contains(out, raw) {
				t.Errorf("%s: raw value %q in:\n%s", l, raw, out)
			}
		}
	}
}
