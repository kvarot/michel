package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/store"
)

// findingDoc is 'michel finding --json', decoded by its snake_case keys.
type findingDoc struct {
	Finding  map[string]any `json:"finding"`
	Analysis *struct {
		FindingID string `json:"finding_id"`
		ProjectID string `json:"project_id"`
		Calls     struct {
			Count   int              `json:"count"`
			Quality string           `json:"quality"`
			Sites   []map[string]any `json:"sites"`
		} `json:"calls"`
		Coverage struct {
			Method string `json:"method"`
		} `json:"coverage"`
		Changelog struct {
			Available bool `json:"available"`
		} `json:"changelog"`
		Risk struct {
			Score          int            `json:"score"`
			Recommendation string         `json:"recommendation"`
			Warning        bool           `json:"warning"`
			Terms          map[string]int `json:"terms"`
		} `json:"risk"`
		InputsHash string `json:"inputs_hash"`
	} `json:"analysis"`
	Explanation struct {
		What, Impact, Cost string
	} `json:"explanation"`
}

func findingJSON(t *testing.T, dir, id string) (findingDoc, string) {
	t.Helper()
	_, out, _, err := run(t, dir, "finding", id, "--json")
	var doc findingDoc
	if err != nil || json.Unmarshal([]byte(out), &doc) != nil {
		t.Fatalf("finding --json: %v\n%s", err, out)
	}
	return doc, out
}

func TestFindingJSONHasSnakeCaseKeys(t *testing.T) {
	dir, list := scannedDemo(t, true)
	doc, raw := findingJSON(t, dir, list[0].ID)
	a := doc.Analysis
	if a == nil || a.FindingID != list[0].ID || a.ProjectID == "" || len(a.InputsHash) != 64 ||
		a.Risk.Recommendation == "" || a.Risk.Terms == nil || a.Coverage.Method == "" || a.Calls.Quality == "" {
		t.Fatalf("analysis not decoded by snake_case keys:\n%s", raw)
	}
	for _, goName := range []string{`"FindingID"`, `"Calls"`, `"Risk"`, `"Snippet"`, `"snippet"`} {
		if strings.Contains(raw, goName) {
			t.Errorf("JSON has %s:\n%s", goName, raw)
		}
	}
}

func TestFindingShowsRiskTermsAndWarning(t *testing.T) {
	dir, list := scannedDemo(t, true)
	// Low thresholds make every finding with points carry a warning.
	if _, _, _, err := run(t, dir, "project", "set", "demo", "--risk", "auto_fix_below=1", "--risk", "handoff_up_to=2"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "analyze", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	warned := ""
	for _, f := range list {
		if doc, _ := findingJSON(t, dir, f.ID); doc.Analysis != nil && doc.Analysis.Risk.Warning {
			warned = f.ID
			break
		}
	}
	if warned == "" {
		t.Fatal("no finding above the lowered threshold")
	}
	for _, tc := range []struct{ lang, warn, plus string }{
		{"en", "Warning: risk above 2, review carefully.", " +"},
		{"fr", "Attention : risque au-dessus de 2, à examiner avec soin.", " +"},
	} {
		_, out, _, err := run(t, dir, "finding", warned, "--lang", tc.lang)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, tc.warn) || !strings.Contains(out, tc.plus) {
			t.Errorf("%s: no plain risk terms or warning:\n%s", tc.lang, out)
		}
		for _, raw := range []string{"no_tests", "major_jump", "many_call_sites", "core_package", "jump_unknown_handoff", "thresholds_fallback"} {
			if strings.Contains(out, raw) {
				t.Errorf("%s: raw key %q in:\n%s", tc.lang, raw, out)
			}
		}
	}
}

func TestProjectSetSaysAnalysisWillBeRecomputed(t *testing.T) {
	dir, proj := t.TempDir(), t.TempDir()
	if _, _, _, err := run(t, dir, "project", "add", proj, "--name", "shop"); err != nil {
		t.Fatal(err)
	}
	const msg = "Analysis will be recomputed on the next scan or `michel analyze --project shop`."
	for _, args := range [][]string{{"--core-package", "acme/core"}, {"--risk", "major_jump=30"}} {
		_, out, _, err := run(t, dir, append([]string{"project", "set", "shop"}, args...)...)
		if err != nil || !strings.Contains(out, msg) {
			t.Errorf("%v: %v\n%s", args, err, out)
		}
	}
	_, out, _, err := run(t, dir, "project", "set", "shop", "--fix-level", "2")
	if err != nil || strings.Contains(out, "recomputed") {
		t.Errorf("fix level does not change the analysis: %v\n%s", err, out)
	}
}

func TestProjectSetCorePackageRecomputesAnalysis(t *testing.T) {
	dir, list := scannedDemo(t, true)
	doc, _ := findingJSON(t, dir, list[0].ID)
	pkg, _ := doc.Finding["package"].(string)
	if _, out, _, _ := run(t, dir, "analyze", "--project", "demo"); !strings.Contains(out, "skipped, already fresh") {
		t.Fatalf("fresh analyses must be skipped:\n%s", out)
	}
	if _, _, _, err := run(t, dir, "project", "set", "demo", "--core-package", pkg); err != nil {
		t.Fatal(err)
	}
	_, out, _, err := run(t, dir, "analyze", "--project", "demo")
	if err != nil || strings.Contains(out, "already fresh") {
		t.Fatalf("a core package change must recompute every analysis: %v\n%s", err, out)
	}
	if doc, _ = findingJSON(t, dir, list[0].ID); doc.Analysis.Risk.Terms["core_package"] == 0 {
		t.Errorf("core package term missing: %v", doc.Analysis.Risk.Terms)
	}
}

func TestAnalyzeAuditFailureExitsOne(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.DB().Exec(`CREATE TRIGGER fail_finish BEFORE INSERT ON audit_event WHEN NEW.action = 'analyze.finish'
		BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`)
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	_, out, errOut, err := run(t, dir, "analyze", "--project", "demo")
	if ExitCode(err) != 1 || !strings.Contains(errOut, "audit log") {
		t.Fatalf("exit %d, err %v\nstdout:\n%s\nstderr:\n%s", ExitCode(err), err, out, errOut)
	}
}

func TestAmbiguousPrefixSaysAtLeastWhenCapped(t *testing.T) {
	many := make([]scan.Finding, scan.MaxPrefixMatches)
	for i := range many {
		many[i] = scan.Finding{ID: fmt.Sprintf("ab%014d", i), Package: "p\x1b[2K", OSVID: "X"}
	}
	msg := ambiguousPrefixMessage("ab", many, nil)
	if !strings.Contains(msg, "matches at least 50 findings") || !strings.Contains(msg, "... and more") || strings.Contains(msg, "\x1b") {
		t.Errorf("capped: %s", msg)
	}
	msg = ambiguousPrefixMessage("ab", many[:12], nil)
	if !strings.Contains(msg, "matches 12 findings") || !strings.Contains(msg, "... and 2 more") {
		t.Errorf("not capped: %s", msg)
	}
}
