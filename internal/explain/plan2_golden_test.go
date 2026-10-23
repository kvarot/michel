package explain

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/kvarot/michel/internal/analyze"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/plan2_render.golden.json")

// plan2LabelKeys are the label keys of plan 2, before the catalog existed.
var plan2LabelKeys = []string{
	"what", "impact", "cost", "facts", "path", "versions", "constraint", "calls", "tests", "changelog", "risk",
	"glossary", "project", "direct", "transitive", "unknown", "installed", "fixed", "target", "none", "hint", "more",
	"score", "recommendation", "nochangelog", "nobreak", "breaks", "term_breaking", "term_transitive",
	"rec_auto_fix", "rec_handoff", "rec_report_only", "jump_patch", "jump_minor", "jump_major", "jump_unknown",
	"jump_none", "quality_psr4", "quality_import", "quality_name", "quality_low", "quality_noautoload", "noversions",
	"risk_major_jump", "risk_breaking", "risk_direct", "risk_many_call_sites", "risk_no_tests", "risk_core_package",
	"risk_jump_unknown_handoff", "risk_thresholds_fallback", "risk_none", "warning", "method_callsite",
	"method_reference", "method_none", "tests_zero", "tests_one", "tests_many",
}

// goldenVariants are single changes to sampleFacts that walk every branch of
// the three templates.
func goldenVariants() map[string]func(*Facts) {
	return map[string]func(*Facts){
		"sample":            func(*Facts) {},
		"no_target":         func(f *Facts) { f.Target = "" },
		"minor":             func(f *Facts) { f.Jump = analyze.JumpMinor },
		"major":             func(f *Facts) { f.Jump = analyze.JumpMajor },
		"unknown_jump":      func(f *Facts) { f.Jump = analyze.JumpUnknown },
		"breaking_one":      func(f *Facts) { f.Breaking = true },
		"breaking_two":      func(f *Facts) { f.Breaking, f.BreakingLines = true, []string{"a", "b"} },
		"versions_unread":   func(f *Facts) { f.ChangelogVersionsUnread = true },
		"no_changelog":      func(f *Facts) { f.ChangelogAvailable = false },
		"tests_zero":        func(f *Facts) { f.TestCount = 0 },
		"tests_three":       func(f *Facts) { f.TestCount = 3 },
		"fix_level_one":     func(f *Facts) { f.FixLevel = 1 },
		"handoff":           func(f *Facts) { f.Risk.Recommendation = analyze.RecHandoff },
		"report_only":       func(f *Facts) { f.Risk.Recommendation = analyze.RecReportOnly },
		"constraint_blocks": func(f *Facts) { f.ConstraintOK = false },
		"constraint_free":   func(f *Facts) { f.ConstraintKnown = false },
		"critical":          func(f *Facts) { f.SeverityLabel = "critical" },
		"medium":            func(f *Facts) { f.SeverityLabel = "medium" },
		"low":               func(f *Facts) { f.SeverityLabel = "low" },
		"unrated":           func(f *Facts) { f.SeverityLabel = "unknown" },
		"odd_severity":      func(f *Facts) { f.SeverityLabel = "odd" },
		"certainty_medium":  func(f *Facts) { f.Certainty = "medium" },
		"certainty_low":     func(f *Facts) { f.Certainty = "low" },
		"no_analysis":       func(f *Facts) { f.HasAnalysis, f.Certainty = false, "low" },
		"transitive":        func(f *Facts) { f.Directness, f.Via = analyze.Transitive, []string{"vendor/parent"} },
		"quality_low":       func(f *Facts) { f.CallSitesQuality = "low" },
		"quality_noauto":    func(f *Facts) { f.CallSitesQuality = "noautoload" },
		"one_place":         func(f *Facts) { f.CallSiteCount = 1 },
		"no_example":        func(f *Facts) { f.Example = "" },
		"by_name_absent":    func(f *Facts) { f.CallSiteCount, f.CallSitesQuality = 0, "name" },
		"absent":            func(f *Facts) { f.CallSiteCount = 0 },
		"no_summary":        func(f *Facts) { f.Summary = "" },
	}
}

type goldenLang struct {
	Explanations map[string]Explanation `json:"explanations"`
	Labels       map[string]string      `json:"labels"`
	Glossary     map[string]string      `json:"glossary"`
	TestsLines   []string               `json:"tests_lines"`
	RiskWarning  string                 `json:"risk_warning"`
	RiskTerms    string                 `json:"risk_terms"`
}

func renderGolden(t *testing.T) map[Lang]goldenLang {
	t.Helper()
	out := map[Lang]goldenLang{}
	for _, l := range []Lang{EN, FR} {
		g := goldenLang{Explanations: map[string]Explanation{}, Labels: map[string]string{}, Glossary: map[string]string{}}
		for name, change := range goldenVariants() {
			f := sampleFacts()
			change(&f)
			g.Explanations[name] = mustRender(t, l, f)
		}
		for _, k := range plan2LabelKeys {
			g.Labels[k] = Label(l, k)
		}
		for _, k := range Terms() {
			g.Glossary[k] = Term(l, k)
		}
		for _, n := range []int{0, 1, 2} {
			g.TestsLines = append(g.TestsLines, TestsLine(l, n))
		}
		g.RiskWarning = RiskWarning(l, 60)
		g.RiskTerms = RiskTerms(l, map[string]int{"major_jump": 40, "no_tests": 20, "direct": 10, "jump_unknown_handoff": 1})
		out[l] = g
	}
	return out
}

// TestTemplatesRenderIdenticalToPlan2 compares every template branch, label,
// glossary entry and severity word with the output recorded from plan 2,
// before the text moved to internal/i18n.
func TestTemplatesRenderIdenticalToPlan2(t *testing.T) {
	got, err := json.MarshalIndent(renderGolden(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join("testdata", "plan2_render.golden.json")
	if *updateGolden {
		if err := os.WriteFile(file, append(got, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(got)+"\n" {
		t.Errorf("rendering differs from plan 2 (%s); got:\n%s", file, got)
	}
}
