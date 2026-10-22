package analyze

import (
	"testing"

	"github.com/kvarot/michel/internal/policy"
)

func cfg() policy.RiskConfig { return policy.Defaults().Risk }

func TestScoreRiskTerms(t *testing.T) {
	tests := []struct {
		name  string
		in    RiskInput
		score int
		rec   Recommendation
		warn  bool
		terms map[string]int
	}{
		{"everything, capped", RiskInput{Jump: JumpMajor, Breaking: true, Directness: Direct, CallSiteCount: 12, TestCount: 0, IsCore: true, HasFix: true},
			100, "handoff", true,
			map[string]int{"major_jump": 40, "breaking": 25, "direct": 10, "many_call_sites": 15, "no_tests": 20, "core_package": 20}},
		{"patch, transitive, tested", RiskInput{Jump: JumpPatch, Directness: Transitive, CallSiteCount: 3, TestCount: 4, HasFix: true},
			0, "auto_fix", false,
			map[string]int{"major_jump": 0, "breaking": 0, "direct": 0, "many_call_sites": 0, "no_tests": 0, "core_package": 0}},
		{"threshold is strict", RiskInput{Jump: JumpMinor, Directness: Direct, CallSiteCount: 10, TestCount: 1, HasFix: true},
			10, "auto_fix", false,
			map[string]int{"major_jump": 0, "breaking": 0, "direct": 10, "many_call_sites": 0, "no_tests": 0, "core_package": 0}},
		{"minor direct untested", RiskInput{Jump: JumpMinor, Directness: Direct, CallSiteCount: 11, TestCount: 0, HasFix: true},
			45, "handoff", false,
			map[string]int{"major_jump": 0, "breaking": 0, "direct": 10, "many_call_sites": 15, "no_tests": 20, "core_package": 0}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := ScoreRisk(cfg(), nil, tc.in)
			if r.Score != tc.score || r.Recommendation != tc.rec || r.Warning != tc.warn {
				t.Fatalf("got %+v", r)
			}
			for k, v := range tc.terms {
				if got, ok := r.Terms[k]; !ok || got != v {
					t.Errorf("term %s = %d (present %v), want %d", k, got, ok, v)
				}
			}
			if len(r.Terms) != len(tc.terms) {
				t.Errorf("terms = %v", r.Terms)
			}
		})
	}
}

func TestScoreRiskThresholdsInclusive(t *testing.T) {
	// no_tests alone is 20; use overrides to hit exact scores.
	cases := []struct {
		score int
		rec   Recommendation
		warn  bool
	}{{29, "auto_fix", false}, {30, "handoff", false}, {60, "handoff", false}, {61, "handoff", true}}
	for _, c := range cases {
		r := ScoreRisk(cfg(), map[string]int{"no_tests": c.score}, RiskInput{Jump: JumpPatch, TestCount: 0, HasFix: true})
		if r.Score != c.score || r.Recommendation != c.rec || r.Warning != c.warn {
			t.Errorf("score %d: got %+v", c.score, r)
		}
	}
}

func TestScoreRiskNoFixIsReportOnly(t *testing.T) {
	r := ScoreRisk(cfg(), nil, RiskInput{Jump: JumpMajor, Directness: Direct, TestCount: 1, HasFix: false})
	if r.Recommendation != "report_only" || r.Score != 50 || r.Warning {
		t.Fatalf("got %+v", r)
	}
	r = ScoreRisk(cfg(), nil, RiskInput{Jump: JumpMajor, Breaking: true, IsCore: true, HasFix: false})
	if r.Recommendation != "report_only" || !r.Warning {
		t.Fatalf("high score without fix keeps its warning: %+v", r)
	}
}

func TestScoreRiskUnknownJump(t *testing.T) {
	r := ScoreRisk(cfg(), nil, RiskInput{Jump: JumpUnknown, TestCount: 1, HasFix: true})
	if v, ok := r.Terms["major_jump_unknown"]; !ok || v != 0 {
		t.Fatalf("terms = %v", r.Terms)
	}
	if r.Terms["major_jump"] != 0 || r.Score != 0 {
		t.Fatalf("got %+v", r)
	}
	r = ScoreRisk(cfg(), nil, RiskInput{Jump: JumpMajor, TestCount: 1, HasFix: true})
	if _, ok := r.Terms["major_jump_unknown"]; ok {
		t.Errorf("major_jump_unknown must only appear for unknown jumps: %v", r.Terms)
	}
}

func TestProjectOverridesApply(t *testing.T) {
	in := RiskInput{Jump: JumpMajor, TestCount: 1, HasFix: true}
	if r := ScoreRisk(cfg(), nil, in); r.Score != 40 || r.Recommendation != "handoff" {
		t.Fatalf("base: %+v", r)
	}
	r := ScoreRisk(cfg(), map[string]int{"major_jump": 10, "bogus": 99}, in)
	if r.Score != 10 || r.Recommendation != "auto_fix" || r.Terms["major_jump"] != 10 {
		t.Fatalf("override: %+v", r)
	}
	r = ScoreRisk(cfg(), map[string]int{"many_call_sites_threshold": 2}, RiskInput{Jump: JumpPatch, CallSiteCount: 3, TestCount: 1, HasFix: true})
	if r.Terms["many_call_sites"] != 15 {
		t.Fatalf("threshold override: %+v", r)
	}
}
