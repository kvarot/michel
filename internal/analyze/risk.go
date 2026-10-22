package analyze

import "github.com/kvarot/michel/internal/policy"

// Recommendation is what Michel proposes to do with a finding.
type Recommendation string

const (
	RecAutoFix    Recommendation = "auto_fix"
	RecHandoff    Recommendation = "handoff"
	RecReportOnly Recommendation = "report_only"
)

// RiskInput is the evidence the score is computed from.
type RiskInput struct {
	Jump          Jump
	Breaking      bool
	Directness    Directness
	CallSiteCount int
	TestCount     int
	// IsCore is true when the package is in the project's core packages; the
	// caller computes it.
	IsCore bool
	// HasFix is false when no fixed version exists.
	HasFix bool
}

// Risk is the public, deterministic risk score of upgrading one package.
type Risk struct {
	Score          int
	Recommendation Recommendation
	// Warning is set when the score is above HandoffUpTo.
	Warning bool
	// Terms maps each term to the points it added (0 when its condition is
	// false). "major_jump_unknown" is present, at 0, when the jump is unknown.
	Terms map[string]int
}

// ScoreRisk applies the public rule described in docs/remediation-risk.md.
// overrides (per-project, known keys only) replace values of cfg. No AI input
// ever reaches this function: the model cannot change the score.
func ScoreRisk(cfg policy.RiskConfig, overrides map[string]int, in RiskInput) Risk {
	cfg = cfg.WithOverrides(overrides)
	pts := func(on bool, v int) int {
		if on {
			return v
		}
		return 0
	}
	terms := map[string]int{
		"major_jump":      pts(in.Jump == JumpMajor, cfg.MajorJump),
		"breaking":        pts(in.Breaking, cfg.Breaking),
		"direct":          pts(in.Directness == Direct, cfg.Direct),
		"many_call_sites": pts(in.CallSiteCount > cfg.ManyCallSitesThreshold, cfg.ManyCallSites),
		"no_tests":        pts(in.TestCount == 0, cfg.NoTests),
		"core_package":    pts(in.IsCore, cfg.CorePackage),
	}
	if in.Jump == JumpUnknown {
		terms["major_jump_unknown"] = 0
	}
	score := 0
	for _, v := range terms {
		score += v
	}
	if score > 100 {
		score = 100
	}
	r := Risk{Score: score, Terms: terms, Warning: score > cfg.HandoffUpTo}
	switch {
	case !in.HasFix:
		r.Recommendation = RecReportOnly
	case score < cfg.AutoFixBelow:
		r.Recommendation = RecAutoFix
	default:
		r.Recommendation = RecHandoff
	}
	return r
}
