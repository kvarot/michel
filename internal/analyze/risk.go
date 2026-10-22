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
	// TestMethod is the coverage method ("callsite", "reference", "none"). Only
	// tests that use the package themselves cancel the no_tests term: a test
	// that only mentions a file name is weak evidence.
	TestMethod string
	// IsCore is true when the package is in the project's core packages; the
	// caller computes it.
	IsCore bool
	// HasFix is false when no fixed version exists.
	HasFix bool
}

// Risk is the public, deterministic risk score of upgrading one package.
type Risk struct {
	Score          int            `json:"score"`
	Recommendation Recommendation `json:"recommendation"`
	// Warning is set when the score is above HandoffUpTo.
	Warning bool `json:"warning"`
	// Terms maps each term to the points it added (0 when its condition is
	// false). "major_jump_unknown" is present, at 0, when the jump is unknown.
	// The flags "thresholds_fallback" and "jump_unknown_handoff" (value 1) are
	// not points; see IsRiskFlag.
	Terms map[string]int `json:"terms"`
}

// ScoreRisk applies the public rule described in docs/remediation-risk.md.
// overrides (per-project, known keys only) replace values of cfg. No AI input
// ever reaches this function: the model cannot change the score.
func ScoreRisk(cfg policy.RiskConfig, overrides map[string]int, in RiskInput) Risk {
	cfg, fallback := EffectiveRisk(cfg, overrides)
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
		"no_tests":        pts(in.TestCount == 0 || in.TestMethod == "reference", cfg.NoTests),
		"core_package":    pts(in.IsCore, cfg.CorePackage),
	}
	if in.Jump == JumpUnknown {
		terms["major_jump_unknown"] = 0
	}
	if fallback {
		terms["thresholds_fallback"] = 1
	}
	// Without the size of the update, Michel cannot claim it is safe: an
	// unknown jump is always handed over (the score is unchanged).
	unknownJump := in.Jump == JumpUnknown
	if unknownJump {
		terms["jump_unknown_handoff"] = 1
	}
	score := 0
	for k, v := range terms {
		if IsRiskFlag(k) {
			continue
		}
		score += v
	}
	if score > 100 {
		score = 100
	}
	r := Risk{Score: score, Terms: terms, Warning: score > cfg.HandoffUpTo}
	switch {
	case !in.HasFix:
		r.Recommendation = RecReportOnly
	case score < cfg.AutoFixBelow && !unknownJump:
		r.Recommendation = RecAutoFix
	default:
		r.Recommendation = RecHandoff
	}
	return r
}

// IsRiskFlag tells whether a Terms key is a flag (a fact about how the score
// was computed) rather than points added to the score.
func IsRiskFlag(key string) bool {
	return key == "thresholds_fallback" || key == "jump_unknown_handoff"
}

// EffectiveRisk applies the project's overrides to the policy rule. When the
// resulting thresholds are inconsistent, the policy thresholds are kept and
// fallback is true.
func EffectiveRisk(cfg policy.RiskConfig, overrides map[string]int) (eff policy.RiskConfig, fallback bool) {
	eff = cfg.WithOverrides(overrides)
	if eff.AutoFixBelow < 0 || eff.AutoFixBelow >= eff.HandoffUpTo || eff.HandoffUpTo > 100 {
		eff.AutoFixBelow, eff.HandoffUpTo = cfg.AutoFixBelow, cfg.HandoffUpTo
		fallback = true
	}
	return eff, fallback
}
