package explain

import (
	"fmt"
	"strings"

	"github.com/kvarot/michel/internal/i18n"
)

// Label returns a small piece of interface text (a heading, a hint) from the
// catalog entry "explain.label."+key. An unknown key falls back to English,
// then to the key itself.
func Label(lang Lang, key string) string {
	if !i18n.Has("explain.label." + key) {
		return key
	}
	return i18n.T(lang, "explain.label."+key)
}

// Enum words an enum value (recommendation, jump, call-site quality, coverage
// method) in plain language. kind is "rec", "jump", "quality" or "method"; an
// empty or unknown value gives "unknown" (or "none" for an empty method).
func Enum(lang Lang, kind, value string) string {
	if k := kind + "_" + value; i18n.Has("explain.label." + k) {
		return Label(lang, k)
	}
	if value == "" && kind == "method" {
		return Label(lang, "none")
	}
	return Label(lang, "unknown")
}

// TestsLine is the sentence for the number of test files covering the code.
func TestsLine(lang Lang, n int) string {
	switch {
	case n <= 0:
		return Label(lang, "tests_zero")
	case n == 1:
		return Label(lang, "tests_one")
	}
	return fmt.Sprintf(Label(lang, "tests_many"), n)
}

// riskTermOrder is the order risk terms are worded in, points first.
var riskTermOrder = []string{"major_jump", "breaking", "no_tests", "core_package", "many_call_sites", "direct"}

// RiskTerms words the risk terms that weigh in the score ("major update +40,
// no covering test +20"), then the flags that changed the recommendation.
// Raw term keys never appear. Unknown keys are skipped.
func RiskTerms(lang Lang, terms map[string]int) string {
	var parts []string
	for _, k := range riskTermOrder {
		if v := terms[k]; v != 0 {
			parts = append(parts, fmt.Sprintf("%s +%d", Label(lang, "risk_"+k), v))
		}
	}
	for _, k := range []string{"jump_unknown_handoff", "thresholds_fallback"} {
		if terms[k] != 0 {
			parts = append(parts, Label(lang, "risk_"+k))
		}
	}
	if len(parts) == 0 {
		return Label(lang, "risk_none")
	}
	return strings.Join(parts, ", ")
}

// RiskWarning is the warning line for a score above the handoff threshold.
func RiskWarning(lang Lang, handoffUpTo int) string {
	return fmt.Sprintf(Label(lang, "warning"), handoffUpTo)
}
