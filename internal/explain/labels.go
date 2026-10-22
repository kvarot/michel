package explain

import (
	"fmt"
	"strings"
)

var labels = map[Lang]map[string]string{
	EN: {
		"what": "What", "impact": "Impact", "cost": "Cost", "facts": "Facts", "path": "Path",
		"versions": "Versions", "constraint": "Constraint", "calls": "Call sites", "tests": "Tests",
		"changelog": "Changelog", "risk": "Risk", "glossary": "Glossary", "project": "project",
		"direct": "direct dependency", "transitive": "transitive, through", "unknown": "unknown",
		"installed": "installed", "fixed": "fixed", "target": "target", "none": "none",
		"hint": `Run "michel analyze --project %s" to complete this view.`,
		"more": "and %d more", "score": "score", "recommendation": "recommendation",
		"nochangelog": "not available offline", "nobreak": "no breaking change found", "breaks": "breaking changes",
		"term_breaking": "breaking change", "term_transitive": "transitive",
		"rec_auto_fix": "automatic fix possible", "rec_handoff": "hand over with a brief", "rec_report_only": "report only",
		"jump_patch": "patch update", "jump_minor": "minor update", "jump_major": "major update",
		"jump_unknown": "unknown", "jump_none": "none",
		"quality_psr4": "by namespace", "quality_import": "by import", "quality_name": "by name only", "quality_low": "not searchable",
		"quality_noautoload": "no namespace to search",
		"noversions":         "versions unreadable, breaking changes not assessed",
		"risk_major_jump":    "major update", "risk_breaking": "breaking change in the changelog", "risk_direct": "direct dependency",
		"risk_many_call_sites": "used in many places", "risk_no_tests": "no covering test", "risk_core_package": "core package",
		"risk_jump_unknown_handoff": "update size unknown, so handed over",
		"risk_thresholds_fallback":  "project thresholds inconsistent, policy thresholds used",
		"risk_none":                 "no risk factor",
		"warning":                   "Warning: risk above %d, review carefully.",
		"method_callsite":           "tests use the package", "method_reference": "tests reference the files", "method_none": "none",
		"tests_zero": "No test covers it", "tests_one": "1 test file covers the code that uses it",
		"tests_many": "%d test files cover the code that uses it",
	},
	FR: {
		"what": "Quoi", "impact": "Impact", "cost": "Coût", "facts": "Faits", "path": "Chemin",
		"versions": "Versions", "constraint": "Contrainte", "calls": "Endroits où le paquet est utilisé", "tests": "Tests",
		"changelog": "Journal des modifications", "risk": "Risque", "glossary": "Glossaire", "project": "projet",
		"direct": "dépendance directe", "transitive": "transitive, via", "unknown": "inconnu",
		"installed": "installée", "fixed": "corrigée", "target": "cible", "none": "aucune",
		"hint": `Lance « michel analyze --project %s » pour compléter cette fiche.`,
		"more": "et %d de plus", "score": "note", "recommendation": "recommandation",
		"nochangelog": "indisponible hors ligne", "nobreak": "aucun changement incompatible repéré", "breaks": "changements incompatibles",
		"term_breaking": "changement incompatible", "term_transitive": "transitive",
		"rec_auto_fix": "correction automatique possible", "rec_handoff": "à confier avec un descriptif", "rec_report_only": "rapport seulement",
		"jump_patch": "mise à jour corrective", "jump_minor": "mise à jour mineure", "jump_major": "mise à jour majeure",
		"jump_unknown": "inconnue", "jump_none": "aucune",
		"quality_psr4": "par espace de noms", "quality_import": "par import", "quality_name": "par nom seulement", "quality_low": "recherche impossible",
		"quality_noautoload": "aucun espace de noms à chercher",
		"noversions":         "versions illisibles, changements incompatibles non évalués",
		"risk_major_jump":    "mise à jour majeure", "risk_breaking": "changement incompatible dans le journal", "risk_direct": "dépendance directe",
		"risk_many_call_sites": "utilisé à beaucoup d'endroits", "risk_no_tests": "aucun test qui couvre", "risk_core_package": "paquet central",
		"risk_jump_unknown_handoff": "ampleur de la mise à jour inconnue, donc à confier",
		"risk_thresholds_fallback":  "seuils du projet incohérents, seuils de la politique utilisés",
		"risk_none":                 "aucun facteur de risque",
		"warning":                   "Attention : risque au-dessus de %d, à examiner avec soin.",
		"method_callsite":           "des tests utilisent le paquet", "method_reference": "des tests mentionnent les fichiers", "method_none": "aucun",
		"tests_zero": "Aucun test ne le couvre", "tests_one": "1 fichier de test couvre le code qui l'utilise",
		"tests_many": "%d fichiers de test couvrent le code qui l'utilise",
	},
}

// Label returns a small piece of interface text (a heading, a hint). An
// unknown key falls back to English, then to the key itself.
func Label(lang Lang, key string) string {
	if s, ok := labels[lang][key]; ok {
		return s
	}
	if s, ok := labels[EN][key]; ok {
		return s
	}
	return key
}

// Enum words an enum value (recommendation, jump, call-site quality, coverage
// method) in plain language. kind is "rec", "jump", "quality" or "method"; an
// empty or unknown value gives "unknown" (or "none" for an empty method).
func Enum(lang Lang, kind, value string) string {
	if s, ok := labels[lang][kind+"_"+value]; ok {
		return s
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
