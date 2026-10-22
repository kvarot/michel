// Package explain turns the facts about a finding into three plain-language
// sentences (what, impact, cost) in English or French. Both languages are
// hand-written templates with the same structure.
package explain

import (
	"embed"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/scan"
)

//go:embed templates
var templateFS embed.FS

// Lang is a supported language.
type Lang string

const (
	EN Lang = "en"
	FR Lang = "fr"
)

// Valid tells whether l is a supported language.
func (l Lang) Valid() bool { return l == EN || l == FR }

// Facts is everything the templates may mention.
type Facts struct {
	Package, Ecosystem, OSVID, Summary, SeverityLabel string
	CVSS                                              float64
	Installed, Target                                 string
	Jump                                              analyze.Jump
	Directness                                        analyze.Directness
	Via                                               []string
	CallSiteCount                                     int
	CallSitesQuality                                  string
	TestCount                                         int
	TestMethod                                        string
	ChangelogAvailable, Breaking                      bool
	BreakingLines                                     []string
	Risk                                              analyze.Risk
	ManifestRelPath                                   string
	// Certainty is "high" when the call sites were matched precisely (psr4 or
	// import) and a test covers them, "medium" when matched precisely or by
	// name only, "low" otherwise (and without analysis).
	Certainty string

	// HasAnalysis is false when no analysis was stored for the finding.
	HasAnalysis bool
	// Example is the first call site as "file:line" (relative path), or "".
	Example string
	// Constraint is the project's constraint on a direct dependency.
	Constraint string
	// ConstraintKnown tells whether ConstraintOK is meaningful.
	ConstraintKnown, ConstraintOK bool
	// BreakingCount is len(BreakingLines), at least 1 when Breaking.
	BreakingCount int
}

// Explanation is the three sentences.
type Explanation struct {
	What   string `json:"what"`
	Impact string `json:"impact"`
	Cost   string `json:"cost"`
}

const maxSummary = 160

var drivePrefix = regexp.MustCompile(`^[A-Za-z]:`)

// relOnly keeps explanations free of absolute paths: an absolute or
// drive-prefixed path is reduced to its base name.
func relOnly(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(p, "/") || drivePrefix.MatchString(p) || filepath.IsAbs(p) {
		return path.Base(p)
	}
	return p
}

func shorten(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= maxSummary {
		return s
	}
	r := []rune(s)
	return strings.TrimSpace(string(r[:maxSummary])) + "..."
}

// FactsFrom builds the facts of a finding. Without analysis only what the scan
// knows is filled, and the upgrade is planned from the finding itself.
func FactsFrom(fi scan.Finding, a analyze.Analysis, hasAnalysis bool) Facts {
	f := Facts{
		Package: fi.Package, Ecosystem: fi.Ecosystem, OSVID: fi.OSVID, Summary: shorten(fi.Summary),
		SeverityLabel: fi.SeverityLabel, CVSS: fi.CVSS, Installed: fi.InstalledVersion,
		ManifestRelPath: fi.ManifestRelPath, HasAnalysis: hasAnalysis, Directness: analyze.Unknown,
		Certainty: "low",
	}
	if !hasAnalysis {
		up := analyze.PlanUpgrade(fi.Ecosystem, fi.InstalledVersion, fi.FixedVersions, "")
		f.Target, f.Jump = up.Target, up.Jump
		return f
	}
	f.Target, f.Jump = a.Upgrade.Target, a.Upgrade.Jump
	if a.Upgrade.ConstraintAllows != nil {
		f.ConstraintKnown, f.ConstraintOK = true, *a.Upgrade.ConstraintAllows
	}
	f.Constraint = a.Path.Constraint
	f.Directness, f.Via = a.Path.Directness, a.Path.Via
	f.CallSiteCount, f.CallSitesQuality = a.Calls.Count, a.Calls.Quality
	if len(a.Calls.Sites) > 0 {
		s := a.Calls.Sites[0]
		f.Example = fmt.Sprintf("%s:%d", relOnly(s.File), s.Line)
	}
	f.TestCount, f.TestMethod = a.Coverage.Count, a.Coverage.Method
	f.ChangelogAvailable, f.Breaking, f.BreakingLines = a.Changelog.Available, a.Changelog.Breaking, a.Changelog.BreakingLines
	f.Risk = a.Risk
	switch q := f.CallSitesQuality; {
	case (q == "psr4" || q == "import") && f.TestCount > 0:
		f.Certainty = "high"
	case q == "psr4" || q == "import" || q == "name":
		f.Certainty = "medium"
	}
	return f
}

func severityWords(lang Lang) map[string]string {
	if lang == FR {
		return map[string]string{
			"critical": "peut permettre à un attaquant de prendre le contrôle",
			"high":     "est grave",
			"medium":   "est modérée",
			"low":      "est mineure",
			"unknown":  "n'a pas encore de note de gravité",
		}
	}
	return map[string]string{
		"critical": "could let an attacker take control",
		"high":     "is serious",
		"medium":   "is moderate",
		"low":      "is minor",
		"unknown":  "has no rating yet",
	}
}

func funcs(lang Lang) template.FuncMap {
	words := severityWords(lang)
	return template.FuncMap{
		"plural": func(n int, one, many string) string {
			if n == 1 || (lang == FR && n == 0) {
				return one
			}
			return many
		},
		"join": strings.Join,
		"severityWord": func(label string) string {
			if w, ok := words[label]; ok {
				return w
			}
			return words["unknown"]
		},
	}
}

func renderOne(lang Lang, name string, f Facts) (string, error) {
	file := path.Join("templates", string(lang), name+".tmpl")
	raw, err := templateFS.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("explanation template %s is missing: %w", file, err)
	}
	t, err := template.New(name).Funcs(funcs(lang)).Parse(string(raw))
	if err != nil {
		return "", fmt.Errorf("explanation template %s is invalid: %w", file, err)
	}
	var sb strings.Builder
	if err := t.Execute(&sb, f); err != nil {
		return "", fmt.Errorf("explanation template %s failed: %w", file, err)
	}
	return strings.TrimSpace(sb.String()), nil
}

// Render writes the three sentences in lang.
func Render(lang Lang, f Facts) (Explanation, error) {
	if !lang.Valid() {
		return Explanation{}, fmt.Errorf("language %q is not supported (use en or fr)", lang)
	}
	if f.Breaking {
		f.BreakingCount = max(len(f.BreakingLines), 1)
	}
	var e Explanation
	for _, p := range []struct {
		name string
		to   *string
	}{{"what", &e.What}, {"impact", &e.Impact}, {"cost", &e.Cost}} {
		s, err := renderOne(lang, p.name, f)
		if err != nil {
			return Explanation{}, err
		}
		*p.to = s
	}
	return e, nil
}
