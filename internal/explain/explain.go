// Package explain turns the facts about a finding into three plain-language
// sentences (what, impact, cost) in English or French. Both languages are
// hand-written templates with the same structure, kept in internal/i18n.
package explain

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"unicode"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
)

// Lang is a supported language.
type Lang = i18n.Lang

const (
	EN = i18n.EN
	FR = i18n.FR
)

// Facts is everything the templates may mention. Text that comes from
// outside (advisories, package names, file names, changelogs) is stripped of
// control characters by FactsFrom.
type Facts struct {
	Package          string             `json:"package"`
	Ecosystem        string             `json:"ecosystem"`
	OSVID            string             `json:"osv_id"`
	Summary          string             `json:"summary"`
	SeverityLabel    string             `json:"severity"`
	CVSS             float64            `json:"cvss"`
	Installed        string             `json:"installed"`
	Target           string             `json:"target"`
	Jump             analyze.Jump       `json:"jump"`
	Directness       analyze.Directness `json:"directness"`
	Via              []string           `json:"via"`
	CallSiteCount    int                `json:"call_site_count"`
	CallSitesQuality string             `json:"call_sites_quality"`
	TestCount        int                `json:"test_count"`
	TestMethod       string             `json:"test_method"`
	// ChangelogAvailable is true when a changelog was read.
	ChangelogAvailable bool `json:"changelog_available"`
	// ChangelogVersionsUnread is true when the changelog was read but its
	// version headings were not: breaking changes were not assessed.
	ChangelogVersionsUnread bool         `json:"changelog_versions_unread"`
	Breaking                bool         `json:"breaking"`
	BreakingLines           []string     `json:"breaking_lines"`
	Risk                    analyze.Risk `json:"risk"`
	ManifestRelPath         string       `json:"manifest_rel_path"`
	// Certainty is "high" when the call sites were matched precisely (psr4 or
	// import) and a test using the package covers them (method "callsite"),
	// "medium" when matched precisely or by name only, "low" otherwise
	// (not searchable, no namespace, or without analysis).
	Certainty string `json:"certainty"`
	// FixLevel is the project's fix level (0 to 3): an automatic fix is only
	// offered from level 2.
	FixLevel int `json:"fix_level"`

	// HasAnalysis is false when no analysis was stored for the finding.
	HasAnalysis bool `json:"has_analysis"`
	// Example is the first call site as "file:line" (relative path), or "".
	Example string `json:"example"`
	// Constraint is the project's constraint on a direct dependency.
	Constraint string `json:"constraint"`
	// ConstraintKnown tells whether ConstraintOK is meaningful.
	ConstraintKnown bool `json:"constraint_known"`
	ConstraintOK    bool `json:"constraint_ok"`
	// BreakingCount is len(BreakingLines), at least 1 when Breaking.
	BreakingCount int `json:"breaking_count"`
	// Malicious is true for an OSV MAL- advisory: the package itself was
	// published to do harm.
	Malicious bool `json:"malicious"`
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

// clean removes control characters from one line of untrusted text; a line
// break becomes a space.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		return r
	}, scan.SanitizeText(s))
}

func shorten(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && !unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= maxSummary {
		return s
	}
	r := []rune(s)
	return strings.TrimSpace(string(r[:maxSummary])) + "..."
}

// FactsFrom builds the facts of a finding. Without analysis only what the scan
// knows is filled, and the upgrade is planned from the finding itself. The
// caller sets FixLevel from the project.
func FactsFrom(fi scan.Finding, a analyze.Analysis, hasAnalysis bool) Facts {
	f := Facts{
		Package: clean(fi.Package), Ecosystem: fi.Ecosystem, OSVID: clean(fi.OSVID), Summary: shorten(fi.Summary),
		SeverityLabel: fi.SeverityLabel, CVSS: fi.CVSS, Installed: clean(fi.InstalledVersion),
		ManifestRelPath: clean(fi.ManifestRelPath), HasAnalysis: hasAnalysis, Directness: analyze.Unknown,
		Certainty: "low", Malicious: fi.Malicious,
	}
	if !hasAnalysis {
		up := analyze.PlanUpgrade(fi.Ecosystem, fi.InstalledVersion, fi.FixedVersions, "")
		f.Target, f.Jump = clean(up.Target), up.Jump
		return f
	}
	f.Target, f.Jump = clean(a.Upgrade.Target), a.Upgrade.Jump
	if a.Upgrade.ConstraintAllows != nil {
		f.ConstraintKnown, f.ConstraintOK = true, *a.Upgrade.ConstraintAllows
	}
	f.Constraint = clean(a.Path.Constraint)
	f.Directness, f.Via = a.Path.Directness, scan.SanitizeAll(a.Path.Via)
	f.CallSiteCount, f.CallSitesQuality = a.Calls.Count, a.Calls.Quality
	if len(a.Calls.Sites) > 0 {
		s := a.Calls.Sites[0]
		f.Example = fmt.Sprintf("%s:%d", relOnly(clean(s.File)), s.Line)
	}
	f.TestCount, f.TestMethod = a.Coverage.Count, a.Coverage.Method
	f.ChangelogAvailable, f.Breaking = a.Changelog.Available, a.Changelog.Breaking
	f.ChangelogVersionsUnread = a.Changelog.VersionsUnread()
	f.BreakingLines = scan.SanitizeAll(a.Changelog.BreakingLines)
	f.Risk = a.Risk
	switch q := f.CallSitesQuality; {
	case (q == "psr4" || q == "import") && f.TestMethod == "callsite" && f.TestCount > 0:
		f.Certainty = "high"
	case q == "psr4" || q == "import" || q == "name":
		f.Certainty = "medium"
	}
	return f
}

func funcs(lang Lang) template.FuncMap {
	return template.FuncMap{
		"plural": func(n int, one, many string) string {
			if n == 1 || (lang == FR && n == 0) {
				return one
			}
			return many
		},
		"join": strings.Join,
		"severityWord": func(label string) string {
			if k := "explain.severity." + label; i18n.Has(k) {
				return i18n.T(lang, k)
			}
			return i18n.T(lang, "explain.severity.unknown")
		},
	}
}

func renderOne(lang Lang, name string, f Facts) (string, error) {
	t, err := i18n.Template(lang, name, funcs(lang))
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	if err := t.Execute(&sb, f); err != nil {
		return "", fmt.Errorf("explanation template %s/%s failed: %w", lang, name, err)
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
