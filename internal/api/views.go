package api

import (
	"path/filepath"
	"strings"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/explain"
	"github.com/kvarot/michel/internal/gitrepo"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
)

// The views are what the API answers. None of them holds the project's
// folder, its declared commands (test_cmd, install_cmd), code or a secret:
// call-site files are relative to the project, as stored.

// ProjectView is one active project with its counters, as the digest counts
// them: Open by severity (new, pending, decided fix or defer), Decided by
// action of the decisions in force, Total = open + ignored.
type ProjectView struct {
	Name           string `json:"name"`
	Classification string `json:"classification"`
	FixLevel       int    `json:"fix_level"`
	AutoFixMinor   bool   `json:"auto_fix_minor"`
	// HasTestCmd says a test command is declared, never which one. GitRepo says
	// the folder holds a Git repository (read on disk, git does not run).
	HasTestCmd bool           `json:"has_test_cmd"`
	GitRepo    bool           `json:"git_repo"`
	Open       map[string]int `json:"open"`
	Decided    map[string]int `json:"decided"`
	Total      int            `json:"total"`
	// LastScanAt is the start of the newest scan, RFC 3339, "" when never
	// scanned; LastScanStatus is its status, or "never".
	LastScanAt     string `json:"last_scan_at"`
	LastScanStatus string `json:"last_scan_status"`
	// Scanning says a scan started from the page is running; LastFailure is how
	// the last one failed, if it did. Both live in the memory of this process.
	Scanning    bool             `json:"scanning"`
	LastFailure *TargetLastCheck `json:"last_failure"`
}

// FindingView is a finding with its project's name instead of its id, the
// stored analysis (nil if none, and in lists), the three sentences in the
// request's language, the decision in force (nil if none) and the
// definitions of the glossary terms the explanation relies on.
type FindingView struct {
	ID               string   `json:"id"`
	Project          string   `json:"project"`
	ManifestRelPath  string   `json:"manifest_rel_path"`
	Ecosystem        string   `json:"ecosystem"`
	Package          string   `json:"package"`
	OSVID            string   `json:"osv_id"`
	Aliases          []string `json:"aliases"`
	Severity         string   `json:"severity"`
	CVSS             float64  `json:"cvss"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersions    []string `json:"fixed_versions"`
	DepGroups        []string `json:"dep_groups"`
	Summary          string   `json:"summary"`
	Status           string   `json:"status"`
	FirstSeenAt      string   `json:"first_seen_at"`
	LastSeenAt       string   `json:"last_seen_at"`
	// Severity is the effective severity (scan.EffectiveSeverity);
	// SeveritySource says where it comes from: osv, enrichment (an
	// advisory without severity, rated from a CVE record) or malicious.
	SeveritySource string `json:"severity_source"`
	// Kind is the sort of finding (dependency); Malicious marks a malicious
	// package; KEV marks a flaw exploited in the wild (CISA list) since
	// KEVAdded; EPSS and EPSSPercentile are FIRST's exploitation score.
	Kind string `json:"kind"`
	// RuleID and Location are set for a plugin finding (Kind code,
	// misconfig...): the rule or flaw the tool reports and the relative file
	// (and line) it points at; SourceKey is the plugin.
	RuleID         string  `json:"rule_id"`
	Location       string  `json:"location"`
	SourceKey      string  `json:"source_key"`
	Malicious      bool    `json:"malicious"`
	KEV            bool    `json:"kev"`
	KEVAdded       string  `json:"kev_added"`
	EPSS           float64 `json:"epss"`
	EPSSPercentile float64 `json:"epss_percentile"`

	Analysis    *analyze.Analysis   `json:"analysis"`
	Explanation explain.Explanation `json:"explanation"`
	Decision    *decide.Decision    `json:"decision"`
	Glossary    map[string]string   `json:"glossary"`
	// AuditEventID is the decision.set event, in the answer to a decision only.
	AuditEventID string `json:"audit_event_id,omitempty"`
}

// DecisionRequest is the body of POST /api/v1/findings/{id}/decision.
type DecisionRequest struct {
	Action string `json:"action"`
	Why    string `json:"why"`
	// Until is the deferral date, YYYY-MM-DD; empty means 30 days.
	Until string `json:"until"`
}

// ErrorBody is every error answer: what went wrong and, when there is one,
// what to do, in the request's language.
type ErrorBody struct {
	Error string `json:"error"`
	Hint  string `json:"hint,omitempty"`
}

// MetaView is GET /api/v1/meta.
type MetaView struct {
	Version   string    `json:"version"`
	Lang      i18n.Lang `json:"lang"`
	Languages []string  `json:"languages"`
	Assistant string    `json:"assistant"`
	// OSVFetchedAt is the oldest download of the offline databases, RFC 3339,
	// "" when unknown; OSVStale is true when it is older than the digest's limit.
	OSVFetchedAt string `json:"osv_fetched_at"`
	OSVStale     bool   `json:"osv_stale"`
}

// sanitizeAll strips control characters from every item; never nil.
func sanitizeAll(s []string) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		out = append(out, scan.SanitizeText(v))
	}
	return out
}

// scrub removes the project's folder from stored free text (an analysis note
// may quote a file error).
func scrub(s string, p project.Project) string {
	if p.Path == "" {
		return s
	}
	for _, root := range []string{p.Path, filepath.ToSlash(p.Path), filepath.FromSlash(p.Path)} {
		s = strings.ReplaceAll(s, root, "<project>")
	}
	return s
}

// findingView builds the view of fi; ex, a and dec are optional.
func findingView(fi scan.Finding, p project.Project, ex explain.Explanation, a *analyze.Analysis, dec *decide.Decision, glossary map[string]string) FindingView {
	severity, source := scan.EffectiveSeverity(fi)
	kind := fi.Kind
	if kind == "" {
		kind = scan.KindDependency
	}
	v := FindingView{
		ID: fi.ID, Project: scan.SanitizeText(p.Name), ManifestRelPath: scan.SanitizeText(fi.ManifestRelPath), Ecosystem: fi.Ecosystem,
		Package: scan.SanitizeText(fi.Package), OSVID: scan.SanitizeText(fi.OSVID), Aliases: sanitizeAll(fi.Aliases),
		Severity: severity, SeveritySource: source, Kind: scan.SanitizeText(kind), Malicious: fi.Malicious,
		RuleID: scan.SanitizeText(fi.RuleID), Location: scan.SanitizeText(fi.Location), SourceKey: fi.SourceKey,
		KEV: fi.KEV, KEVAdded: scan.SanitizeText(fi.KEVAdded), EPSS: fi.EPSS, EPSSPercentile: fi.EPSSPercentile,
		CVSS: fi.CVSS, InstalledVersion: scan.SanitizeText(fi.InstalledVersion),
		FixedVersions: sanitizeAll(fi.FixedVersions), DepGroups: sanitizeAll(fi.DepGroups), Summary: scan.SanitizeText(fi.Summary),
		Status: fi.Status, FirstSeenAt: fi.FirstSeenAt, LastSeenAt: fi.LastSeenAt,
		Explanation: ex, Decision: dec, Glossary: glossary,
	}
	if v.Glossary == nil {
		v.Glossary = map[string]string{}
	}
	if a != nil {
		c := *a
		c.Notes = append([]string{}, c.Notes...)
		for i, n := range c.Notes {
			c.Notes[i] = scrub(n, p)
		}
		c.Changelog.Note = scrub(c.Changelog.Note, p)
		c.Changelog.Source = scrub(c.Changelog.Source, p)
		v.Analysis = &c
	}
	return v
}

// glossaryOf defines the terms the explanation of f relies on, in lang.
func glossaryOf(lang i18n.Lang, f explain.Facts, aliases []string) map[string]string {
	out := map[string]string{}
	add := func(k string) {
		if def := explain.Term(lang, k); def != "" {
			out[k] = def
		}
	}
	if f.Directness == analyze.Transitive {
		add("transitive")
	}
	if f.Breaking || (f.HasAnalysis && f.Target != "" && f.ChangelogAvailable) {
		add("breaking")
	}
	if f.CVSS > 0 {
		add("cvss")
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			add("cve")
			break
		}
	}
	return out
}

// SourceView is one source as the Sources page shows it. State is the
// displayed state (off, waiting_consent, on, hidden; a plugin or a reference
// is never waiting_consent). Config is the merged settings without a secret's
// name, a local file or folder, or a launch command: an installed skill or
// MCP server says installed (and its sha), a plugin with a fixed report says
// has_input. Badges are new_version, suggested (a feed off whose technology
// you use) and archived. Note is the catalog's note, in the request's
// language ("" for a source of yours).
type SourceView struct {
	Key      string         `json:"key"`
	Kind     string         `json:"kind"`
	Origin   string         `json:"origin"`
	Name     string         `json:"name"`
	URL      string         `json:"url"`
	Hosts    []string       `json:"hosts"`
	Purpose  string         `json:"purpose"`
	State    string         `json:"state"`
	Enabled  bool           `json:"enabled"`
	Hidden   bool           `json:"hidden"`
	Tech     []string       `json:"tech"`
	Config   map[string]any `json:"config"`
	LastRead LastReadView   `json:"last_read"`
	Status   map[string]any `json:"status"`
	Badges   []string       `json:"badges"`
	Note     string         `json:"note"`
}

// LastReadView is the last read of a source: when (RFC 3339, "" if never),
// its result (ok, error, denied, waiting_consent, skipped, unreachable), the
// error in English without any local path, and the number of items.
type LastReadView struct {
	At     string `json:"at"`
	Result string `json:"result"`
	Error  string `json:"error"`
	Items  int    `json:"items"`
}

// HostRuleView is one host of a source with the allow rule it needs and
// whether the policy in force has it.
type HostRuleView struct {
	Host    string `json:"host"`
	Purpose string `json:"purpose"`
	Rule    string `json:"rule"`
	Allowed bool   `json:"allowed"`
}

// SourceDetailView is GET /sources/{key}: the source, its rules and its
// most recent items (a feed).
type SourceDetailView struct {
	SourceView
	Rules []HostRuleView `json:"rules"`
	Items []ReadingView  `json:"items"`
}

// ReadingView is one feed item ("to read"): Title is in the request's
// language for a watched page's change; Read tells it was marked read.
type ReadingView struct {
	ID          string   `json:"id"`
	SourceKey   string   `json:"source_key"`
	Source      string   `json:"source"`
	Title       string   `json:"title"`
	URL         string   `json:"url"`
	PublishedAt string   `json:"published_at"`
	Tech        []string `json:"tech"`
	Read        bool     `json:"read"`
}

// CatalogView is the digest's catalog with its one-sentence summary in the
// request's language ("" when there is nothing to say).
type CatalogView struct {
	digest.Catalog
	Line string `json:"line"`
}

// TodayView is GET /today: the digest (exploited flaws first, the items to
// read, the catalog line) and the number of repositories to discover.
type TodayView struct {
	digest.Digest
	Catalog     CatalogView `json:"catalog"`
	DiscoverNew int         `json:"discover_new"`
}

// ConsentView is one host a source needs consent for: the sentence that
// says what Michel does there, in the request's language, and the exact
// rule that will be written in the policy file.
type ConsentView struct {
	Host    string `json:"host"`
	Purpose string `json:"purpose"`
	What    string `json:"what"`
	Rule    string `json:"rule"`
}

// ConsentBody is the 409 of POST /sources/{key}/enable without consent.
type ConsentBody struct {
	Error   string        `json:"error"`
	Hint    string        `json:"hint,omitempty"`
	Consent []ConsentView `json:"consent"`
}

// PluginRunView is one run of a plugin, without its report file or log.
type PluginRunView struct {
	ID          string `json:"id"`
	SourceKey   string `json:"source_key"`
	Project     string `json:"project"`
	StartedAt   string `json:"started_at"`
	FinishedAt  string `json:"finished_at"`
	ToolVersion string `json:"tool_version"`
	Status      string `json:"status"`
	Error       string `json:"error"`
	Findings    int    `json:"findings"`
}

// PreviewView is GET /sources/{key}/preview: what installing (Kind install)
// or upgrading (Kind upgrade) would bring and do. The folders it names are
// the user's skills folder: the point of the preview.
type PreviewView struct {
	Kind    string           `json:"kind"`
	Install *gitrepo.Preview `json:"install,omitempty"`
	Upgrade *gitrepo.Diff    `json:"upgrade,omitempty"`
}

// noPaths replaces every local path of s (Windows, POSIX, file:// URLs)
// with <path>, after control characters are stripped. Web addresses stay.
//
// A path starts with file:/, a drive (C:\ or C:/) or a share (\\host\)
// after a character that cannot end a word, or with / at the start of the
// text or after a space, quote, "(", "=" or "[". It may hold spaces and
// parentheses, so it runs to the next ": " (Go's error separator), quote,
// line end or end of the text, or to a ")" that no "(" of the path opened:
// in "(see /tmp/x) refused" that ")" closes the text's own group and stays.
func noPaths(s string) string {
	s = scan.SanitizeText(s)
	var b strings.Builder
	for i := 0; i < len(s); {
		if !pathStart(s, i) {
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteString("<path>")
		i = pathEnd(s, i)
	}
	return b.String()
}

// pathStart tells whether a local path starts at s[i].
func pathStart(s string, i int) bool {
	var prev byte = ' '
	if i > 0 {
		prev = s[i-1]
	}
	rest := s[i:]
	switch {
	case strings.HasPrefix(rest, "file:/"):
		return true
	case rest[0] == '/' && strings.IndexByte(" \t\n\v\f\r\"'(=[", prev) >= 0:
		return true
	case isWordByte(prev):
		return false
	case len(rest) >= 3 && isLetter(rest[0]) && rest[1] == ':' && (rest[2] == '\\' || rest[2] == '/'):
		return true
	case strings.HasPrefix(rest, `\\`):
		host, _, found := strings.Cut(rest[2:], `\`)
		return found && host != "" && !strings.ContainsAny(host, " \t\n\v\f\r")
	}
	return false
}

// pathEnd is the index just past the path that starts at s[i].
func pathEnd(s string, i int) int {
	depth := 0
	for ; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\'' || c == '\n':
			return i
		case c == ':' && i+1 < len(s) && s[i+1] == ' ':
			return i
		case c == '(':
			depth++
		case c == ')':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return i
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// isWordByte is a character a drive letter cannot follow: C:\ in a.C:\ or
// 1C:\ is not a path start.
func isWordByte(c byte) bool {
	return isLetter(c) || c >= '0' && c <= '9' || c == '.' || c == '+' || c == '-'
}
