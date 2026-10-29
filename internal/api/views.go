package api

import (
	"path/filepath"
	"strings"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/explain"
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
	Name           string         `json:"name"`
	Classification string         `json:"classification"`
	FixLevel       int            `json:"fix_level"`
	Open           map[string]int `json:"open"`
	Decided        map[string]int `json:"decided"`
	Total          int            `json:"total"`
	// LastScanAt is the start of the newest scan, RFC 3339, "" when never
	// scanned; LastScanStatus is its status, or "never".
	LastScanAt     string `json:"last_scan_at"`
	LastScanStatus string `json:"last_scan_status"`
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
