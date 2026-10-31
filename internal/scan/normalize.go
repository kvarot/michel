package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Finding is one vulnerability affecting one package in one manifest.
type Finding struct {
	ID               string   `json:"id"`
	ProjectID        string   `json:"project_id"`
	ManifestRelPath  string   `json:"manifest_rel_path"`
	Ecosystem        string   `json:"ecosystem"`
	Package          string   `json:"package"`
	OSVID            string   `json:"osv_id"`
	Aliases          []string `json:"aliases"`
	SeverityLabel    string   `json:"severity"`
	CVSS             float64  `json:"cvss"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersions    []string `json:"fixed_versions"`
	DepGroups        []string `json:"dep_groups"`
	Summary          string   `json:"summary"`
	// Kind is the sort of finding: KindDependency for a vulnerable package.
	Kind string `json:"kind"`
	// Mitigation marks a server finding that only holds a flaw back (a
	// setting that blocks its path): it never closes the upstream finding.
	// SAPI is the PHP SAPI ("cli", "fpm") a server finding is about.
	Mitigation bool   `json:"mitigation,omitempty"`
	SAPI       string `json:"sapi,omitempty"`
	// Malicious marks an OSV MAL- advisory: the package itself is malware.
	Malicious bool `json:"malicious"`
	// KEV is true when one of the finding's CVEs is on CISA's Known
	// Exploited Vulnerabilities list, since KEVAdded (YYYY-MM-DD). EPSS and
	// EPSSPercentile are FIRST's exploitation score; CVSSEnriched is a CVSS
	// read from a CVE record (see EffectiveSeverity). All come from the
	// enrichment sources, never from the OSV advisory.
	KEV            bool    `json:"kev"`
	KEVAdded       string  `json:"kev_added"`
	EPSS           float64 `json:"epss"`
	EPSSPercentile float64 `json:"epss_percentile"`
	CVSSEnriched   float64 `json:"cvss_enriched"`
	// SourceKey is the plugin source that reported the finding ("" for an
	// OSV finding); RuleID, Location (a path relative to the project, with
	// ":line" when known) and Fingerprint come from the tool's report.
	SourceKey   string `json:"source_key"`
	RuleID      string `json:"rule_id"`
	Location    string `json:"location"`
	Fingerprint string `json:"fingerprint"`

	// Set when read back from the store.
	Status      string `json:"status,omitempty"`
	FirstSeenAt string `json:"first_seen_at,omitempty"`
	LastSeenAt  string `json:"last_seen_at,omitempty"`
}

// KindDependency is the kind of a finding on a package of a lockfile.
const KindDependency = "dependency"

// Kinds of the findings on a server: a vulnerable system package, and an
// unsafe configuration directive. Their project_id column holds the target id.
const (
	KindServerPackage = "server_package"
	KindServerConfig  = "server_config"
)

// IsMalicious tells whether an OSV id is a malicious-package advisory.
func IsMalicious(osvID string) bool { return strings.HasPrefix(osvID, "MAL-") }

// ManifestResult is the outcome for one lockfile.
type ManifestResult struct {
	RelPath    string `json:"rel_path"`
	Ecosystem  string `json:"ecosystem"`
	LockSHA256 string `json:"lock_sha256"`
	Packages   int    `json:"packages"`
	Findings   int    `json:"findings"`
	Err        error  `json:"-"`
	Error      string `json:"error,omitempty"`
}

// FindingID is the stable identity of a finding: the first 16 hex characters
// of the SHA-256 of its coordinates.
func FindingID(projectID, manifestRelPath, ecosystem, pkg, osvID string) string {
	sum := sha256.Sum256([]byte(projectID + "|" + manifestRelPath + "|" + ecosystem + "|" + pkg + "|" + osvID))
	return hex.EncodeToString(sum[:])[:16]
}

// relPath returns the slash-separated path of source relative to root.
// It fails when source is not inside root.
func relPath(root, source string) (string, error) {
	rel, err := filepath.Rel(root, source)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s is not inside the project folder %s", source, root)
	}
	return filepath.ToSlash(rel), nil
}

// FixedVersions returns the "fixed" events of the ECOSYSTEM and SEMVER ranges
// that concern the given package, without duplicates, in order of appearance.
func FixedVersions(v *osvschema.Vulnerability, ecosystem, pkg string) []string {
	out := []string{}
	for _, a := range v.GetAffected() {
		if a.GetPackage().GetName() != pkg {
			continue
		}
		if e := a.GetPackage().GetEcosystem(); e != "" && e != ecosystem {
			continue
		}
		for _, r := range a.GetRanges() {
			if t := r.GetType(); t != osvschema.Range_ECOSYSTEM && t != osvschema.Range_SEMVER {
				continue
			}
			for _, ev := range r.GetEvents() {
				if f := ev.GetFixed(); f != "" && !slices.Contains(out, f) {
					out = append(out, f)
				}
			}
		}
	}
	return out
}

// severityOf finds the severity of vulnerability id in the package's groups,
// falling back to the advisory's textual database_specific.severity.
func severityOf(pv models.PackageVulns, v *osvschema.Vulnerability) (string, float64) {
	for _, g := range pv.Groups {
		if slices.Contains(g.IDs, v.GetId()) {
			if label, score := SeverityLabel(g.MaxSeverity); label != "unknown" {
				return label, score
			}
		}
	}
	if f := v.GetDatabaseSpecific().GetFields()["severity"]; f != nil {
		if l := labelFromAdvisory(f.GetStringValue()); l != "" {
			return l, 0
		}
	}
	return "unknown", 0
}

// Normalize flattens osv-scanner results into findings and per-manifest
// results. Paths are made relative to projectRoot with forward slashes.
func Normalize(projectID, projectRoot string, r models.VulnerabilityResults) ([]Finding, []ManifestResult) {
	findings := []Finding{}
	manifests := []ManifestResult{}
	seen := map[string]bool{}
	for _, res := range r.Results {
		rel, rerr := relPath(projectRoot, res.Source.Path)
		if rerr != nil {
			manifests = append(manifests, ManifestResult{
				RelPath: filepath.ToSlash(res.Source.Path), Packages: len(res.Packages),
				Err: fmt.Errorf("cannot place %s in the project: %w", res.Source.Path, rerr),
			})
			continue
		}
		mr := ManifestResult{RelPath: rel, Packages: len(res.Packages)}
		for _, pv := range res.Packages {
			if mr.Ecosystem == "" {
				mr.Ecosystem = pv.Package.Ecosystem
			}
			for _, v := range pv.Vulnerabilities {
				id := FindingID(projectID, rel, pv.Package.Ecosystem, pv.Package.Name, v.GetId())
				if seen[id] {
					continue
				}
				seen[id] = true
				label, score := severityOf(pv, v)
				malicious := IsMalicious(v.GetId())
				if malicious {
					// A malicious package is never a minor matter, whatever
					// the advisory scores (MAL- advisories usually have none).
					label = "critical"
				}
				// Package names, ids and paths are lookup keys and stay as read;
				// they are sanitized where they are printed. Free text is
				// sanitized here, at the source.
				aliases := SanitizeAll(append([]string{}, v.GetAliases()...))
				groups := append([]string{}, pv.DepGroups...)
				findings = append(findings, Finding{
					ID: id, ProjectID: projectID, ManifestRelPath: rel,
					Ecosystem: pv.Package.Ecosystem, Package: pv.Package.Name, OSVID: v.GetId(),
					Aliases: aliases, SeverityLabel: label, CVSS: score,
					InstalledVersion: pv.Package.Version,
					FixedVersions:    FixedVersions(v, pv.Package.Ecosystem, pv.Package.Name),
					DepGroups:        groups, Summary: SanitizeText(v.GetSummary()),
					Kind: KindDependency, Malicious: malicious,
				})
				mr.Findings++
			}
		}
		manifests = append(manifests, mr)
	}
	sort.SliceStable(manifests, func(i, j int) bool { return manifests[i].RelPath < manifests[j].RelPath })
	return findings, manifests
}

// Ref names f for a listing: package, advisory id and manifest for a
// dependency finding; for a plugin finding, the tool (its source key without
// "plugin."), the rule and the location.
func Ref(f Finding) (what, id, where string) {
	if f.Kind == "" || f.Kind == KindDependency {
		return f.Package, f.OSVID, f.ManifestRelPath
	}
	return strings.TrimPrefix(f.SourceKey, "plugin."), f.RuleID, f.Location
}
