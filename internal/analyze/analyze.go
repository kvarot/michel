package analyze

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/store"
)

// Analysis is every offline fact Michel computed about one finding.
// Its JSON form (snake_case keys) is part of 'michel finding --json'.
type Analysis struct {
	FindingID string `json:"finding_id"`
	// ProjectID is the project the finding belongs to.
	ProjectID       string    `json:"project_id"`
	ComputedAt      time.Time `json:"computed_at"`
	MichelVersion   string    `json:"michel_version"`
	Path            DepPath   `json:"path"`
	HasRootManifest bool      `json:"has_root_manifest"`
	Upgrade         Upgrade   `json:"upgrade"`
	// Calls has no Snippet once persisted, and never in JSON.
	Calls     CallSites `json:"calls"`
	Coverage  Coverage  `json:"coverage"`
	Changelog Changelog `json:"changelog"`
	Risk      Risk      `json:"risk"`
	// InputsHash fingerprints the settings the analysis depends on besides
	// the finding (risk rule, core packages, exclusions); see InputsHash.
	InputsHash string `json:"inputs_hash"`
	// Notes explains degraded results (for example a missing lockfile), in
	// English.
	Notes []string `json:"notes,omitempty"`
}

// InputsHash is the SHA-256 (hex) of the canonical JSON of the settings an
// analysis depends on, besides the finding and the files: the effective risk
// rule (policy plus the project's overrides), the sorted core packages, the
// exclusions and whether this package is a core package. A stored analysis
// whose hash differs is no longer fresh.
func InputsHash(cfg policy.RiskConfig, p project.Project, exclude []string, core bool) string {
	eff := cfg.WithOverrides(p.RiskOverrides)
	cores := append([]string{}, p.CorePackages...)
	sort.Strings(cores)
	ex := append([]string{}, exclude...)
	sort.Strings(ex)
	doc := struct {
		Risk     map[string]int `json:"risk"`
		Core     []string       `json:"core_packages"`
		Excludes []string       `json:"excludes"`
		IsCore   bool           `json:"is_core"`
	}{riskMap(eff), cores, ex, core}
	b, _ := json.Marshal(doc) // maps marshal with sorted keys: canonical
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// riskMap lists every value of the risk rule by its policy key.
func riskMap(r policy.RiskConfig) map[string]int {
	return map[string]int{
		"major_jump": r.MajorJump, "breaking": r.Breaking, "direct": r.Direct,
		"many_call_sites": r.ManyCallSites, "no_tests": r.NoTests, "core_package": r.CorePackage,
		"many_call_sites_threshold": r.ManyCallSitesThreshold,
		"auto_fix_below":            r.AutoFixBelow, "handoff_up_to": r.HandoffUpTo,
	}
}

// isCore tells whether pkg is one of the project's core packages: ignoring
// case for Packagist, exact for npm.
func isCore(p project.Project, ecosystem, pkg string) bool {
	for _, c := range p.CorePackages {
		if c == pkg || (strings.EqualFold(ecosystem, "Packagist") && strings.EqualFold(c, pkg)) {
			return true
		}
	}
	return false
}

func manifestDir(projectRoot, manifestRelPath string) string {
	return filepath.Dir(filepath.Join(projectRoot, filepath.FromSlash(manifestRelPath)))
}

// Analyze computes the analysis of one finding. It is pure: no database, no
// audit. It loads the dependency graph itself; Run shares graphs instead.
func Analyze(projectRoot string, p project.Project, f scan.Finding, cfg policy.RiskConfig, exclude []string) (Analysis, error) {
	g, err := LoadDepGraph(manifestDir(projectRoot, f.ManifestRelPath), f.Ecosystem, filepath.Base(f.ManifestRelPath))
	return AnalyzeWith(g, err, projectRoot, p, f, cfg, exclude)
}

// AnalyzeWith is Analyze with an already loaded graph. loadErr is the error
// of that load: it is not fatal, the path becomes "unknown" and a note says why.
func AnalyzeWith(g *DepGraph, loadErr error, projectRoot string, p project.Project, f scan.Finding, cfg policy.RiskConfig, exclude []string) (Analysis, error) {
	core := isCore(p, f.Ecosystem, f.Package)
	a := Analysis{FindingID: f.ID, ProjectID: f.ProjectID, InputsHash: InputsHash(cfg, p, exclude, core)}
	if a.ProjectID == "" {
		a.ProjectID = p.ID
	}
	if loadErr != nil || g == nil {
		a.Path = DepPath{Directness: Unknown}
		msg := "no dependency graph"
		if loadErr != nil {
			msg = loadErr.Error()
		}
		a.Notes = append(a.Notes, "dependency graph unavailable: "+msg)
	} else {
		a.Path = g.PathTo(f.Package)
		a.HasRootManifest = g.HasRootManifest
	}
	a.Upgrade = PlanUpgrade(f.Ecosystem, f.InstalledVersion, f.FixedVersions, a.Path.Constraint)
	calls, err := FindCallSites(projectRoot, f.ManifestRelPath, f.Ecosystem, f.Package, exclude)
	if err != nil {
		return a, fmt.Errorf("cannot search the call sites of %s: %w", f.Package, err)
	}
	a.Calls = calls
	cov, err := FindCoveringTests(projectRoot, f.ManifestRelPath, calls, f.Ecosystem, exclude)
	if err != nil {
		return a, fmt.Errorf("cannot search the tests covering %s: %w", f.Package, err)
	}
	a.Coverage = cov
	a.Changelog = ReadChangelog(projectRoot, f.ManifestRelPath, f.Ecosystem, f.Package, f.InstalledVersion, a.Upgrade.Target)
	a.Risk = ScoreRisk(cfg, p.RiskOverrides, RiskInput{
		Jump: a.Upgrade.Jump, Breaking: a.Changelog.Breaking, Directness: a.Path.Directness,
		CallSiteCount: a.Calls.Count, TestCount: a.Coverage.Count, TestMethod: a.Coverage.Method,
		IsCore: core, HasFix: a.Upgrade.Target != "",
		// Exploited in the wild (KEV) or malicious: a flag and the urgency, no point.
		Exploited: scan.Urgent(f),
	})
	return a, nil
}

// Deps are the collaborators of Run.
type Deps struct {
	Store   *store.Store
	Audit   *audit.Logger
	Version string
	Now     func() time.Time
	Risk    policy.RiskConfig
}

// Options tunes Run.
type Options struct {
	// Force recomputes analyses that are still fresh.
	Force bool
}

// RunResult is the outcome of Run.
type RunResult struct {
	Analyzed, Skipped, Failed int
	Errors                    []error
	Duration                  time.Duration
}

// loadGraph is swapped by tests to count graph loads.
var loadGraph = LoadDepGraph

type graphEntry struct {
	g   *DepGraph
	err error
}

// Run analyzes the findings of one project and stores the results.
func Run(ctx context.Context, deps Deps, p project.Project, findings []scan.Finding, opt Options) (RunResult, error) {
	var res RunResult
	started := deps.Now()
	repo := NewRepo(deps.Store)
	record := func(action, result string, ev map[string]any) {
		if deps.Audit == nil {
			return
		}
		if _, err := deps.Audit.Record(context.WithoutCancel(ctx), audit.Event{Actor: "analyze", Action: action, Target: p.Name, Result: result, Evidence: ev}); err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("cannot write the audit log: %w", err))
		}
	}
	record("analyze.start", "ok", map[string]any{"project_id": p.ID, "findings": len(findings)})

	exclude := scan.EffectiveExclude(p)
	graphs := map[string]graphEntry{}
	for _, f := range findings {
		if err := ctx.Err(); err != nil {
			res.Duration = deps.Now().Sub(started)
			record("analyze.finish", "failed", map[string]any{"analyzed": res.Analyzed, "skipped": res.Skipped,
				"failed": res.Failed, "duration_ms": res.Duration.Milliseconds(), "reason": "cancelled"})
			return res, err
		}
		if !opt.Force {
			old, ok, gerr := repo.Get(ctx, f.ID)
			if gerr != nil {
				slog.Warn("stored analysis unreadable, recomputing", "finding", f.ID, "err", gerr)
			} else if ok && fresh(old, f, deps.Version, InputsHash(deps.Risk, p, exclude, isCore(p, f.Ecosystem, f.Package))) {
				res.Skipped++
				continue
			}
		}
		key := f.Ecosystem + "\x00" + f.ManifestRelPath
		ge, ok := graphs[key]
		if !ok {
			ge.g, ge.err = loadGraph(manifestDir(p.Path, f.ManifestRelPath), f.Ecosystem, filepath.Base(f.ManifestRelPath))
			graphs[key] = ge
		}
		a, err := AnalyzeWith(ge.g, ge.err, p.Path, p, f, deps.Risk, exclude)
		if err == nil {
			a.ComputedAt, a.MichelVersion = deps.Now().UTC(), deps.Version
			err = repo.Save(ctx, a)
		}
		if err != nil {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Errorf("%s (%s): %w", f.Package, f.OSVID, err))
			continue
		}
		res.Analyzed++
	}
	res.Duration = deps.Now().Sub(started)
	result := "ok"
	switch {
	case res.Failed > 0 && res.Analyzed == 0:
		result = "failed"
	case res.Failed > 0:
		result = "partial"
	}
	record("analyze.finish", result, map[string]any{"analyzed": res.Analyzed, "skipped": res.Skipped,
		"failed": res.Failed, "duration_ms": res.Duration.Milliseconds()})
	return res, nil
}

// fresh tells whether a stored analysis is still valid for the finding: same
// Michel version, same settings (inputsHash) and computed after the last scan
// that saw the finding.
func fresh(a Analysis, f scan.Finding, version, inputsHash string) bool {
	if a.MichelVersion != version || a.InputsHash != inputsHash {
		return false
	}
	// The KEV mark can change without a scan (enrichment): the stored
	// urgency must follow it.
	if (a.Risk.Terms["exploited"] != 0) != scan.Urgent(f) {
		return false
	}
	seen, err := time.Parse(time.RFC3339, f.LastSeenAt)
	if err != nil {
		return false
	}
	return !a.ComputedAt.Before(seen)
}
