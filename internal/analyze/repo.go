package analyze

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kvarot/michel/internal/store"
)

const (
	maxPersistedSites = 200
)

// Repo stores analyses.
type Repo struct{ s *store.Store }

// NewRepo builds a Repo.
func NewRepo(s *store.Store) *Repo { return &Repo{s: s} }

type storedSite struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	IsTest bool   `json:"is_test"`
}

func js(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// cutUTF8 truncates s to at most n bytes without splitting a character.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// Save stores a (insert or replace). Snippets are not stored, and the
// call sites and changelog excerpt are capped.
func (r *Repo) Save(ctx context.Context, a Analysis) error {
	sites := make([]storedSite, 0, len(a.Calls.Sites))
	for _, s := range a.Calls.Sites {
		if len(sites) == maxPersistedSites {
			break
		}
		sites = append(sites, storedSite{s.File, s.Line, s.IsTest})
	}
	var allows any
	if a.Upgrade.ConstraintAllows != nil {
		allows = b2i(*a.Upgrade.ConstraintAllows)
	}
	terms := a.Risk.Terms
	if terms == nil {
		terms = map[string]int{}
	}
	_, err := r.s.DB().ExecContext(ctx, `INSERT INTO analysis (finding_id, computed_at, michel_version, directness, via,
		root_constraint, has_root_manifest, target_version, jump, constraint_allows, call_sites, call_site_count,
		call_sites_quality, namespaces, test_files, test_count, test_method, changelog_source, changelog_excerpt,
		changelog_available, breaking, breaking_lines, risk_score, risk_terms, recommendation, warning,
		inputs_hash, project_id, changelog_note, notes, calls_unreadable, calls_unreadable_paths, calls_test_files,
		calls_test_file_count, calls_test_hit_count, calls_source_files, coverage_skipped, coverage_unreadable)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(finding_id) DO UPDATE SET computed_at=excluded.computed_at, michel_version=excluded.michel_version,
		directness=excluded.directness, via=excluded.via, root_constraint=excluded.root_constraint,
		has_root_manifest=excluded.has_root_manifest, target_version=excluded.target_version, jump=excluded.jump,
		constraint_allows=excluded.constraint_allows, call_sites=excluded.call_sites, call_site_count=excluded.call_site_count,
		call_sites_quality=excluded.call_sites_quality, namespaces=excluded.namespaces, test_files=excluded.test_files,
		test_count=excluded.test_count, test_method=excluded.test_method, changelog_source=excluded.changelog_source,
		changelog_excerpt=excluded.changelog_excerpt, changelog_available=excluded.changelog_available,
		breaking=excluded.breaking, breaking_lines=excluded.breaking_lines, risk_score=excluded.risk_score,
		risk_terms=excluded.risk_terms, recommendation=excluded.recommendation, warning=excluded.warning,
		inputs_hash=excluded.inputs_hash, project_id=excluded.project_id, changelog_note=excluded.changelog_note,
		notes=excluded.notes, calls_unreadable=excluded.calls_unreadable, calls_unreadable_paths=excluded.calls_unreadable_paths,
		calls_test_files=excluded.calls_test_files, calls_test_file_count=excluded.calls_test_file_count,
		calls_test_hit_count=excluded.calls_test_hit_count, calls_source_files=excluded.calls_source_files,
		coverage_skipped=excluded.coverage_skipped, coverage_unreadable=excluded.coverage_unreadable`,
		a.FindingID, a.ComputedAt.UTC().Format(time.RFC3339), a.MichelVersion, string(a.Path.Directness),
		js(nonNil(a.Path.Via)), a.Path.Constraint, b2i(a.HasRootManifest), a.Upgrade.Target, string(a.Upgrade.Jump), allows,
		js(sites), a.Calls.Count, a.Calls.Quality, js(nonNil(a.Calls.Namespaces)), js(nonNil(a.Coverage.TestFiles)),
		a.Coverage.Count, a.Coverage.Method, a.Changelog.Source, cutUTF8(a.Changelog.Excerpt, maxExcerptBytes),
		b2i(a.Changelog.Available), b2i(a.Changelog.Breaking), js(nonNil(a.Changelog.BreakingLines)),
		a.Risk.Score, js(terms), string(a.Risk.Recommendation), b2i(a.Risk.Warning),
		a.InputsHash, a.ProjectID, a.Changelog.Note, js(nonNil(a.Notes)), a.Calls.Unreadable,
		js(nonNil(a.Calls.UnreadablePaths)), js(nonNil(a.Calls.TestFiles)), a.Calls.TestFileCount, a.Calls.TestHitCount,
		js(nonNil(a.Calls.SourceFiles)), js(nonNil(a.Coverage.Skipped)), a.Coverage.Unreadable)
	if err != nil {
		return fmt.Errorf("cannot save the analysis of finding %s: %w", a.FindingID, err)
	}
	return nil
}

// Get reads the analysis of a finding; found is false when there is none.
func (r *Repo) Get(ctx context.Context, findingID string) (Analysis, bool, error) {
	var a Analysis
	var computed, dir, via, sites, ns, tests, bl, terms, jump, rec string
	var notes, unreadablePaths, callTests, sources, skipped string
	var hasRoot, allows, breaking, avail, warn sql.NullInt64
	row := r.s.DB().QueryRowContext(ctx, `SELECT computed_at, michel_version, COALESCE(directness,''), via, root_constraint,
		has_root_manifest, target_version, jump, constraint_allows, call_sites, call_site_count, call_sites_quality,
		namespaces, test_files, test_count, test_method, changelog_source, changelog_excerpt, changelog_available,
		breaking, breaking_lines, risk_score, risk_terms, recommendation, warning, inputs_hash, project_id, changelog_note,
		notes, calls_unreadable, calls_unreadable_paths, calls_test_files, calls_test_file_count, calls_test_hit_count,
		calls_source_files, coverage_skipped, coverage_unreadable
		FROM analysis WHERE finding_id = ?`, findingID)
	err := row.Scan(&computed, &a.MichelVersion, &dir, &via, &a.Path.Constraint, &hasRoot, &a.Upgrade.Target, &jump,
		&allows, &sites, &a.Calls.Count, &a.Calls.Quality, &ns, &tests, &a.Coverage.Count, &a.Coverage.Method,
		&a.Changelog.Source, &a.Changelog.Excerpt, &avail, &breaking, &bl, &a.Risk.Score, &terms, &rec, &warn,
		&a.InputsHash, &a.ProjectID, &a.Changelog.Note, &notes, &a.Calls.Unreadable, &unreadablePaths, &callTests,
		&a.Calls.TestFileCount, &a.Calls.TestHitCount, &sources, &skipped, &a.Coverage.Unreadable)
	if errors.Is(err, sql.ErrNoRows) {
		return Analysis{}, false, nil
	}
	if err != nil {
		return Analysis{}, false, fmt.Errorf("cannot read the analysis of finding %s: %w", findingID, err)
	}
	a.FindingID = findingID
	t, perr := time.Parse(time.RFC3339, computed)
	if perr != nil {
		return Analysis{}, false, fmt.Errorf("cannot read the analysis of finding %s: bad computed_at %q", findingID, computed)
	}
	a.ComputedAt = t
	a.Path.Directness, a.Upgrade.Jump, a.Risk.Recommendation = Directness(dir), Jump(jump), Recommendation(rec)
	a.HasRootManifest, a.Changelog.Available = hasRoot.Int64 != 0, avail.Int64 != 0
	a.Changelog.Breaking, a.Risk.Warning = breaking.Int64 != 0, warn.Int64 != 0
	if allows.Valid {
		v := allows.Int64 != 0
		a.Upgrade.ConstraintAllows = &v
	}
	var st []storedSite
	for _, d := range []struct {
		raw string
		to  any
	}{{sites, &st}, {via, &a.Path.Via}, {ns, &a.Calls.Namespaces}, {tests, &a.Coverage.TestFiles},
		{bl, &a.Changelog.BreakingLines}, {terms, &a.Risk.Terms}, {notes, &a.Notes},
		{unreadablePaths, &a.Calls.UnreadablePaths}, {callTests, &a.Calls.TestFiles}, {sources, &a.Calls.SourceFiles},
		{skipped, &a.Coverage.Skipped}} {
		if err := json.Unmarshal([]byte(d.raw), d.to); err != nil {
			return Analysis{}, false, fmt.Errorf("cannot read the analysis of finding %s: stored JSON is damaged: %w", findingID, err)
		}
	}
	for _, s := range st {
		a.Calls.Sites = append(a.Calls.Sites, CallSite{File: s.File, Line: s.Line, IsTest: s.IsTest})
	}
	// The urgency is not a column: it follows from the "exploited" flag.
	if a.Risk.Terms["exploited"] != 0 {
		a.Risk.Urgency = UrgencyUrgent
	}
	// These lists come back nil when empty, as the analysis produces them, so
	// a stored analysis reads the same as a fresh one.
	for _, l := range []*[]string{&a.Notes, &a.Calls.UnreadablePaths, &a.Calls.TestFiles, &a.Calls.SourceFiles, &a.Coverage.Skipped} {
		if len(*l) == 0 {
			*l = nil
		}
	}
	return a, true, nil
}
