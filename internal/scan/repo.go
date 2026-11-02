package scan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/store"
)

// Finding statuses.
const (
	StatusNew     = "new"
	StatusPending = "pending"
	StatusGone    = "gone"
	// StatusDecided is a finding with a decision in force (package decide).
	StatusDecided = "decided"
)

// Reasons why a decision stops being in force (decision.superseded_reason).
// Package decide names them as decide.Reason values.
const (
	ReasonRedecided           = "redecided"
	ReasonSeverityChanged     = "severity_changed"
	ReasonFixedVersionChanged = "fixed_version_changed"
	ReasonDueReached          = "due_reached"
	ReasonReappearedChanged   = "reappeared_changed"
	// ReasonKEVChanged: the finding entered (or left) CISA's list of
	// vulnerabilities exploited in the wild since the decision.
	ReasonKEVChanged = "kev_changed"
)

// Superseded is a decision a scan took out of force: the finding, its
// project, the reason code and the action of that decision.
type Superseded struct{ FindingID, ProjectID, Reason, Previous string }

// SnapshotChanged compares what was known when a decision was taken
// (severity, fixed versions, KEV) with what is known now. The severity is
// compared exactly and wins; then the fixed versions, compared as sets so
// their order does not count; the KEV mark comes last. reason is
// ReasonSeverityChanged, ReasonFixedVersionChanged, ReasonKEVChanged or "".
func SnapshotChanged(seenSeverity string, seenFixed []string, seenKEV bool, severity string, fixed []string, kev bool) (changed bool, reason string) {
	if seenSeverity != severity {
		return true, ReasonSeverityChanged
	}
	if !sameSet(seenFixed, fixed) {
		return true, ReasonFixedVersionChanged
	}
	if seenKEV != kev {
		return true, ReasonKEVChanged
	}
	return false, ""
}

func sameSet(a, b []string) bool {
	set := func(s []string) []string {
		out := slices.Clone(s)
		slices.Sort(out)
		return slices.Compact(out)
	}
	return slices.Equal(set(a), set(b))
}

// decisionView is what applyScan needs of the decision in force on a finding.
type decisionView struct {
	Action   string
	Severity string
	Fixed    []string
	DueAt    string
	KEV      bool
}

// dueReached tells whether a defer decision has reached its date at now. A
// date Michel cannot read counts as reached, so the finding is asked again.
func (d decisionView) dueReached(now time.Time) bool {
	if d.Action != "defer" || d.DueAt == "" {
		return false
	}
	due, err := time.Parse(time.RFC3339, d.DueAt)
	return err != nil || !due.After(now)
}

// currentDecisions reads, inside tx, the decisions in force of one project,
// by finding id.
func currentDecisions(ctx context.Context, tx *sql.Tx, projectID string) (map[string]decisionView, error) {
	rows, err := tx.QueryContext(ctx, `SELECT finding_id, action, seen_severity, seen_fixed_versions, due_at, seen_kev
		FROM decision WHERE project_id = ? AND superseded_at = '' ORDER BY created_at, id`, projectID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the decisions: %w", err)
	}
	defer rows.Close()
	out := map[string]decisionView{}
	for rows.Next() {
		var id, fixed string
		var kev int
		var d decisionView
		if err := rows.Scan(&id, &d.Action, &d.Severity, &fixed, &d.DueAt, &kev); err != nil {
			return nil, err
		}
		d.KEV = kev != 0
		_ = json.Unmarshal([]byte(fixed), &d.Fixed)
		out[id] = d // the newest wins, should there be several
	}
	return out, rows.Err()
}

// label names f in an error: its OSV id, else its rule.
func label(f Finding) string {
	if f.OSVID != "" {
		return f.OSVID
	}
	return f.RuleID
}

// kindOf is the stored kind of f, KindDependency when unset.
func kindOf(f Finding) string {
	if f.Kind == "" {
		return KindDependency
	}
	return f.Kind
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func jsonList(s []string) string {
	if s == nil {
		s = []string{}
	}
	b, _ := json.Marshal(s)
	return string(b)
}

// applyScan records the findings of one scan inside tx and moves every
// finding of the project to its new status:
//
//	present and unknown          -> new
//	present and new/pending      -> pending
//	present and gone             -> pending (counted as reappeared)
//	absent and not gone          -> gone
//
// current holds the decisions in force of the project (currentDecisions).
// A present finding with one is judged against its snapshot:
//
//	decided, defer whose date is reached     -> pending, decision superseded (due_reached)
//	decided, severity or fixed versions moved -> pending, decision superseded (severity_changed, fixed_version_changed)
//	decided, unchanged                       -> decided
//	gone, decision in force, unchanged       -> decided (counted as reappeared)
//	gone, decision in force, changed or due  -> pending, decision superseded (reappeared_changed, due_reached)
//
// A decided finding that disappears becomes gone and keeps its decision. The
// superseded decisions are returned for the audit log, which the caller
// writes after the commit.
//
// Every status change sets status_changed_at to now; a finding whose status
// stays the same keeps it.
//
// Findings of manifests listed in unread are neither refreshed nor closed:
// the scan could not read that file, so absence proves nothing.
//
// enriched tells whether the findings carry their enrichment (KEV, EPSS,
// enriched CVSS) from Options.Lookup. When false, a finding already stored
// keeps the enrichment it has, and its KEV mark is judged from it.
//
// Only the OSV findings of the project (source_key "") are read and closed:
// a scan never touches what a plugin reported.
func applyScan(ctx context.Context, tx *sql.Tx, projectID, scanID string, now time.Time, findings []Finding, unread map[string]bool, current map[string]decisionView, enriched bool) (newN, still, reappeared, gone int, superseded []Superseded, err error) {
	return apply(ctx, tx, projectID, "", scanID, now, findings, unread, current, enriched)
}

// ApplyExternal records the findings of one plugin run (sourceKey, runID)
// inside tx with the same statuses as a scan (see applyScan). Only the
// findings of the same project and source are closed when absent: a plugin
// run never touches the OSV findings nor another plugin's. A finding that
// comes back counts in still. Each finding's ID is
// FindingID(projectID, sourceKey, "", ruleID, fingerprint or location).
// A nil current reads the decisions in force of the project inside tx.
func ApplyExternal(ctx context.Context, tx *sql.Tx, projectID, sourceKey, runID string, now time.Time, findings []Finding, current map[string]decisionView) (newN, still, gone int, superseded []Superseded, err error) {
	if sourceKey == "" {
		return 0, 0, 0, nil, errors.New("an external finding needs the key of its source")
	}
	if current == nil {
		if current, err = currentDecisions(ctx, tx, projectID); err != nil {
			return 0, 0, 0, nil, err
		}
	}
	newN, still, reappeared, gone, superseded, err := apply(ctx, tx, projectID, sourceKey, runID, now, findings, nil, current, false)
	return newN, still + reappeared, gone, superseded, err
}

// ServerApply shapes ApplyServerFindings. Unread lists the manifest keys
// (such as "os-packages" or "fpm:/usr/sbin/php-fpm8.2") the check could not
// judge: their findings are neither refreshed nor closed. Enriched tells
// that the findings carry their enrichment (see applyScan).
//
// UnreadPrefixes protects, the same way, every stored manifest of the
// server that starts with one of them ("cli:", "fpm:"): the check could not
// even tell which runtimes are there.
type ServerApply struct {
	Unread         []string
	UnreadPrefixes []string
	Enriched       bool
}

// ApplyServerFindings records the findings of one check of a server
// (targetID, runID) inside tx with the statuses of a scan (see applyScan):
// a finding the check no longer sees, without a fix by Michel, becomes gone.
// Server findings keep the target id in project_id and are stored as OSV
// findings (source_key ""), so a plugin's findings are never touched. A
// finding that comes back counts in still. The decisions superseded are
// returned for the audit log, which the caller writes after the commit.
func ApplyServerFindings(ctx context.Context, tx *sql.Tx, targetID, runID string, now time.Time, fs []Finding, o ServerApply) (newN, still, gone int, superseded []Superseded, err error) {
	if targetID == "" {
		return 0, 0, 0, nil, errors.New("a server finding needs the id of its server")
	}
	for _, f := range fs {
		if f.ProjectID != targetID || (f.Kind != KindServerPackage && f.Kind != KindServerConfig) {
			return 0, 0, 0, nil, fmt.Errorf("finding %s is not a finding of server %s", label(f), targetID)
		}
	}
	current, err := currentDecisions(ctx, tx, targetID)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	unread := map[string]bool{}
	for _, m := range o.Unread {
		unread[m] = true
	}
	if len(o.UnreadPrefixes) > 0 {
		rows, err := tx.QueryContext(ctx, `SELECT DISTINCT manifest_rel_path FROM finding WHERE project_id = ? AND source_key = ''`, targetID)
		if err != nil {
			return 0, 0, 0, nil, fmt.Errorf("cannot read the existing findings: %w", err)
		}
		for rows.Next() {
			var m string
			if err := rows.Scan(&m); err != nil {
				rows.Close()
				return 0, 0, 0, nil, err
			}
			for _, p := range o.UnreadPrefixes {
				if strings.HasPrefix(m, p) {
					unread[m] = true
				}
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return 0, 0, 0, nil, err
		}
	}
	newN, still, reappeared, gone, superseded, err := apply(ctx, tx, targetID, "", runID, now, fs, unread, current, o.Enriched)
	return newN, still + reappeared, gone, superseded, err
}

// apply is applyScan for the findings of one source: "" for the OSV scan, a
// plugin key for a plugin run. Only the findings of that source are read and
// closed; the findings are stored with that source key.
func apply(ctx context.Context, tx *sql.Tx, projectID, sourceKey, scanID string, now time.Time, findings []Finding, unread map[string]bool, current map[string]decisionView, enriched bool) (newN, still, reappeared, gone int, superseded []Superseded, err error) {
	ts := now.UTC().Format(time.RFC3339)
	rows, err := tx.QueryContext(ctx, `SELECT id, manifest_rel_path, status, kev, kev_added, epss, epss_percentile, cvss_enriched
		FROM finding WHERE project_id = ? AND source_key = ?`, projectID, sourceKey)
	if err != nil {
		return 0, 0, 0, 0, nil, fmt.Errorf("cannot read the existing findings: %w", err)
	}
	type known struct {
		manifest, status string
		enrichment       Enrichment
	}
	existing := map[string]known{}
	for rows.Next() {
		var id string
		var k known
		var kev int
		if err := rows.Scan(&id, &k.manifest, &k.status, &kev, &k.enrichment.KEVAdded, &k.enrichment.EPSS,
			&k.enrichment.EPSSPercentile, &k.enrichment.CVSS); err != nil {
			rows.Close()
			return 0, 0, 0, 0, nil, err
		}
		k.enrichment.KEV = kev != 0
		existing[id] = k
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, 0, 0, 0, nil, err
	}
	rows.Close()

	ins, err := tx.PrepareContext(ctx, `INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id,
		aliases, severity_label, cvss_score, installed_version, fixed_versions, dep_groups, status,
		first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, summary, status_changed_at, kind, malicious,
		kev, kev_added, epss, epss_percentile, cvss_enriched, source_key, rule_id, location, fingerprint, mitigation, sapi)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, 0, 0, 0, nil, err
	}
	defer ins.Close()
	upd, err := tx.PrepareContext(ctx, `UPDATE finding SET aliases=?, severity_label=?, cvss_score=?, installed_version=?,
		fixed_versions=?, dep_groups=?, status=?, last_seen_scan=?, last_seen_at=?, summary=?, malicious=?,
		kev=?, kev_added=?, epss=?, epss_percentile=?, cvss_enriched=?, location=?, mitigation=?, sapi=?,
		status_changed_at = CASE WHEN status <> ? THEN ? ELSE status_changed_at END WHERE id=?`)
	if err != nil {
		return 0, 0, 0, 0, nil, err
	}
	defer upd.Close()
	closeStmt, err := tx.PrepareContext(ctx, `UPDATE finding SET status=?,
		status_changed_at = CASE WHEN status <> ? THEN ? ELSE status_changed_at END WHERE id=?`)
	if err != nil {
		return 0, 0, 0, 0, nil, err
	}
	defer closeStmt.Close()
	supersede, err := tx.PrepareContext(ctx, `UPDATE decision SET superseded_at=?, superseded_reason=?
		WHERE finding_id=? AND project_id=? AND superseded_at=''`)
	if err != nil {
		return 0, 0, 0, 0, nil, err
	}
	defer supersede.Close()

	present := make(map[string]bool, len(findings))
	for _, f := range findings {
		present[f.ID] = true
		var cvss any
		if f.CVSS > 0 {
			cvss = f.CVSS
		}
		k, ok := existing[f.ID]
		if ok && !enriched {
			f = WithEnrichment(f, k.enrichment)
		}
		if !ok {
			if _, err := ins.ExecContext(ctx, f.ID, projectID, f.ManifestRelPath, f.Ecosystem, f.Package, f.OSVID,
				jsonList(f.Aliases), f.SeverityLabel, cvss, f.InstalledVersion, jsonList(f.FixedVersions), jsonList(f.DepGroups),
				StatusNew, scanID, scanID, ts, ts, f.Summary, ts, kindOf(f), boolInt(f.Malicious),
				boolInt(f.KEV), f.KEVAdded, f.EPSS, f.EPSSPercentile, f.CVSSEnriched, sourceKey, f.RuleID, f.Location, f.Fingerprint, boolInt(f.Mitigation), f.SAPI); err != nil {
				return 0, 0, 0, 0, nil, fmt.Errorf("cannot save finding %s: %w", label(f), err)
			}
			newN++
			continue
		}
		status, reason := StatusPending, ""
		if d, ok := current[f.ID]; ok && (k.status == StatusDecided || k.status == StatusGone) {
			changed, why := SnapshotChanged(d.Severity, d.Fixed, d.KEV, f.SeverityLabel, f.FixedVersions, f.KEV)
			switch {
			case d.dueReached(now):
				reason = ReasonDueReached
			case changed && k.status == StatusGone:
				reason = ReasonReappearedChanged
			case changed:
				reason = why
			default:
				status = StatusDecided
			}
			if reason != "" {
				if _, err := supersede.ExecContext(ctx, ts, reason, f.ID, projectID); err != nil {
					return 0, 0, 0, 0, nil, fmt.Errorf("cannot supersede the decision on %s: %w", label(f), err)
				}
				superseded = append(superseded, Superseded{FindingID: f.ID, ProjectID: projectID, Reason: reason, Previous: d.Action})
			}
		}
		if _, err := upd.ExecContext(ctx, jsonList(f.Aliases), f.SeverityLabel, cvss, f.InstalledVersion,
			jsonList(f.FixedVersions), jsonList(f.DepGroups), status, scanID, ts, f.Summary, boolInt(f.Malicious),
			boolInt(f.KEV), f.KEVAdded, f.EPSS, f.EPSSPercentile, f.CVSSEnriched, f.Location, boolInt(f.Mitigation), f.SAPI, status, ts, f.ID); err != nil {
			return 0, 0, 0, 0, nil, fmt.Errorf("cannot update finding %s: %w", label(f), err)
		}
		if k.status == StatusGone {
			reappeared++
		} else {
			still++
		}
	}
	ids := make([]string, 0, len(existing))
	for id := range existing {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		k := existing[id]
		if present[id] || k.status == StatusGone || unread[k.manifest] {
			continue
		}
		if _, err := closeStmt.ExecContext(ctx, StatusGone, StatusGone, ts, id); err != nil {
			return 0, 0, 0, 0, nil, fmt.Errorf("cannot close finding %s: %w", id, err)
		}
		gone++
	}
	return newN, still, reappeared, gone, superseded, nil
}

// Repo reads findings from the store.
type Repo struct{ s *store.Store }

// NewRepo builds a Repo.
func NewRepo(s *store.Store) *Repo { return &Repo{s: s} }

// findingColumns are the columns scanFinding reads, in order.
const findingColumns = `id, project_id, manifest_rel_path, ecosystem, package, osv_id, aliases, severity_label, cvss_score,
	installed_version, fixed_versions, dep_groups, status, first_seen_at, last_seen_at, summary, kind, malicious,
	kev, kev_added, epss, epss_percentile, cvss_enriched, source_key, rule_id, location, fingerprint, mitigation, sapi`

// scanFinding reads one row of findingColumns.
func scanFinding(rows *sql.Rows) (Finding, error) {
	var f Finding
	var cvss sql.NullFloat64
	var aliases, fixed, groups string
	var malicious, kev, mitigation int
	if err := rows.Scan(&f.ID, &f.ProjectID, &f.ManifestRelPath, &f.Ecosystem, &f.Package, &f.OSVID, &aliases,
		&f.SeverityLabel, &cvss, &f.InstalledVersion, &fixed, &groups, &f.Status, &f.FirstSeenAt, &f.LastSeenAt, &f.Summary,
		&f.Kind, &malicious, &kev, &f.KEVAdded, &f.EPSS, &f.EPSSPercentile, &f.CVSSEnriched,
		&f.SourceKey, &f.RuleID, &f.Location, &f.Fingerprint, &mitigation, &f.SAPI); err != nil {
		return Finding{}, err
	}
	f.CVSS, f.Malicious, f.KEV, f.Mitigation = cvss.Float64, malicious != 0, kev != 0, mitigation != 0
	_ = json.Unmarshal([]byte(aliases), &f.Aliases)
	_ = json.Unmarshal([]byte(fixed), &f.FixedVersions)
	_ = json.Unmarshal([]byte(groups), &f.DepGroups)
	return f, nil
}

// ListFindings returns the findings of a project, the urgent ones (exploited
// in the wild or malicious, see Urgent) first, then the most severe first
// (EffectiveSeverity). An empty status means everything except "gone"; "all"
// means everything; "actionable" means new or pending.
func (r *Repo) ListFindings(ctx context.Context, projectID, status string) ([]Finding, error) {
	q := `SELECT ` + findingColumns + ` FROM finding WHERE project_id = ? AND kind NOT IN ('server_package', 'server_config')`
	args := []any{projectID}
	switch status {
	case "all":
	case "actionable":
		q += ` AND status IN ('new', 'pending')`
	case "":
		q += ` AND status <> 'gone'`
	default:
		q += ` AND status = ?`
		args = append(args, status)
	}
	rows, err := r.s.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("cannot read the findings: %w", err)
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ua, ub := Urgent(a), Urgent(b); ua != ub {
			return ua
		}
		la, _ := EffectiveSeverity(a)
		lb, _ := EffectiveSeverity(b)
		if ra, rb := severityRank(la), severityRank(lb); ra != rb {
			return ra < rb
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.OSVID < b.OSVID
	})
	return out, nil
}

// MaxPrefixMatches caps FindByIDPrefix: a result of that size may hide more.
const MaxPrefixMatches = 50

// FindByIDPrefix returns every finding, in any project and any status, whose
// id starts with prefix (at most MaxPrefixMatches). An empty prefix matches nothing.
func (r *Repo) FindByIDPrefix(ctx context.Context, prefix string) ([]Finding, error) {
	if prefix == "" {
		return []Finding{}, nil
	}
	rows, err := r.s.DB().QueryContext(ctx, `SELECT `+findingColumns+` FROM finding WHERE substr(id, 1, ?) = ? ORDER BY id LIMIT ?`,
		len(prefix), prefix, MaxPrefixMatches)
	if err != nil {
		return nil, fmt.Errorf("cannot look the finding up: %w", err)
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListServerFindings returns every finding of a server (any status), by id.
func (r *Repo) ListServerFindings(ctx context.Context, targetID string) ([]Finding, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT `+findingColumns+` FROM finding WHERE project_id = ? AND source_key = '' AND kind IN ('server_package', 'server_config') ORDER BY id`, targetID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the findings of the server: %w", err)
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
