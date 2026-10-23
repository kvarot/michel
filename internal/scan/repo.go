package scan

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/kvarot/michel/internal/store"
)

// Finding statuses.
const (
	StatusNew     = "new"
	StatusPending = "pending"
	StatusGone    = "gone"
)

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
// Every status change sets status_changed_at to now; a finding whose status
// stays the same keeps it.
//
// Findings of manifests listed in unread are neither refreshed nor closed:
// the scan could not read that file, so absence proves nothing.
func applyScan(ctx context.Context, tx *sql.Tx, projectID, scanID string, now time.Time, findings []Finding, unread map[string]bool) (newN, still, reappeared, gone int, err error) {
	ts := now.UTC().Format(time.RFC3339)
	rows, err := tx.QueryContext(ctx, `SELECT id, manifest_rel_path, status FROM finding WHERE project_id = ?`, projectID)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("cannot read the existing findings: %w", err)
	}
	type known struct{ manifest, status string }
	existing := map[string]known{}
	for rows.Next() {
		var id string
		var k known
		if err := rows.Scan(&id, &k.manifest, &k.status); err != nil {
			rows.Close()
			return 0, 0, 0, 0, err
		}
		existing[id] = k
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, 0, 0, 0, err
	}
	rows.Close()

	ins, err := tx.PrepareContext(ctx, `INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id,
		aliases, severity_label, cvss_score, installed_version, fixed_versions, dep_groups, status,
		first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, summary, status_changed_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer ins.Close()
	upd, err := tx.PrepareContext(ctx, `UPDATE finding SET aliases=?, severity_label=?, cvss_score=?, installed_version=?,
		fixed_versions=?, dep_groups=?, status=?, last_seen_scan=?, last_seen_at=?, summary=?,
		status_changed_at = CASE WHEN status <> ? THEN ? ELSE status_changed_at END WHERE id=?`)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer upd.Close()
	closeStmt, err := tx.PrepareContext(ctx, `UPDATE finding SET status=?,
		status_changed_at = CASE WHEN status <> ? THEN ? ELSE status_changed_at END WHERE id=?`)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer closeStmt.Close()

	present := make(map[string]bool, len(findings))
	for _, f := range findings {
		present[f.ID] = true
		var cvss any
		if f.CVSS > 0 {
			cvss = f.CVSS
		}
		k, ok := existing[f.ID]
		if !ok {
			if _, err := ins.ExecContext(ctx, f.ID, projectID, f.ManifestRelPath, f.Ecosystem, f.Package, f.OSVID,
				jsonList(f.Aliases), f.SeverityLabel, cvss, f.InstalledVersion, jsonList(f.FixedVersions), jsonList(f.DepGroups),
				StatusNew, scanID, scanID, ts, ts, f.Summary, ts); err != nil {
				return 0, 0, 0, 0, fmt.Errorf("cannot save finding %s: %w", f.OSVID, err)
			}
			newN++
			continue
		}
		if _, err := upd.ExecContext(ctx, jsonList(f.Aliases), f.SeverityLabel, cvss, f.InstalledVersion,
			jsonList(f.FixedVersions), jsonList(f.DepGroups), StatusPending, scanID, ts, f.Summary, StatusPending, ts, f.ID); err != nil {
			return 0, 0, 0, 0, fmt.Errorf("cannot update finding %s: %w", f.OSVID, err)
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
			return 0, 0, 0, 0, fmt.Errorf("cannot close finding %s: %w", id, err)
		}
		gone++
	}
	return newN, still, reappeared, gone, nil
}

// Repo reads findings from the store.
type Repo struct{ s *store.Store }

// NewRepo builds a Repo.
func NewRepo(s *store.Store) *Repo { return &Repo{s: s} }

// ListFindings returns the findings of a project, most severe first. An empty
// status means everything except "gone"; "all" means everything; "actionable"
// means new or pending.
func (r *Repo) ListFindings(ctx context.Context, projectID, status string) ([]Finding, error) {
	q := `SELECT id, project_id, manifest_rel_path, ecosystem, package, osv_id, aliases, severity_label, cvss_score,
		installed_version, fixed_versions, dep_groups, status, first_seen_at, last_seen_at, summary
		FROM finding WHERE project_id = ?`
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
		var f Finding
		var cvss sql.NullFloat64
		var aliases, fixed, groups string
		if err := rows.Scan(&f.ID, &f.ProjectID, &f.ManifestRelPath, &f.Ecosystem, &f.Package, &f.OSVID, &aliases,
			&f.SeverityLabel, &cvss, &f.InstalledVersion, &fixed, &groups, &f.Status, &f.FirstSeenAt, &f.LastSeenAt, &f.Summary); err != nil {
			return nil, err
		}
		f.CVSS = cvss.Float64
		_ = json.Unmarshal([]byte(aliases), &f.Aliases)
		_ = json.Unmarshal([]byte(fixed), &f.FixedVersions)
		_ = json.Unmarshal([]byte(groups), &f.DepGroups)
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := severityRank(a.SeverityLabel), severityRank(b.SeverityLabel); ra != rb {
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
	rows, err := r.s.DB().QueryContext(ctx, `SELECT id, project_id, manifest_rel_path, ecosystem, package, osv_id, aliases,
		severity_label, cvss_score, installed_version, fixed_versions, dep_groups, status, first_seen_at, last_seen_at, summary
		FROM finding WHERE substr(id, 1, ?) = ? ORDER BY id LIMIT ?`, len(prefix), prefix, MaxPrefixMatches)
	if err != nil {
		return nil, fmt.Errorf("cannot look the finding up: %w", err)
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		var f Finding
		var cvss sql.NullFloat64
		var aliases, fixed, groups string
		if err := rows.Scan(&f.ID, &f.ProjectID, &f.ManifestRelPath, &f.Ecosystem, &f.Package, &f.OSVID, &aliases,
			&f.SeverityLabel, &cvss, &f.InstalledVersion, &fixed, &groups, &f.Status, &f.FirstSeenAt, &f.LastSeenAt, &f.Summary); err != nil {
			return nil, err
		}
		f.CVSS = cvss.Float64
		_ = json.Unmarshal([]byte(aliases), &f.Aliases)
		_ = json.Unmarshal([]byte(fixed), &f.FixedVersions)
		_ = json.Unmarshal([]byte(groups), &f.DepGroups)
		out = append(out, f)
	}
	return out, rows.Err()
}
