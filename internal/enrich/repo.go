package enrich

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/scan"
)

// replaceKEV swaps the whole kev table for rows, in one transaction.
func replaceKEV(ctx context.Context, db *sql.DB, rows []kevRow) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot store the KEV list: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM kev`); err != nil {
		return fmt.Errorf("cannot store the KEV list: %w", err)
	}
	st, err := tx.PrepareContext(ctx, `INSERT INTO kev (cve, vendor, product, name, date_added, due_date, ransomware, notes_url)
		VALUES (?,?,?,?,?,?,?,?) ON CONFLICT (cve) DO UPDATE SET vendor = excluded.vendor, product = excluded.product,
		name = excluded.name, date_added = excluded.date_added, due_date = excluded.due_date, ransomware = excluded.ransomware,
		notes_url = excluded.notes_url`)
	if err != nil {
		return fmt.Errorf("cannot store the KEV list: %w", err)
	}
	defer st.Close()
	for _, r := range rows {
		if _, err := st.ExecContext(ctx, r.cve, r.vendor, r.product, r.name, r.added, r.due, r.ransomware, r.notesURL); err != nil {
			return fmt.Errorf("cannot store the KEV list: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cannot store the KEV list: %w", err)
	}
	return nil
}

// replaceEPSS swaps the whole epss table for rows, in one transaction.
func replaceEPSS(ctx context.Context, db *sql.DB, rows []epssRow, modelDate string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot store the EPSS scores: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM epss`); err != nil {
		return fmt.Errorf("cannot store the EPSS scores: %w", err)
	}
	st, err := tx.PrepareContext(ctx, `INSERT INTO epss (cve, score, percentile, model_date) VALUES (?,?,?,?)
		ON CONFLICT (cve) DO UPDATE SET score = excluded.score, percentile = excluded.percentile, model_date = excluded.model_date`)
	if err != nil {
		return fmt.Errorf("cannot store the EPSS scores: %w", err)
	}
	defer st.Close()
	for _, r := range rows {
		if _, err := st.ExecContext(ctx, r.cve, r.score, r.percentile, modelDate); err != nil {
			return fmt.Errorf("cannot store the EPSS scores: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cannot store the EPSS scores: %w", err)
	}
	return nil
}

// ApplyResult is what Apply changed: the findings whose enrichment moved,
// those newly marked KEV, and the decisions taken out of force.
type ApplyResult struct{ Updated, NowKEV, Superseded int }

// stored is one finding as Apply reads it.
type stored struct {
	id, projectID, status string
	aliases               []string
	osvID                 string
	was                   scan.Enrichment
}

// Apply recomputes kev, kev_added, epss, epss_percentile and cvss_enriched
// of every finding not gone from the enrichment tables. When the KEV mark of
// a decided finding no longer matches the snapshot of its decision in force
// (seen_kev), the decision is superseded (kev_changed) and the finding moves
// to pending, as a re-scan would do. Everything happens in one transaction;
// the decision.superseded audit events are written after it commits.
func Apply(ctx context.Context, deps Deps) (ApplyResult, error) {
	var res ApplyResult
	now := deps.Now().UTC().Truncate(time.Second)
	tx, err := deps.Store.DB().BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("cannot apply the enrichment: %w", err)
	}
	defer tx.Rollback()

	var list []stored
	cves := []string{}
	seen := map[string]bool{}
	if err := each(ctx, tx, `SELECT id, project_id, status, osv_id, aliases, kev, kev_added, epss, epss_percentile, cvss_enriched
		FROM finding WHERE status <> ? ORDER BY id`, []any{scan.StatusGone}, func(r *sql.Rows) error {
		var s stored
		var aliases string
		var kev int
		if err := r.Scan(&s.id, &s.projectID, &s.status, &s.osvID, &aliases, &kev, &s.was.KEVAdded, &s.was.EPSS,
			&s.was.EPSSPercentile, &s.was.CVSS); err != nil {
			return err
		}
		s.was.KEV = kev != 0
		_ = json.Unmarshal([]byte(aliases), &s.aliases)
		for _, c := range scan.CVEsOf(scan.Finding{OSVID: s.osvID, Aliases: s.aliases}) {
			if !seen[c] {
				seen[c] = true
				cves = append(cves, c)
			}
		}
		list = append(list, s)
		return nil
	}); err != nil {
		return res, fmt.Errorf("cannot read the findings: %w", err)
	}
	l, err := loadLookup(ctx, tx, cves)
	if err != nil {
		return res, fmt.Errorf("cannot read the enrichment data: %w", err)
	}
	type inForce struct {
		action string
		kev    bool
	}
	current := map[string]inForce{}
	if err := each(ctx, tx, `SELECT finding_id, action, seen_kev FROM decision WHERE superseded_at = '' ORDER BY created_at, id`, nil,
		func(r *sql.Rows) error {
			var id string
			var d inForce
			var kev int
			if err := r.Scan(&id, &d.action, &kev); err != nil {
				return err
			}
			d.kev = kev != 0
			current[id] = d // the newest wins, should there be several
			return nil
		}); err != nil {
		return res, fmt.Errorf("cannot read the decisions: %w", err)
	}

	upd, err := tx.PrepareContext(ctx, `UPDATE finding SET kev = ?, kev_added = ?, epss = ?, epss_percentile = ?, cvss_enriched = ? WHERE id = ?`)
	if err != nil {
		return res, fmt.Errorf("cannot apply the enrichment: %w", err)
	}
	defer upd.Close()
	repo := decide.NewRepo(deps.Store)
	var superseded []decide.Decision
	for _, s := range list {
		ids := append([]string{s.osvID}, s.aliases...)
		var e scan.Enrichment
		e.KEV, e.KEVAdded, e.EPSS, e.EPSSPercentile, e.CVSS = l.Of(ids)
		if e != s.was {
			if _, err := upd.ExecContext(ctx, boolInt(e.KEV), e.KEVAdded, e.EPSS, e.EPSSPercentile, e.CVSS, s.id); err != nil {
				return res, fmt.Errorf("cannot apply the enrichment: %w", err)
			}
			res.Updated++
			if e.KEV && !s.was.KEV {
				res.NowKEV++
			}
		}
		d, ok := current[s.id]
		if !ok || s.status != scan.StatusDecided || d.kev == e.KEV {
			continue
		}
		if err := repo.Supersede(ctx, tx, s.id, decide.KEVChanged, now); err != nil {
			return res, err
		}
		superseded = append(superseded, decide.Decision{FindingID: s.id, ProjectID: s.projectID, Action: decide.Action(d.action)})
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("cannot apply the enrichment: %w", err)
	}
	res.Superseded = len(superseded)
	if deps.Audit == nil {
		return res, nil
	}
	for _, d := range superseded {
		if _, err := decide.RecordSuperseded(ctx, deps.Audit, "enrich", d, decide.KEVChanged); err != nil {
			return res, fmt.Errorf("the enrichment was applied but the audit log could not be written: %w", err)
		}
	}
	return res, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
