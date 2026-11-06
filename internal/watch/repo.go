package watch

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/kvarot/michel/internal/store"
)

// keepDays is how long the record of a day's source read is kept.
const keepDays = 30

// Repo reads what the watch needs from the database.
type Repo struct{ s *store.Store }

// NewRepo returns the watch's view of s.
func NewRepo(s *store.Store) *Repo { return &Repo{s: s} }

// countedStatuses is the SQL filter of the scans that count as a check of
// the day: a failed check does, an interrupted one (serve stopped during it)
// or one still running (in progress elsewhere, or left by a crash) does not.
const countedStatuses = `status NOT IN ('interrupted', 'running')`

// LastStarts maps each project id to the start of its newest scan that
// counts as a check (see countedStatuses): a failed check is a check of the
// day too.
func (r *Repo) LastStarts(ctx context.Context) (map[string]time.Time, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT project_id, MAX(started_at) FROM scan WHERE `+countedStatuses+` GROUP BY project_id`)
	if err != nil {
		return nil, fmt.Errorf("cannot read the last checks: %w", err)
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id, at string
		if err := rows.Scan(&id, &at); err != nil {
			return nil, fmt.Errorf("cannot read the last checks: %w", err)
		}
		t, err := time.Parse(time.RFC3339, at)
		if err != nil {
			return nil, fmt.Errorf("a check of project %s has an unreadable start %q: %w", id, at, err)
		}
		out[id] = t
	}
	return out, rows.Err()
}

// LastScan is the newest scan of the project: its start and status, has
// false when it was never scanned.
func (r *Repo) LastScan(ctx context.Context, projectID string) (at time.Time, status string, has bool, err error) {
	var started string
	err = r.s.DB().QueryRowContext(ctx, `SELECT started_at, status FROM scan WHERE project_id = ?
		ORDER BY started_at DESC, id DESC LIMIT 1`, projectID).Scan(&started, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, "", false, nil
	}
	if err != nil {
		return time.Time{}, "", false, fmt.Errorf("cannot read the last check: %w", err)
	}
	at, err = time.Parse(time.RFC3339, started)
	if err != nil {
		return time.Time{}, "", false, fmt.Errorf("a check has an unreadable start %q: %w", started, err)
	}
	return at, status, true, nil
}

// ClaimSources records that the watch of the local day (YYYY-MM-DD) reads
// the sources, and reports whether this call did: once a day, whichever serve
// asks first, and not again after a restart. Records older than keepDays go.
func (r *Repo) ClaimSources(ctx context.Context, day string, at time.Time) (bool, error) {
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("cannot record the source read of the day: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO watch_day (day, sources_at) VALUES (?, ?) ON CONFLICT (day) DO NOTHING`,
		day, at.UTC().Format(time.RFC3339))
	if err != nil {
		return false, fmt.Errorf("cannot record the source read of the day: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("cannot record the source read of the day: %w", err)
	}
	if d, perr := time.Parse("2006-01-02", day); perr == nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM watch_day WHERE day < ?`, d.AddDate(0, 0, -keepDays).Format("2006-01-02")); err != nil {
			return false, fmt.Errorf("cannot record the source read of the day: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("cannot record the source read of the day: %w", err)
	}
	return n == 1, nil
}

// ReleaseSources forgets the source read of the local day (YYYY-MM-DD), so
// the next claim of that day succeeds: the read was stopped or failed.
func (r *Repo) ReleaseSources(ctx context.Context, day string) error {
	if _, err := r.s.DB().ExecContext(ctx, `DELETE FROM watch_day WHERE day = ?`, day); err != nil {
		return fmt.Errorf("cannot let go of the source read of the day: %w", err)
	}
	return nil
}
