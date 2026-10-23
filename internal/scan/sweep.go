package scan

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"time"

	"github.com/kvarot/michel/internal/project"
)

// ScanInterrupted is the status of a scan whose process stopped before it
// finished (crash, kill, power loss), set by SweepStale.
const ScanInterrupted = "interrupted"

// StaleScanAfter is how long a scan may stay "running" before SweepStale
// treats it as interrupted. A real scan takes minutes; an hour leaves room
// for two processes scanning at the same time.
const StaleScanAfter = time.Hour

// interruptedError is the stored (English) error of an interrupted scan; the
// display translates it from the status.
const interruptedError = "Michel stopped before this scan finished"

// SweepStale marks every scan row left in status "running" for more than maxAge as interrupted and returns how many.
func SweepStale(ctx context.Context, db *sql.DB, now time.Time, maxAge time.Duration) (int, error) {
	cutoff := now.UTC().Add(-maxAge).Format(time.RFC3339)
	res, err := db.ExecContext(ctx, `UPDATE scan SET status = ?, finished_at = ?, error = ? WHERE status = 'running' AND started_at < ?`,
		ScanInterrupted, now.UTC().Format(time.RFC3339), interruptedError, cutoff)
	if err != nil {
		return 0, fmt.Errorf("cannot mark interrupted scans: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("cannot mark interrupted scans: %w", err)
	}
	return int(n), nil
}

// EffectiveExclude merges DefaultExclude with the project's own list (sorted, unique).
func EffectiveExclude(p project.Project) []string {
	out := append(append([]string{}, DefaultExclude...), p.Exclude...)
	slices.Sort(out)
	return slices.Compact(out)
}
