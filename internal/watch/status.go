package watch

import (
	"context"
	"time"

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
)

// Status is what the CLI and the page both say of a project's checks.
type Status struct {
	// HasScan is false when the project was never scanned; LastScanAt (RFC 3339
	// UTC) and LastScanStatus are then empty.
	HasScan        bool
	LastScanAt     string
	LastScanStatus string
	// NextCheck is the next automatic check, RFC 3339 UTC, "" when the watch
	// is off or the project is not watched.
	NextCheck string
}

// ProjectStatus reads the newest scan of p (of any status) and computes the
// next check from the last one that counts (an interrupted or running scan
// is checked again), as the watch itself does.
func ProjectStatus(ctx context.Context, repo *Repo, p project.Project, pol policy.Policy, now time.Time) (Status, error) {
	var st Status
	at, status, has, err := repo.LastScan(ctx, p.ID)
	if err != nil {
		return Status{}, err
	}
	if has {
		st.HasScan, st.LastScanAt, st.LastScanStatus = true, at.UTC().Format(time.RFC3339), status
	}
	if h, m, on := pol.WatchHour(); on && p.AutoScan {
		last, counted, err := repo.LastStart(ctx, p.ID)
		if err != nil {
			return Status{}, err
		}
		st.NextCheck = Next(last, counted, now, h, m).UTC().Format(time.RFC3339)
	}
	return st, nil
}
