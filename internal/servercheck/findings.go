package servercheck

import (
	"context"
	"fmt"
	"time"

	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

// unknownPHPVersion is the id serverrules gives a PHP whose version could not
// be read.
const unknownPHPVersion = "PHP-VERSION-UNKNOWN"

// Alert kinds.
const (
	AlertNew            = "new"
	AlertRollbackFailed = "rollback_failed"
	AlertRolledBack     = "rolled_back"
	AlertAppliedAuto    = "applied_auto"
	// AlertUndoNow: a fix the user ran broke the site; the user must run
	// the undo script now (Michel never runs a script it was not allowed to).
	AlertUndoNow = "undo_now"
	// AlertRestoreSnapshot: a package upgrade failed or took the site
	// down; there is no script to undo it, the snapshot is the way back.
	AlertRestoreSnapshot = "restore_snapshot"
	// AlertUnknownState: a fix script ran past its bound or lost its
	// connection: Michel cannot tell what changed.
	AlertUnknownState = "unknown_state"
)

// AlertInput is what Alert is told: the server, the findings concerned and
// whether one of them is urgent (Urgent). Kind is one of the Alert* kinds.
// Backups lists, for a fix that could not be undone, the backup files on the
// server and the file each one restores ("backup -> file"): for the page
// only, never put in a message.
type AlertInput struct {
	Target  target.Target
	New     []scan.Finding
	Urgent  bool
	Kind    string
	Backups []string
}

// Urgent tells whether f on t must be fixed now: t is a production server
// and f is exploited in the wild (KEV) or critical. A distribution advisory
// with no fixed package yet is urgent only when exploited: there is nothing
// to install today. A PHP whose version could not be read is urgent: PHP2Shell
// cannot be ruled out.
func Urgent(t target.Target, f scan.Finding) bool {
	if t.Env != target.EnvProd {
		return false
	}
	if f.KEV || f.OSVID == unknownPHPVersion {
		return true
	}
	if f.Ecosystem == "os" && len(f.FixedVersions) == 0 {
		return false
	}
	label, _ := scan.EffectiveSeverity(f)
	return label == "critical"
}

// grave tells whether a new finding is worth an alert: urgent, exploited,
// or of high or critical severity.
func grave(t target.Target, f scan.Finding) bool {
	if Urgent(t, f) || f.KEV {
		return true
	}
	label, _ := scan.EffectiveSeverity(f)
	return label == "critical" || label == "high"
}

// storeFindings applies fs, judged from the inventory taken at invAt, to the
// stored findings of t in one transaction. It returns the findings that are
// new, or came back from gone without a decision still in force. stale is
// true, and nothing is stored, when a newer inventory of t exists (a check
// stored it while a rematch judged an older one).
func storeFindings(ctx context.Context, d CheckDeps, t target.Target, invAt time.Time, fs []scan.Finding, o scan.ServerApply, res *CheckResult) (fresh []scan.Finding, superseded []scan.Superseded, stale bool, err error) {
	tx, err := d.Store.DB().BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, false, fmt.Errorf("cannot store the findings: %w", err)
	}
	defer tx.Rollback()
	var latest string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(at), '') FROM target_inventory WHERE target_id = ?`, t.ID).Scan(&latest); err != nil {
		return nil, nil, false, fmt.Errorf("cannot read the inventories of the server: %w", err)
	}
	if latest > invAt.UTC().Truncate(time.Second).Format(time.RFC3339) {
		return nil, nil, true, nil
	}
	statuses := func() (map[string]string, error) {
		rows, err := tx.QueryContext(ctx, `SELECT id, status FROM finding WHERE project_id = ? AND source_key = ''`, t.ID)
		if err != nil {
			return nil, fmt.Errorf("cannot read the findings of the server: %w", err)
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var id, status string
			if err := rows.Scan(&id, &status); err != nil {
				return nil, err
			}
			out[id] = status
		}
		return out, rows.Err()
	}
	before, err := statuses()
	if err != nil {
		return nil, nil, false, err
	}
	newN, still, gone, superseded, err := scan.ApplyServerFindings(ctx, tx, t.ID, newRunID(), d.now(), fs, o)
	if err != nil {
		return nil, nil, false, err
	}
	after, err := statuses()
	if err != nil {
		return nil, nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, false, fmt.Errorf("cannot store the findings: %w", err)
	}
	res.New, res.Still, res.Gone = newN, still, gone
	for _, f := range fs {
		st, ok := before[f.ID]
		if ok && st != scan.StatusGone {
			continue
		}
		if now := after[f.ID]; now == scan.StatusNew || now == scan.StatusPending {
			fresh = append(fresh, f)
		}
	}
	return fresh, superseded, false, nil
}

// alertNew tells Alert about the grave findings among fresh, once.
func alertNew(ctx context.Context, d CheckDeps, t target.Target, fresh []scan.Finding) {
	if d.Alert == nil {
		return
	}
	in := AlertInput{Target: t, Kind: AlertNew}
	for _, f := range fresh {
		if !grave(t, f) {
			continue
		}
		in.New = append(in.New, f)
		in.Urgent = in.Urgent || Urgent(t, f)
	}
	if len(in.New) > 0 {
		d.Alert(ctx, in)
	}
}
