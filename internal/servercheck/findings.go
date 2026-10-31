package servercheck

import (
	"context"
	"fmt"

	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

// Alert kinds.
const (
	AlertNew            = "new"
	AlertRollbackFailed = "rollback_failed"
	AlertRolledBack     = "rolled_back"
	AlertAppliedAuto    = "applied_auto"
)

// AlertInput is what Alert is told: the server, the findings concerned and
// whether one of them is urgent (Urgent). Kind is one of the Alert* kinds.
type AlertInput struct {
	Target target.Target
	New    []scan.Finding
	Urgent bool
	Kind   string
}

// Urgent tells whether f on t must be fixed now: t is a production server
// and f is exploited in the wild (KEV) or critical. A distribution advisory
// with no fixed package yet is urgent only when exploited: there is nothing
// to install today.
func Urgent(t target.Target, f scan.Finding) bool {
	if t.Env != target.EnvProd {
		return false
	}
	if f.KEV {
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

// storeFindings applies fs to the stored findings of t in one transaction
// and returns the findings that are new or came back (they were gone).
func storeFindings(ctx context.Context, d CheckDeps, t target.Target, fs []scan.Finding, unread []string, enriched bool, res *CheckResult) ([]scan.Finding, []scan.Superseded, error) {
	tx, err := d.Store.DB().BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot store the findings: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id, status FROM finding WHERE project_id = ? AND source_key = ''`, t.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read the findings of the server: %w", err)
	}
	before := map[string]string{}
	for rows.Next() {
		var id, status string
		if err := rows.Scan(&id, &status); err != nil {
			rows.Close()
			return nil, nil, err
		}
		before[id] = status
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, err
	}
	rows.Close()
	newN, still, gone, superseded, err := scan.ApplyServerFindings(ctx, tx, t.ID, newRunID(), d.now(), fs,
		scan.ServerApply{Unread: unread, Enriched: enriched})
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("cannot store the findings: %w", err)
	}
	res.New, res.Still, res.Gone = newN, still, gone
	var fresh []scan.Finding
	for _, f := range fs {
		if st, ok := before[f.ID]; !ok || st == scan.StatusGone {
			fresh = append(fresh, f)
		}
	}
	return fresh, superseded, nil
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
