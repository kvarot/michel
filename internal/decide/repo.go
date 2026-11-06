package decide

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/history"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/store"
	"github.com/oklog/ulid/v2"
)

// Repo stores decisions. Every read is scoped to one finding or one project.
type Repo struct{ s *store.Store }

// NewRepo builds a Repo.
func NewRepo(s *store.Store) *Repo { return &Repo{s: s} }

const columns = `id, finding_id, project_id, action, justification, due_at, author, created_at,
	seen_severity, seen_fixed_versions, superseded_at, superseded_reason, seen_kev`

type scanner interface{ Scan(dest ...any) error }

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func scanDecision(row scanner) (Decision, error) {
	var d Decision
	var action, due, created, fixed, supAt, reason string
	var kev int
	if err := row.Scan(&d.ID, &d.FindingID, &d.ProjectID, &action, &d.Justification, &due, &d.Author, &created,
		&d.SeenSeverity, &fixed, &supAt, &reason, &kev); err != nil {
		return Decision{}, err
	}
	d.SeenKEV = kev != 0
	d.Action, d.SupersededReason = Action(action), Reason(reason)
	d.DueAt, d.CreatedAt, d.SupersededAt = parseTime(due), parseTime(created), parseTime(supAt)
	if err := json.Unmarshal([]byte(fixed), &d.SeenFixedVersions); err != nil {
		return Decision{}, fmt.Errorf("cannot read the fixed versions of decision %s: %w", d.ID, err)
	}
	if d.SeenFixedVersions == nil {
		d.SeenFixedVersions = []string{}
	}
	return d, nil
}

// querier is a *sql.DB or a *sql.Tx.
type querier interface {
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
}

func (r *Repo) query(ctx context.Context, q string, args ...any) ([]Decision, error) {
	return queryWith(ctx, r.s.DB(), q, args...)
}

func queryWith(ctx context.Context, db querier, q string, args ...any) ([]Decision, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("cannot read the decisions: %w", err)
	}
	defer rows.Close()
	out := []Decision{}
	for rows.Next() {
		d, err := scanDecision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Set stores d, supersedes the previous current decision (reason redecided) and moves the finding to "decided", in one transaction. It refuses a finding in status gone.
// d is validated first (Validate); its project and snapshot come from the
// finding. It returns the decision as stored.
func (r *Repo) Set(ctx context.Context, d Decision, now time.Time) (Decision, error) {
	if err := Validate(&d, now); err != nil {
		return Decision{}, err
	}
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return Decision{}, fmt.Errorf("cannot save the decision: %w", err)
	}
	defer tx.Rollback()
	var status, fixed string
	var kev int
	err = tx.QueryRowContext(ctx, `SELECT project_id, status, severity_label, fixed_versions, kev FROM finding WHERE id = ?`, d.FindingID).
		Scan(&d.ProjectID, &status, &d.SeenSeverity, &fixed, &kev)
	d.SeenKEV = kev != 0
	if errors.Is(err, sql.ErrNoRows) {
		return Decision{}, ErrFindingNotFound
	}
	if err != nil {
		return Decision{}, fmt.Errorf("cannot read the finding: %w", err)
	}
	if status == scan.StatusGone {
		return Decision{}, ErrFindingGone
	}
	d.SeenFixedVersions = []string{}
	if err := json.Unmarshal([]byte(fixed), &d.SeenFixedVersions); err != nil {
		return Decision{}, fmt.Errorf("cannot read the fixed versions of the finding: %w", err)
	}
	if d.SeenFixedVersions == nil {
		d.SeenFixedVersions = []string{}
	}
	d.CreatedAt = now.UTC().Truncate(time.Second)
	d.SupersededAt, d.SupersededReason = time.Time{}, ""
	ts := timeText(d.CreatedAt)
	if _, err := tx.ExecContext(ctx, `UPDATE decision SET superseded_at = ?, superseded_reason = ?
		WHERE finding_id = ? AND superseded_at = ''`, ts, string(Redecided), d.FindingID); err != nil {
		return Decision{}, fmt.Errorf("cannot replace the earlier decision: %w", err)
	}
	d.ID = ulid.Make().String()
	fx, _ := json.Marshal(d.SeenFixedVersions)
	seenKEV := 0
	if d.SeenKEV {
		seenKEV = 1
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO decision (`+columns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		d.ID, d.FindingID, d.ProjectID, string(d.Action), d.Justification, timeText(d.DueAt), d.Author, ts,
		d.SeenSeverity, string(fx), "", "", seenKEV); err != nil {
		return Decision{}, fmt.Errorf("cannot save the decision: %w", err)
	}
	if err := setStatus(ctx, tx, d.FindingID, scan.StatusDecided, ts, ""); err != nil {
		return Decision{}, err
	}
	if err := tx.Commit(); err != nil {
		return Decision{}, fmt.Errorf("cannot save the decision: %w", err)
	}
	return d, nil
}

// setStatus moves a finding to status; status_changed_at changes only when
// the status does. It writes the events of the change in the history, reason
// being the reason of the supersession the change carries ("" if none); the
// status before the change is read inside tx.
func setStatus(ctx context.Context, tx *sql.Tx, findingID, status, ts string, reason Reason) error {
	var from string
	err := tx.QueryRowContext(ctx, `SELECT status FROM finding WHERE id = ?`, findingID).Scan(&from)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // no such finding: nothing to move
	}
	if err != nil {
		return fmt.Errorf("cannot read the finding: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE finding SET status = ?,
		status_changed_at = CASE WHEN status <> ? THEN ? ELSE status_changed_at END WHERE id = ?`,
		status, status, ts, findingID); err != nil {
		return fmt.Errorf("cannot update the finding: %w", err)
	}
	return history.AddStatusEvents(ctx, tx, findingID, from, status, string(reason), parseTime(ts))
}

// Current returns the decision in force for a finding (ok=false if none).
func (r *Repo) Current(ctx context.Context, findingID string) (Decision, bool, error) {
	list, err := r.query(ctx, `SELECT `+columns+` FROM decision WHERE finding_id = ? AND superseded_at = ''
		ORDER BY created_at DESC, id DESC LIMIT 1`, findingID)
	if err != nil || len(list) == 0 {
		return Decision{}, false, err
	}
	return list[0], true, nil
}

// CurrentByProject maps finding id -> decision in force for every finding of the project.
func (r *Repo) CurrentByProject(ctx context.Context, projectID string) (map[string]Decision, error) {
	list, err := r.query(ctx, `SELECT `+columns+` FROM decision WHERE project_id = ? AND superseded_at = ''
		ORDER BY created_at, id`, projectID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]Decision, len(list))
	for _, d := range list {
		out[d.FindingID] = d // the newest wins, should there be several
	}
	return out, nil
}

// Supersede marks the current decision of a finding as superseded with reason and moves the finding to "pending".
// A nil tx runs it in a transaction of its own.
func (r *Repo) Supersede(ctx context.Context, tx *sql.Tx, findingID string, reason Reason, now time.Time) error {
	if tx == nil {
		own, err := r.s.DB().BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("cannot supersede the decision: %w", err)
		}
		defer own.Rollback()
		if err := r.Supersede(ctx, own, findingID, reason, now); err != nil {
			return err
		}
		return own.Commit()
	}
	ts := timeText(now.UTC().Truncate(time.Second))
	if _, err := tx.ExecContext(ctx, `UPDATE decision SET superseded_at = ?, superseded_reason = ?
		WHERE finding_id = ? AND superseded_at = ''`, ts, string(reason), findingID); err != nil {
		return fmt.Errorf("cannot supersede the decision: %w", err)
	}
	return setStatus(ctx, tx, findingID, scan.StatusPending, ts, reason)
}

// List returns the decisions of a project, newest first; filter: "" (current only), "fix"|"defer"|"ignore" (current with that action), "superseded", "all".
func (r *Repo) List(ctx context.Context, projectID, filter string) ([]Decision, error) {
	q := `SELECT ` + columns + ` FROM decision WHERE project_id = ?`
	args := []any{projectID}
	switch filter {
	case "":
		q += ` AND superseded_at = ''`
	case string(Fix), string(Defer), string(Ignore):
		q += ` AND superseded_at = '' AND action = ?`
		args = append(args, filter)
	case "superseded":
		q += ` AND superseded_at <> ''`
	case "all":
	default:
		return nil, ErrInvalidFilter
	}
	return r.query(ctx, q+` ORDER BY created_at DESC, id DESC`, args...)
}

// ExpireDue supersedes (due_reached) every current defer whose due_at <= now, in all projects, moves those findings to pending, writes one decision.superseded audit event each, and returns the finding ids. Called by digest --send only (scan does the same inside applyScan).
// Only findings still decided are touched: a gone finding keeps its
// decision, and the scan checks the date if it comes back. The read and the
// updates share one transaction, and each update is guarded, so a decision
// re-taken meanwhile stays in force.
func (r *Repo) ExpireDue(ctx context.Context, now time.Time, log *audit.Logger) ([]string, error) {
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot supersede the decisions: %w", err)
	}
	defer tx.Rollback()
	list, err := queryWith(ctx, tx, `SELECT `+columns+` FROM decision WHERE action = ? AND superseded_at = ''
		AND finding_id IN (SELECT id FROM finding WHERE status = ?) ORDER BY finding_id`, string(Defer), scan.StatusDecided)
	if err != nil {
		return nil, err
	}
	var due []Decision
	for _, d := range list {
		if !d.DueAt.After(now) {
			due = append(due, d)
		}
	}
	if len(due) == 0 {
		return []string{}, nil
	}
	due, err = r.expire(ctx, tx, due, now)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("cannot supersede the decisions: %w", err)
	}
	ids := make([]string, 0, len(due))
	for _, d := range due {
		ids = append(ids, d.FindingID)
	}
	sort.Strings(ids)
	if log == nil {
		return ids, nil
	}
	for _, d := range due {
		if _, err := RecordSuperseded(ctx, log, "decide", d, DueReached); err != nil {
			return ids, err
		}
	}
	return ids, nil
}

// expire takes each decision of due out of force (due_reached) inside tx, but
// only while it is still in force, still a deferral and still due at now, and
// moves its finding to pending. It returns the decisions it took out of force.
func (r *Repo) expire(ctx context.Context, tx *sql.Tx, due []Decision, now time.Time) ([]Decision, error) {
	ts := timeText(now.UTC().Truncate(time.Second))
	done := make([]Decision, 0, len(due))
	for _, d := range due {
		res, err := tx.ExecContext(ctx, `UPDATE decision SET superseded_at = ?, superseded_reason = ?
			WHERE id = ? AND superseded_at = '' AND action = ? AND due_at <> '' AND due_at <= ?`,
			ts, string(DueReached), d.ID, string(Defer), timeText(now))
		if err != nil {
			return nil, fmt.Errorf("cannot supersede the decision: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return nil, fmt.Errorf("cannot supersede the decision: %w", err)
		} else if n == 0 {
			continue
		}
		if err := setStatus(ctx, tx, d.FindingID, scan.StatusPending, ts, DueReached); err != nil {
			return nil, err
		}
		done = append(done, d)
	}
	return done, nil
}

// RecordSuperseded writes the decision.superseded audit event of d, taken
// out of force for reason.
func RecordSuperseded(ctx context.Context, log *audit.Logger, actor string, d Decision, reason Reason) (audit.Event, error) {
	return log.Record(ctx, audit.Event{Actor: actor, Action: "decision.superseded", Target: d.FindingID, Result: "ok",
		Evidence: map[string]any{
			"finding_id": d.FindingID, "project_id": d.ProjectID, "reason": string(reason), "previous_action": string(d.Action),
		}})
}

// RecordSet writes the decision.set audit event of d, just stored by Set,
// for the finding of that package and advisory. The evidence holds no code,
// path or command: the ids, the action, its date, the author and the
// sanitized justification.
func RecordSet(ctx context.Context, log *audit.Logger, actor string, d Decision, pkg, osvID string) (audit.Event, error) {
	return log.Record(ctx, audit.Event{Actor: actor, Action: "decision.set", Target: d.FindingID, Result: "ok",
		Evidence: map[string]any{
			"finding_id": d.FindingID, "project_id": d.ProjectID, "action": string(d.Action), "due_at": timeText(d.DueAt),
			"author": d.Author, "justification": d.Justification, "package": scan.SanitizeText(pkg), "osv_id": scan.SanitizeText(osvID),
		}})
}
