package fix

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/store"
	"github.com/oklog/ulid/v2"
)

// Repo reads and writes the fix tables.
type Repo struct {
	s *store.Store
	// Now gives the current time; tests replace it.
	Now func() time.Time

	mu      sync.Mutex
	entropy *ulid.MonotonicEntropy
}

// NewRepo returns a Repo on s.
func NewRepo(s *store.Store) *Repo {
	return &Repo{s: s, Now: time.Now, entropy: ulid.Monotonic(rand.Reader, 0)}
}

func (r *Repo) now() time.Time { return r.Now().UTC().Truncate(time.Second) }

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func (r *Repo) newID(now time.Time) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, err := ulid.New(ulid.Timestamp(now), r.entropy)
	if err != nil {
		return "", fmt.Errorf("cannot create a fix id: %w", err)
	}
	return id.String(), nil
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("unreadable date %q in the fix tables: %w", s, err)
	}
	return t, nil
}

// busyStates are the states of an attempt that is still being worked on or
// waits for the user: the project has no other attempt meanwhile.
const busyStates = `('preparing','proposed','approved')`

const attemptCols = `id, finding_id, project_id, origin, state, clone_dir, session_id, cause, created_at, updated_at`

// CreateAttempt stores a new attempt in state preparing; ID, State and the
// dates are set here.
func (r *Repo) CreateAttempt(ctx context.Context, a Attempt) (Attempt, error) {
	now := r.now()
	id, err := r.newID(now)
	if err != nil {
		return Attempt{}, err
	}
	a.ID, a.State, a.CreatedAt, a.UpdatedAt = id, StatePreparing, now, now
	_, err = r.s.DB().ExecContext(ctx, `INSERT INTO fix_attempt (`+attemptCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.FindingID, a.ProjectID, a.Origin, string(a.State), a.CloneDir, a.SessionID, a.Cause, ts(now), ts(now))
	if err != nil {
		return Attempt{}, fmt.Errorf("cannot save the fix attempt: %w", err)
	}
	return a, nil
}

type scanner interface{ Scan(...any) error }

func scanAttempt(s scanner) (Attempt, error) {
	var a Attempt
	var state, created, updated string
	if err := s.Scan(&a.ID, &a.FindingID, &a.ProjectID, &a.Origin, &state, &a.CloneDir, &a.SessionID, &a.Cause, &created, &updated); err != nil {
		return Attempt{}, err
	}
	a.State = State(state)
	var err error
	if a.CreatedAt, err = parseTime(created); err != nil {
		return Attempt{}, err
	}
	if a.UpdatedAt, err = parseTime(updated); err != nil {
		return Attempt{}, err
	}
	return a, nil
}

// GetAttempt returns the attempt with this id, or ErrNotFound.
func (r *Repo) GetAttempt(ctx context.Context, id string) (Attempt, error) {
	a, err := scanAttempt(r.s.DB().QueryRowContext(ctx, `SELECT `+attemptCols+` FROM fix_attempt WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Attempt{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return a, err
}

// ListAttempts returns the attempts, newest first, of one project ("" for
// all) in one state ("" for any).
func (r *Repo) ListAttempts(ctx context.Context, projectID, state string) ([]Attempt, error) {
	q, args := `SELECT `+attemptCols+` FROM fix_attempt WHERE 1 = 1`, []any{}
	if projectID != "" {
		q += ` AND project_id = ?`
		args = append(args, projectID)
	}
	if state != "" {
		q += ` AND state = ?`
		args = append(args, state)
	}
	rows, err := r.s.DB().QueryContext(ctx, q+` ORDER BY created_at DESC, id DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("cannot read the fix attempts: %w", err)
	}
	defer rows.Close()
	out := []Attempt{}
	for rows.Next() {
		a, err := scanAttempt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetState moves the attempt from one of the states in from to the state to,
// and records cause (kept as it is when empty). An attempt in any other
// state gives ErrBadTransition; an unknown id gives ErrNotFound.
func (r *Repo) SetState(ctx context.Context, id string, from []State, to State, cause string) error {
	if len(from) == 0 {
		return ErrBadTransition
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(from)), ",")
	args := []any{string(to), cause, cause, ts(r.now()), id}
	for _, f := range from {
		args = append(args, string(f))
	}
	res, err := r.s.DB().ExecContext(ctx, `UPDATE fix_attempt SET state = ?, cause = CASE WHEN ? = '' THEN cause ELSE ? END, updated_at = ?
		WHERE id = ? AND state IN (`+marks+`)`, args...)
	if err != nil {
		return fmt.Errorf("cannot change the fix attempt: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	if _, err := r.GetAttempt(ctx, id); err != nil {
		return err
	}
	return fmt.Errorf("%w (moving to %s)", ErrBadTransition, to)
}

// SetRun records the work copy and the agent session of an attempt.
func (r *Repo) SetRun(ctx context.Context, id, cloneDir, sessionID string) error {
	res, err := r.s.DB().ExecContext(ctx, `UPDATE fix_attempt SET clone_dir = ?, session_id = ?, updated_at = ? WHERE id = ?`,
		cloneDir, sessionID, ts(r.now()), id)
	if err != nil {
		return fmt.Errorf("cannot change the fix attempt: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return nil
}

const proposalCols = `id, attempt_id, summary, diff, files, tests_status, tests_output, rescan_clean, risk, hash, steps_server, created_at, superseded`

// AddProposal stores p for its attempt and marks the attempt's previous
// proposals Superseded, in one transaction. ID and CreatedAt are set here.
func (r *Repo) AddProposal(ctx context.Context, p Proposal) (Proposal, error) {
	now := r.now()
	id, err := r.newID(now)
	if err != nil {
		return Proposal{}, err
	}
	p.ID, p.CreatedAt, p.Superseded = id, now, false
	p.Files, p.StepsServer = nonNil(p.Files), nonNil(p.StepsServer)
	files, err := json.Marshal(p.Files)
	if err != nil {
		return Proposal{}, fmt.Errorf("cannot save the proposal: %w", err)
	}
	steps, err := json.Marshal(p.StepsServer)
	if err != nil {
		return Proposal{}, fmt.Errorf("cannot save the proposal: %w", err)
	}
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return Proposal{}, fmt.Errorf("cannot save the proposal: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE fix_proposal SET superseded = 1 WHERE attempt_id = ?`, p.AttemptID); err != nil {
		return Proposal{}, fmt.Errorf("cannot save the proposal: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO fix_proposal (`+proposalCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0)`,
		p.ID, p.AttemptID, p.Summary, p.Diff, string(files), p.TestsStatus, p.TestsOutput, b2i(p.RescanClean), p.Risk, p.Hash, string(steps), ts(now)); err != nil {
		return Proposal{}, fmt.Errorf("cannot save the proposal: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Proposal{}, fmt.Errorf("cannot save the proposal: %w", err)
	}
	return p, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func scanProposal(s scanner) (Proposal, error) {
	var p Proposal
	var files, steps, created string
	var rescan, superseded int
	if err := s.Scan(&p.ID, &p.AttemptID, &p.Summary, &p.Diff, &files, &p.TestsStatus, &p.TestsOutput, &rescan, &p.Risk, &p.Hash, &steps, &created, &superseded); err != nil {
		return Proposal{}, err
	}
	if err := json.Unmarshal([]byte(files), &p.Files); err != nil {
		return Proposal{}, fmt.Errorf("proposal %s has an unreadable file list: %w", p.ID, err)
	}
	if err := json.Unmarshal([]byte(steps), &p.StepsServer); err != nil {
		return Proposal{}, fmt.Errorf("proposal %s has an unreadable list of server steps: %w", p.ID, err)
	}
	p.Files, p.StepsServer = nonNil(p.Files), nonNil(p.StepsServer)
	p.RescanClean, p.Superseded = rescan != 0, superseded != 0
	var err error
	if p.CreatedAt, err = parseTime(created); err != nil {
		return Proposal{}, err
	}
	return p, nil
}

// CurrentProposal returns the newest proposal of the attempt; ok is false
// when it has none.
func (r *Repo) CurrentProposal(ctx context.Context, attemptID string) (Proposal, bool, error) {
	p, err := scanProposal(r.s.DB().QueryRowContext(ctx, `SELECT `+proposalCols+` FROM fix_proposal
		WHERE attempt_id = ? AND superseded = 0 ORDER BY created_at DESC, id DESC LIMIT 1`, attemptID))
	if errors.Is(err, sql.ErrNoRows) {
		return Proposal{}, false, nil
	}
	if err != nil {
		return Proposal{}, false, err
	}
	return p, true, nil
}

// Proposals returns every proposal of the attempt, oldest first.
func (r *Repo) Proposals(ctx context.Context, attemptID string) ([]Proposal, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT `+proposalCols+` FROM fix_proposal WHERE attempt_id = ? ORDER BY created_at, id`, attemptID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the proposals: %w", err)
	}
	defer rows.Close()
	out := []Proposal{}
	for rows.Next() {
		p, err := scanProposal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// AddMessage stores a message of the conversation; ID is set here, and At
// when it is zero.
func (r *Repo) AddMessage(ctx context.Context, m Message) (Message, error) {
	now := r.now()
	id, err := r.newID(now)
	if err != nil {
		return Message{}, err
	}
	m.ID = id
	if m.At.IsZero() {
		m.At = now
	}
	m.At = m.At.UTC().Truncate(time.Second)
	if _, err := r.s.DB().ExecContext(ctx, `INSERT INTO fix_message (id, attempt_id, role, text, at) VALUES (?,?,?,?,?)`,
		m.ID, m.AttemptID, m.Role, m.Text, ts(m.At)); err != nil {
		return Message{}, fmt.Errorf("cannot save the message: %w", err)
	}
	return m, nil
}

// ListMessages returns the conversation of the attempt, oldest first.
func (r *Repo) ListMessages(ctx context.Context, attemptID string) ([]Message, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT id, attempt_id, role, text, at FROM fix_message WHERE attempt_id = ? ORDER BY at, id`, attemptID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the messages: %w", err)
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		var m Message
		var at string
		if err := rows.Scan(&m.ID, &m.AttemptID, &m.Role, &m.Text, &at); err != nil {
			return nil, err
		}
		if m.At, err = parseTime(at); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// PurgeMessages deletes the messages older than before and returns how many.
func (r *Repo) PurgeMessages(ctx context.Context, before time.Time) (int, error) {
	res, err := r.s.DB().ExecContext(ctx, `DELETE FROM fix_message WHERE at < ?`, ts(before))
	if err != nil {
		return 0, fmt.Errorf("cannot purge the old messages: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// Enqueue puts a finding in the queue of automatic attempts; a finding
// already queued stays where it is.
func (r *Repo) Enqueue(ctx context.Context, findingID, projectID string) error {
	_, err := r.s.DB().ExecContext(ctx, `INSERT INTO fix_queue (finding_id, project_id, queued_at) VALUES (?,?,?)
		ON CONFLICT (finding_id) DO NOTHING`, findingID, projectID, ts(r.now()))
	if err != nil {
		return fmt.Errorf("cannot queue the fix: %w", err)
	}
	return nil
}

// NextQueued takes the oldest queued finding whose project has no attempt
// being worked on or waiting for the user, removes it from the queue and
// returns it; ok is false when there is none.
func (r *Repo) NextQueued(ctx context.Context) (findingID, projectID string, ok bool, err error) {
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return "", "", false, fmt.Errorf("cannot read the fix queue: %w", err)
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `SELECT finding_id, project_id FROM fix_queue
		WHERE project_id NOT IN (SELECT project_id FROM fix_attempt WHERE state IN `+busyStates+`)
		ORDER BY queued_at, finding_id LIMIT 1`).Scan(&findingID, &projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("cannot read the fix queue: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM fix_queue WHERE finding_id = ?`, findingID); err != nil {
		return "", "", false, fmt.Errorf("cannot read the fix queue: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", "", false, fmt.Errorf("cannot read the fix queue: %w", err)
	}
	return findingID, projectID, true, nil
}

// StartedToday counts the attempts Michel started alone (origin
// agent.claude.auto) for the project on the UTC day of now.
func (r *Repo) StartedToday(ctx context.Context, projectID string, now time.Time) (int, error) {
	day := now.UTC().Truncate(24 * time.Hour)
	var n int
	err := r.s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM fix_attempt WHERE project_id = ? AND origin = ? AND created_at >= ? AND created_at < ?`,
		projectID, OriginAgentAuto, ts(day), ts(day.Add(24*time.Hour))).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("cannot count today's fix attempts: %w", err)
	}
	return n, nil
}
