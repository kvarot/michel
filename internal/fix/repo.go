package fix

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
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
const busyStates = `('preparing','held','proposed','approved','running')`

// serverBusyStates are busyStates for a server, plus applied (the steps
// after the script: site check, undo, recollection) and unknown (what the
// script changed is not known): one server fix at a time on a server.
const serverBusyStates = `('preparing','proposed','approved','running','applied','unknown')`

// serverRunStates are the states of a server attempt whose script may be
// touching the server, or whose outcome is not known: no other fix of the
// same server is claimed meanwhile.
const serverRunStates = `('running','applied','unknown')`

const attemptCols = `id, finding_id, project_id, origin, state, clone_dir, session_id, cause, created_at, updated_at, work_json, approved_by, approved_proposal, approved_hash, cause_detail`

func workJSON(w Work) (string, error) {
	w.Mirror = w.Copy.Mirror
	b, err := json.Marshal(w)
	if err != nil {
		return "", fmt.Errorf("cannot save the fix attempt: %w", err)
	}
	return string(b), nil
}

// CreateAttempt stores a new attempt in state preparing; ID, State and the
// dates are set here. The insert is conditional on the project having no
// attempt being worked on or waiting for the user (one statement, so two
// callers cannot both succeed): ErrBusy otherwise. For a server fix
// (Work.Server set), an applied or unknown attempt of the server counts
// too (serverBusyStates).
func (r *Repo) CreateAttempt(ctx context.Context, a Attempt) (Attempt, error) {
	now := r.now()
	id, err := r.newID(now)
	if err != nil {
		return Attempt{}, err
	}
	a.ID, a.State, a.CreatedAt, a.UpdatedAt, a.ApprovedBy = id, StatePreparing, now, now, ""
	work, err := workJSON(a.Work)
	if err != nil {
		return Attempt{}, err
	}
	busy := busyStates
	if a.Work.Server != nil {
		busy = serverBusyStates
	}
	res, err := r.s.DB().ExecContext(ctx, `INSERT INTO fix_attempt (`+attemptCols+`)
		SELECT ?,?,?,?,?,?,?,?,?,?,?,'','','',''
		WHERE NOT EXISTS (SELECT 1 FROM fix_attempt WHERE project_id = ? AND state IN `+busy+`)`,
		a.ID, a.FindingID, a.ProjectID, a.Origin, string(a.State), a.CloneDir, a.SessionID, a.Cause, ts(now), ts(now), work, a.ProjectID)
	if err != nil {
		return Attempt{}, fmt.Errorf("cannot save the fix attempt: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Attempt{}, ErrBusy
	}
	return a, nil
}

// SetWork records the work copy and the update plan of an attempt (and
// CloneDir, the copy's folder).
func (r *Repo) SetWork(ctx context.Context, id string, w Work) error {
	work, err := workJSON(w)
	if err != nil {
		return err
	}
	res, err := r.s.DB().ExecContext(ctx, `UPDATE fix_attempt SET work_json = ?, clone_dir = ?, updated_at = ? WHERE id = ?`,
		work, w.Copy.Dir, ts(r.now()), id)
	if err != nil {
		return fmt.Errorf("cannot change the fix attempt: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return nil
}

// Approve moves the attempt from proposed to approved and records who did
// it and for which proposal (id and hash), in one transaction that also
// checks that proposal is still the current one with that hash:
// ErrStaleProposal when it is not (the attempt stays proposed),
// ErrBadTransition in any other state.
func (r *Repo) Approve(ctx context.Context, id, by, proposalID, hash string) error {
	now := r.now()
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot change the fix attempt: %w", err)
	}
	defer tx.Rollback()
	if err := lockProposed(ctx, tx, id, now, StateApproved); err != nil {
		return err
	}
	if err := checkCurrent(ctx, tx, id, proposalID, hash); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE fix_attempt SET state = ?, approved_by = ?, approved_proposal = ?, approved_hash = ?, updated_at = ? WHERE id = ?`,
		string(StateApproved), by, proposalID, hash, ts(now), id); err != nil {
		return fmt.Errorf("cannot change the fix attempt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cannot change the fix attempt: %w", err)
	}
	return nil
}

// lockProposed takes the row of the attempt in tx (an update, which every
// database serializes, PostgreSQL in READ COMMITTED included) when it is
// proposed. ErrNotFound for an unknown attempt, ErrBadTransition (moving to
// to) in any other state.
func lockProposed(ctx context.Context, tx *sql.Tx, id string, now time.Time, to State) error {
	res, err := tx.ExecContext(ctx, `UPDATE fix_attempt SET updated_at = ? WHERE id = ? AND state = ?`, ts(now), id, string(StateProposed))
	if err != nil {
		return fmt.Errorf("cannot change the fix attempt: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM fix_attempt WHERE id = ?`, id).Scan(&state); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	} else if err != nil {
		return fmt.Errorf("cannot read the fix attempt: %w", err)
	}
	return fmt.Errorf("%w (the attempt is %s, moving to %s)", ErrBadTransition, state, to)
}

// checkCurrent reads, after lockProposed, the current proposal of the
// attempt and compares it in Go: ErrStaleProposal unless its hash is hash
// (and its id proposalID, when given).
func checkCurrent(ctx context.Context, tx *sql.Tx, id, proposalID, hash string) error {
	var curID, curHash string
	err := tx.QueryRowContext(ctx, `SELECT id, hash FROM fix_proposal WHERE attempt_id = ? AND superseded = 0
		ORDER BY created_at DESC, id DESC LIMIT 1`, id).Scan(&curID, &curHash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStaleProposal
	}
	if err != nil {
		return fmt.Errorf("cannot read the proposal: %w", err)
	}
	if hash == "" || curHash != hash || (proposalID != "" && curID != proposalID) {
		return ErrStaleProposal
	}
	return nil
}

type scanner interface{ Scan(...any) error }

func scanAttempt(s scanner) (Attempt, error) {
	var a Attempt
	var state, created, updated, work string
	if err := s.Scan(&a.ID, &a.FindingID, &a.ProjectID, &a.Origin, &state, &a.CloneDir, &a.SessionID, &a.Cause, &created, &updated, &work, &a.ApprovedBy, &a.ApprovedProposal, &a.ApprovedHash, &a.CauseDetail); err != nil {
		return Attempt{}, err
	}
	a.State = State(state)
	// An unreadable record never hides the attempt from a listing: it is
	// returned without a copy, WorkError set.
	if err := json.Unmarshal([]byte(work), &a.Work); err != nil {
		a.Work, a.WorkError = Work{}, fmt.Sprintf("unreadable work copy record: %v", err)
	}
	a.Work.Copy.Mirror = a.Work.Mirror
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

// SetCauseDetail records the technical detail behind the attempt's cause.
func (r *Repo) SetCauseDetail(ctx context.Context, id, detail string) error {
	if _, err := r.s.DB().ExecContext(ctx, `UPDATE fix_attempt SET cause_detail = ? WHERE id = ?`, detail, id); err != nil {
		return fmt.Errorf("cannot change the fix attempt: %w", err)
	}
	return nil
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

const proposalCols = `id, attempt_id, summary, diff, files, tests_status, tests_output, rescan_clean, risk, hash, steps_server, created_at, superseded, commit_sha, diff_raw, from_version, to_version, commands, scripts, steps, tree`

// serverRecord is what the scripts column holds for a server fix.
type serverRecord struct {
	Bundle serverfix.Bundle `json:"bundle"`
	Server ServerFix        `json:"server"`
}

func scriptsJSON(p Proposal) (string, error) {
	if p.Scripts == nil && p.Server == nil {
		return "", nil
	}
	if p.Scripts == nil || p.Server == nil {
		return "", errors.New("cannot save the proposal: a server fix needs both its scripts and its server record")
	}
	b, err := json.Marshal(serverRecord{Bundle: *p.Scripts, Server: *p.Server})
	if err != nil {
		return "", fmt.Errorf("cannot save the proposal: %w", err)
	}
	return string(b), nil
}

func stepsJSON(steps []StepResult) (string, error) {
	if steps == nil {
		steps = []StepResult{}
	}
	b, err := json.Marshal(steps)
	if err != nil {
		return "", fmt.Errorf("cannot save the steps: %w", err)
	}
	return string(b), nil
}

// AddProposal stores p for its attempt and marks the attempt's previous
// proposals Superseded, in one transaction that also checks the attempt is
// preparing or proposed (ErrBadTransition otherwise: no proposal ever lands
// on an approved or applied attempt). ID and CreatedAt are set here.
func (r *Repo) AddProposal(ctx context.Context, p Proposal) (Proposal, error) {
	now := r.now()
	p, insert, err := r.proposalInsert(p, now)
	if err != nil {
		return Proposal{}, err
	}
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return Proposal{}, fmt.Errorf("cannot save the proposal: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE fix_attempt SET updated_at = ? WHERE id = ? AND state IN (?, ?)`,
		ts(now), p.AttemptID, string(StatePreparing), string(StateProposed))
	if err != nil {
		return Proposal{}, fmt.Errorf("cannot save the proposal: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Checked inside the transaction: the store has one connection.
		var state string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM fix_attempt WHERE id = ?`, p.AttemptID).Scan(&state); errors.Is(err, sql.ErrNoRows) {
			return Proposal{}, fmt.Errorf("%w: %s", ErrNotFound, p.AttemptID)
		} else if err != nil {
			return Proposal{}, fmt.Errorf("cannot save the proposal: %w", err)
		}
		return Proposal{}, fmt.Errorf("%w (a proposal needs an attempt that is preparing or proposed, not %s)", ErrBadTransition, state)
	}
	if err := insert(ctx, tx); err != nil {
		return Proposal{}, fmt.Errorf("cannot save the proposal: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Proposal{}, fmt.Errorf("cannot save the proposal: %w", err)
	}
	return p, nil
}

// AddProposalIfCurrent stores p for its attempt, superseding the current
// proposal, only when the attempt is proposed and its current proposal still
// has the hash hash: the check and the insert run in one transaction (same
// form as Approve). ErrStaleProposal when the current proposal is another
// one (nothing stored), ErrBadTransition when the attempt is not proposed.
func (r *Repo) AddProposalIfCurrent(ctx context.Context, p Proposal, hash string) (Proposal, error) {
	if hash == "" {
		return Proposal{}, ErrStaleProposal
	}
	now := r.now()
	p, insert, err := r.proposalInsert(p, now)
	if err != nil {
		return Proposal{}, err
	}
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return Proposal{}, fmt.Errorf("cannot save the proposal: %w", err)
	}
	defer tx.Rollback()
	if err := lockProposed(ctx, tx, p.AttemptID, now, StateProposed); err != nil {
		return Proposal{}, err
	}
	if err := checkCurrent(ctx, tx, p.AttemptID, "", hash); err != nil {
		return Proposal{}, err
	}
	if err := insert(ctx, tx); err != nil {
		return Proposal{}, fmt.Errorf("cannot save the proposal: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Proposal{}, fmt.Errorf("cannot save the proposal: %w", err)
	}
	return p, nil
}

// proposalInsert prepares p for storing: its id and date, and the function
// that, inside a transaction, supersedes the attempt's proposals and inserts it.
func (r *Repo) proposalInsert(p Proposal, now time.Time) (Proposal, func(context.Context, *sql.Tx) error, error) {
	id, err := r.newID(now)
	if err != nil {
		return Proposal{}, nil, err
	}
	p.ID, p.CreatedAt, p.Superseded = id, now, false
	p.Files, p.StepsServer = nonNil(p.Files), nonNil(p.StepsServer)
	files, err := json.Marshal(p.Files)
	if err != nil {
		return Proposal{}, nil, fmt.Errorf("cannot save the proposal: %w", err)
	}
	steps, err := json.Marshal(p.StepsServer)
	if err != nil {
		return Proposal{}, nil, fmt.Errorf("cannot save the proposal: %w", err)
	}
	if p.Commands == nil {
		p.Commands = []RanCommand{}
	}
	cmds, err := json.Marshal(p.Commands)
	if err != nil {
		return Proposal{}, nil, fmt.Errorf("cannot save the proposal: %w", err)
	}
	scripts, err := scriptsJSON(p)
	if err != nil {
		return Proposal{}, nil, err
	}
	stepsDone, err := stepsJSON(p.Steps)
	if err != nil {
		return Proposal{}, nil, err
	}
	return p, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE fix_proposal SET superseded = 1 WHERE attempt_id = ?`, p.AttemptID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO fix_proposal (`+proposalCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?,?,?,?,?,?)`,
			p.ID, p.AttemptID, p.Summary, p.Diff, string(files), p.TestsStatus, p.TestsOutput, b2i(p.RescanClean), p.Risk, p.Hash, string(steps), ts(now),
			p.CommitSHA, base64.StdEncoding.EncodeToString(p.DiffRaw), p.FromVersion, p.ToVersion, string(cmds), scripts, stepsDone, p.Tree)
		return err
	}, nil
}

// ReplaceApproved swaps the proposal of an approved attempt for p, approved
// by by, in one transaction: the attempt never leaves approved, so the worker
// never sees it as proposed, and a failure leaves the old approval whole.
// fromProposalID must be the approved proposal (ErrBadTransition otherwise).
func (r *Repo) ReplaceApproved(ctx context.Context, id, fromProposalID string, p Proposal, by string) (Proposal, error) {
	now := r.now()
	p.AttemptID = id
	p, insert, err := r.proposalInsert(p, now)
	if err != nil {
		return Proposal{}, err
	}
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return Proposal{}, fmt.Errorf("cannot save the proposal: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE fix_attempt SET approved_by = ?, approved_proposal = ?, approved_hash = ?, updated_at = ?
		WHERE id = ? AND state = ? AND approved_proposal = ?`, by, p.ID, p.Hash, ts(now), id, string(StateApproved), fromProposalID)
	if err != nil {
		return Proposal{}, fmt.Errorf("cannot change the fix attempt: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Proposal{}, fmt.Errorf("%w (the attempt is no longer approved on that proposal)", ErrBadTransition)
	}
	if err := insert(ctx, tx); err != nil {
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
	var err error
	var files, steps, created, raw, cmds, scripts, ran string
	var rescan, superseded int
	if err := s.Scan(&p.ID, &p.AttemptID, &p.Summary, &p.Diff, &files, &p.TestsStatus, &p.TestsOutput, &rescan, &p.Risk, &p.Hash, &steps, &created, &superseded, &p.CommitSHA, &raw, &p.FromVersion, &p.ToVersion, &cmds, &scripts, &ran, &p.Tree); err != nil {
		return Proposal{}, err
	}
	if scripts != "" {
		var rec serverRecord
		if err := json.Unmarshal([]byte(scripts), &rec); err != nil {
			return Proposal{}, fmt.Errorf("proposal %s has unreadable scripts: %w", p.ID, err)
		}
		p.Scripts, p.Server = &rec.Bundle, &rec.Server
	}
	if err := json.Unmarshal([]byte(ran), &p.Steps); err != nil {
		return Proposal{}, fmt.Errorf("proposal %s has unreadable steps: %w", p.ID, err)
	}
	if p.Steps == nil {
		p.Steps = []StepResult{}
	}
	if p.DiffRaw, err = base64.StdEncoding.DecodeString(raw); err != nil {
		return Proposal{}, fmt.Errorf("proposal %s has an unreadable patch: %w", p.ID, err)
	}
	if err := json.Unmarshal([]byte(files), &p.Files); err != nil {
		return Proposal{}, fmt.Errorf("proposal %s has an unreadable file list: %w", p.ID, err)
	}
	if err := json.Unmarshal([]byte(cmds), &p.Commands); err != nil {
		return Proposal{}, fmt.Errorf("proposal %s has an unreadable list of commands: %w", p.ID, err)
	}
	if p.Commands == nil {
		p.Commands = []RanCommand{}
	}
	if err := json.Unmarshal([]byte(steps), &p.StepsServer); err != nil {
		return Proposal{}, fmt.Errorf("proposal %s has an unreadable list of server steps: %w", p.ID, err)
	}
	p.Files, p.StepsServer = nonNil(p.Files), nonNil(p.StepsServer)
	p.RescanClean, p.Superseded = rescan != 0, superseded != 0
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
// being worked on or waiting for the user and is not one of except (the
// projects that reached their daily cap), removes it from the queue and
// returns it; ok is false when there is none.
func (r *Repo) NextQueued(ctx context.Context, except ...string) (findingID, projectID string, ok bool, err error) {
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return "", "", false, fmt.Errorf("cannot read the fix queue: %w", err)
	}
	defer tx.Rollback()
	q := `SELECT finding_id, project_id FROM fix_queue
		WHERE project_id NOT IN (SELECT project_id FROM fix_attempt WHERE state IN ` + busyStates + `
			OR (state IN ('applied','unknown') AND project_id IN (SELECT id FROM target)))`
	args := []any{}
	for _, p := range except {
		q += ` AND project_id <> ?`
		args = append(args, p)
	}
	err = tx.QueryRowContext(ctx, q+` ORDER BY queued_at, finding_id LIMIT 1`, args...).Scan(&findingID, &projectID)
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
// agent.claude.auto) for the project on the UTC day of now, plus those made
// for it on the servers of also (a production server's agents run on its
// preprod).
func (r *Repo) StartedToday(ctx context.Context, projectID string, now time.Time, also ...string) (int, error) {
	day := now.UTC().Truncate(24 * time.Hour)
	q := `SELECT project_id, work_json FROM fix_attempt WHERE project_id IN (?` + strings.Repeat(",?", len(also)) + `) AND origin = ? AND created_at >= ? AND created_at < ?`
	args := []any{projectID}
	for _, a := range also {
		args = append(args, a)
	}
	args = append(args, OriginAgentAuto, ts(day), ts(day.Add(24*time.Hour)))
	rows, err := r.s.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return 0, fmt.Errorf("cannot count today's fix attempts: %w", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var pid, work string
		if err := rows.Scan(&pid, &work); err != nil {
			return 0, fmt.Errorf("cannot count today's fix attempts: %w", err)
		}
		if pid == projectID {
			n++
			continue
		}
		var w Work
		if json.Unmarshal([]byte(work), &w) == nil && w.Server != nil && w.Server.ProdTargetID == projectID {
			n++
		}
	}
	err = rows.Err()
	if err != nil {
		return 0, fmt.Errorf("cannot count today's fix attempts: %w", err)
	}
	return n, nil
}

// CountQueued counts the findings of the project waiting in the queue ("" for
// every project).
func (r *Repo) CountQueued(ctx context.Context, projectID string) (int, error) {
	q, args := `SELECT COUNT(*) FROM fix_queue`, []any{}
	if projectID != "" {
		q += ` WHERE project_id = ?`
		args = append(args, projectID)
	}
	var n int
	if err := r.s.DB().QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("cannot read the fix queue: %w", err)
	}
	return n, nil
}

// Dequeue removes a finding from the queue (absent: nothing).
func (r *Repo) Dequeue(ctx context.Context, findingID string) error {
	if _, err := r.s.DB().ExecContext(ctx, `DELETE FROM fix_queue WHERE finding_id = ?`, findingID); err != nil {
		return fmt.Errorf("cannot change the fix queue: %w", err)
	}
	return nil
}

// AttemptsOf returns the attempts of one finding, newest first.
func (r *Repo) AttemptsOf(ctx context.Context, findingID string) ([]Attempt, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT `+attemptCols+` FROM fix_attempt WHERE finding_id = ? ORDER BY created_at DESC, id DESC`, findingID)
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

// SetConsent records the AI consent of a project for hosts (replacing a
// previous one).
func (r *Repo) SetConsent(ctx context.Context, projectID string, hosts []string) error {
	b, err := json.Marshal(nonNil(hosts))
	if err != nil {
		return fmt.Errorf("cannot save the consent: %w", err)
	}
	_, err = r.s.DB().ExecContext(ctx, `INSERT INTO fix_consent (project_id, given_at, hosts) VALUES (?,?,?)
		ON CONFLICT (project_id) DO UPDATE SET given_at = excluded.given_at, hosts = excluded.hosts`, projectID, ts(r.now()), string(b))
	if err != nil {
		return fmt.Errorf("cannot save the consent: %w", err)
	}
	return nil
}

// Consent returns when the project gave its AI consent and for which
// hosts; ok is false when it never did.
func (r *Repo) Consent(ctx context.Context, projectID string) (at time.Time, hosts []string, ok bool, err error) {
	var given, raw string
	err = r.s.DB().QueryRowContext(ctx, `SELECT given_at, hosts FROM fix_consent WHERE project_id = ?`, projectID).Scan(&given, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil, false, nil
	}
	if err != nil {
		return time.Time{}, nil, false, fmt.Errorf("cannot read the consent: %w", err)
	}
	if at, err = parseTime(given); err != nil {
		return time.Time{}, nil, false, err
	}
	if err := json.Unmarshal([]byte(raw), &hosts); err != nil {
		return time.Time{}, nil, false, fmt.Errorf("the consent of project %s is unreadable: %w", projectID, err)
	}
	return at, nonNil(hosts), true, nil
}

// DeleteConsent forgets the AI consent of a project.
func (r *Repo) DeleteConsent(ctx context.Context, projectID string) error {
	if _, err := r.s.DB().ExecContext(ctx, `DELETE FROM fix_consent WHERE project_id = ?`, projectID); err != nil {
		return fmt.Errorf("cannot delete the consent: %w", err)
	}
	return nil
}

// SetSteps records the steps Michel ran for a server proposal.
func (r *Repo) SetSteps(ctx context.Context, proposalID string, steps []StepResult) error {
	js, err := stepsJSON(steps)
	if err != nil {
		return err
	}
	if _, err := r.s.DB().ExecContext(ctx, `UPDATE fix_proposal SET steps = ? WHERE id = ?`, js, proposalID); err != nil {
		return fmt.Errorf("cannot save the steps: %w", err)
	}
	return nil
}

// AckSnapshot records that the user made a snapshot of the server before a
// package upgrade of the attempt (the latest acknowledgement wins).
func (r *Repo) AckSnapshot(ctx context.Context, attemptID, actor string) error {
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot record the snapshot: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM server_snapshot_ack WHERE attempt_id = ?`, attemptID); err != nil {
		return fmt.Errorf("cannot record the snapshot: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO server_snapshot_ack (attempt_id, at, actor) VALUES (?,?,?)`, attemptID, ts(r.now()), actor); err != nil {
		return fmt.Errorf("cannot record the snapshot: %w", err)
	}
	return tx.Commit()
}

// SnapshotAck tells whether, when and by whom the snapshot of the attempt
// was acknowledged.
func (r *Repo) SnapshotAck(ctx context.Context, attemptID string) (at time.Time, actor string, ok bool, err error) {
	var when string
	err = r.s.DB().QueryRowContext(ctx, `SELECT at, actor FROM server_snapshot_ack WHERE attempt_id = ?`, attemptID).Scan(&when, &actor)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, "", false, nil
	}
	if err != nil {
		return time.Time{}, "", false, fmt.Errorf("cannot read the snapshot: %w", err)
	}
	at, err = parseTime(when)
	return at, actor, err == nil, err
}

// ServerBackup is the copy of a server file a fix backed up, kept on the
// workstation. Content is the plain file; the store only ever holds it
// sealed (see Deps.addBackup).
type ServerBackup struct {
	ID         string
	AttemptID  string
	TargetID   string
	RemotePath string
	SHA256     string
	Content    []byte
	CreatedAt  time.Time
	// KeyFingerprint names the key the copy was sealed with ("" for a copy
	// stored before Michel recorded it).
	KeyFingerprint string
}

// AddBackup stores a sealed backup: blob is the encrypted content, b.Content
// is not stored.
func (r *Repo) AddBackup(ctx context.Context, b ServerBackup, blob []byte) (ServerBackup, error) {
	now := r.now()
	id, err := r.newID(now)
	if err != nil {
		return ServerBackup{}, err
	}
	b.ID, b.CreatedAt = id, now
	if _, err := r.s.DB().ExecContext(ctx, `INSERT INTO server_backup (id, attempt_id, target_id, remote_path, sha256, blob, created_at, key_fingerprint) VALUES (?,?,?,?,?,?,?,?)`,
		b.ID, b.AttemptID, b.TargetID, b.RemotePath, b.SHA256, base64.StdEncoding.EncodeToString(blob), ts(now), b.KeyFingerprint); err != nil {
		return ServerBackup{}, fmt.Errorf("cannot save the backup: %w", err)
	}
	return b, nil
}

// BackupSize is the size in bytes of the backups the workstation keeps for
// server targetID (the sealed copies, about their plain size) and how many
// files they are.
func (r *Repo) BackupSize(ctx context.Context, targetID string) (bytes int64, files int, err error) {
	var n, total sql.NullInt64
	// The blobs are base64: three bytes for four characters.
	if err := r.s.DB().QueryRowContext(ctx, `SELECT COUNT(*), SUM(LENGTH(blob)) FROM server_backup WHERE target_id = ?`, targetID).Scan(&n, &total); err != nil {
		return 0, 0, fmt.Errorf("cannot read the size of the backups: %w", err)
	}
	return total.Int64 / 4 * 3, int(n.Int64), nil
}

// SealedBackup is a stored backup with its encrypted content.
type SealedBackup struct {
	ServerBackup
	Blob []byte
}

// Backups returns the stored backups of an attempt, oldest first, still
// sealed.
func (r *Repo) Backups(ctx context.Context, attemptID string) ([]SealedBackup, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT id, attempt_id, target_id, remote_path, sha256, blob, created_at, key_fingerprint FROM server_backup WHERE attempt_id = ? ORDER BY created_at, id`, attemptID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the backups: %w", err)
	}
	defer rows.Close()
	var out []SealedBackup
	for rows.Next() {
		var b SealedBackup
		var blob, created string
		if err := rows.Scan(&b.ID, &b.AttemptID, &b.TargetID, &b.RemotePath, &b.SHA256, &blob, &created, &b.KeyFingerprint); err != nil {
			return nil, err
		}
		if b.Blob, err = base64.StdEncoding.DecodeString(blob); err != nil {
			return nil, fmt.Errorf("backup %s is unreadable: %w", b.ID, err)
		}
		if b.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// PurgeBackups deletes the workstation copies of the backups made before
// before. The backups on the servers are never touched.
func (r *Repo) PurgeBackups(ctx context.Context, before time.Time) (int, error) {
	res, err := r.s.DB().ExecContext(ctx, `DELETE FROM server_backup WHERE created_at < ?`, ts(before))
	if err != nil {
		return 0, fmt.Errorf("cannot purge the backups: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// Claim moves an approved attempt to running in one conditional update and
// reports whether this caller got it: only one Apply, in any process, ever
// runs a server fix's script, and never while another attempt of the same
// server is running, applied or unknown (serverRunStates). deadline is when
// the run's own bound ends.
func (r *Repo) Claim(ctx context.Context, id string, deadline time.Time) (bool, error) {
	res, err := r.s.DB().ExecContext(ctx, `UPDATE fix_attempt SET state = ?, updated_at = ?, run_deadline = ? WHERE id = ? AND state = ?
		AND NOT EXISTS (SELECT 1 FROM fix_attempt o WHERE o.project_id = (SELECT p.project_id FROM fix_attempt p WHERE p.id = ?)
			AND o.id <> ? AND o.state IN `+serverRunStates+`)`,
		string(StateRunning), ts(r.now()), ts(deadline), id, string(StateApproved), id, id)
	if err != nil {
		return false, fmt.Errorf("cannot change the fix attempt: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("cannot change the fix attempt: %w", err)
	}
	return n == 1, nil
}

// RunEnd is an attempt that is running or applied, with the end of its
// run's bound (zero when the record has none).
type RunEnd struct {
	Attempt  Attempt
	Deadline time.Time
}

// RunEnds lists the running and applied attempts with their run deadline.
func (r *Repo) RunEnds(ctx context.Context) ([]RunEnd, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT id, run_deadline FROM fix_attempt WHERE state IN (?, ?)`, string(StateRunning), string(StateApplied))
	if err != nil {
		return nil, fmt.Errorf("cannot read the fix attempts: %w", err)
	}
	type row struct{ id, deadline string }
	var list []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.id, &x.deadline); err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, x)
	}
	// Closed before reading the attempts: the store has one connection.
	if err := rows.Close(); err != nil {
		return nil, err
	}
	var out []RunEnd
	for _, x := range list {
		a, err := r.GetAttempt(ctx, x.id)
		if err != nil {
			return nil, err
		}
		e := RunEnd{Attempt: a}
		if x.deadline != "" {
			if e.Deadline, err = parseTime(x.deadline); err != nil {
				return nil, err
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// BackupKeyFingerprint is the fingerprint of the backup key, "" when none
// was made yet.
func (r *Repo) BackupKeyFingerprint(ctx context.Context) (string, error) {
	var fp string
	err := r.s.DB().QueryRowContext(ctx, `SELECT fingerprint FROM server_backup_key WHERE id = 1`).Scan(&fp)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("cannot read the backup key: %w", err)
	}
	return fp, nil
}

// SetBackupKeyFingerprint records fp as the backup key's when the current
// one is old ("" for none), in one conditional statement: it reports
// whether this caller won.
func (r *Repo) SetBackupKeyFingerprint(ctx context.Context, old, fp string) (bool, error) {
	var res sql.Result
	var err error
	if old == "" {
		res, err = r.s.DB().ExecContext(ctx, `INSERT INTO server_backup_key (id, fingerprint) VALUES (1, ?) ON CONFLICT (id) DO NOTHING`, fp)
	} else {
		res, err = r.s.DB().ExecContext(ctx, `UPDATE server_backup_key SET fingerprint = ? WHERE id = 1 AND fingerprint = ?`, fp, old)
	}
	if err != nil {
		return false, fmt.Errorf("cannot record the backup key: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// What stands between a server and its removal.
const (
	// BlockWait: a fix is being prepared or run (or approved to be run by
	// Michel): it ends by itself.
	BlockWait = "wait"
	// BlockUnknown: a fix of unknown outcome: only the user can end it
	// (ResolveUnknown).
	BlockUnknown = "unknown"
	// BlockApproved: a fix the user runs themselves is approved and waits for
	// their word: they run it (applied-by-me) or refuse it.
	BlockApproved = "approved"
)

// TargetBlock says what, if anything, must end before server targetID can
// leave Michel: BlockWait (preparing, running, applied, approved for Michel to run),
// BlockUnknown, BlockApproved, or "" when nothing is pending. The first
// that applies wins, in that order.
func (r *Repo) TargetBlock(ctx context.Context, targetID string) (string, error) {
	list, err := r.ListAttempts(ctx, targetID, "")
	if err != nil {
		return "", err
	}
	rank := map[string]int{"": 0, BlockApproved: 1, BlockUnknown: 2, BlockWait: 3}
	block := ""
	for _, a := range list {
		b := ""
		switch a.State {
		case StatePreparing, StateRunning, StateApplied:
			// Applied: the steps after the script (site check, undo,
			// recollection) still need the server.
			b = BlockWait
		case StateUnknown:
			b = BlockUnknown
		case StateApproved:
			b = BlockWait
			if p, ok, err := r.CurrentProposal(ctx, a.ID); err == nil && ok && p.Server != nil && p.Server.Executor == target.ExecUser {
				b = BlockApproved
			}
		}
		if rank[b] > rank[block] {
			block = b
		}
	}
	return block, nil
}

// GitAnswerRow is one project's answer about its Git service. URL is
// Remote.Address: no secret and no SSH user. RuleWritten says the network rule of
// Host is Michel's to remove.
type GitAnswerRow struct {
	ProjectID, Answer, RemoteName, URL, Host, Provider string
	RuleWritten                                        bool
	AnsweredAt                                         time.Time
}

// FixPush is a fix branch that reached the remote, kept with its first date.
type FixPush struct {
	AttemptID, CommitSHA, Host string
	PushedAt                   time.Time
}

// GitAnswer returns the project's answer; ok is false when it never answered.
func (r *Repo) GitAnswer(ctx context.Context, projectID string) (GitAnswerRow, bool, error) {
	row := GitAnswerRow{ProjectID: projectID}
	var written int
	var at string
	err := r.s.DB().QueryRowContext(ctx, `SELECT answer, remote_name, url, host, provider, rule_written, answered_at
		FROM project_remote WHERE project_id = ?`, projectID).Scan(&row.Answer, &row.RemoteName, &row.URL, &row.Host, &row.Provider, &written, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return GitAnswerRow{}, false, nil
	}
	if err != nil {
		return GitAnswerRow{}, false, fmt.Errorf("cannot read the Git answer: %w", err)
	}
	row.RuleWritten = written != 0
	if row.AnsweredAt, err = parseTime(at); err != nil {
		return GitAnswerRow{}, false, err
	}
	return row, true, nil
}

// SetGitAnswer stores the project's answer in place of the last one.
func (r *Repo) SetGitAnswer(ctx context.Context, row GitAnswerRow) error {
	written := 0
	if row.RuleWritten {
		written = 1
	}
	_, err := r.s.DB().ExecContext(ctx, `INSERT INTO project_remote (project_id, answer, remote_name, url, host, provider, rule_written, answered_at)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT (project_id) DO UPDATE SET answer = excluded.answer, remote_name = excluded.remote_name, url = excluded.url,
			host = excluded.host, provider = excluded.provider, rule_written = excluded.rule_written, answered_at = excluded.answered_at`,
		row.ProjectID, row.Answer, row.RemoteName, row.URL, row.Host, row.Provider, written, ts(r.now()))
	if err != nil {
		return fmt.Errorf("cannot save the Git answer: %w", err)
	}
	return nil
}

// PassGitRule hands the rule of host over to the other projects attached to it, so
// that the last one to leave removes it. It returns how many there are.
func (r *Repo) PassGitRule(ctx context.Context, projectID, host string) (int, error) {
	res, err := r.s.DB().ExecContext(ctx, `UPDATE project_remote SET rule_written = 1
		WHERE answer = 'yes' AND host = ? AND project_id <> ?`, host, projectID)
	if err != nil {
		return 0, fmt.Errorf("cannot read who uses the rule: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("cannot read who uses the rule: %w", err)
	}
	return int(n), nil
}

// RecordPush notes that a fix branch reached the remote. A second click keeps the
// first date.
func (r *Repo) RecordPush(ctx context.Context, p FixPush) error {
	_, err := r.s.DB().ExecContext(ctx, `INSERT INTO fix_push (attempt_id, commit_sha, host, pushed_at) VALUES (?,?,?,?)
		ON CONFLICT(attempt_id) DO NOTHING`, p.AttemptID, p.CommitSHA, p.Host, ts(p.PushedAt))
	if err != nil {
		return fmt.Errorf("cannot save the push: %w", err)
	}
	return nil
}

// Push returns what was sent for an attempt; ok is false when nothing was.
func (r *Repo) Push(ctx context.Context, attemptID string) (FixPush, bool, error) {
	p := FixPush{AttemptID: attemptID}
	var at string
	err := r.s.DB().QueryRowContext(ctx, `SELECT commit_sha, host, pushed_at FROM fix_push WHERE attempt_id = ?`, attemptID).Scan(&p.CommitSHA, &p.Host, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return FixPush{}, false, nil
	}
	if err != nil {
		return FixPush{}, false, fmt.Errorf("cannot read the push: %w", err)
	}
	if p.PushedAt, err = parseTime(at); err != nil {
		return FixPush{}, false, err
	}
	return p, true, nil
}
