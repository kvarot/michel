package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// The kinds of a timeline entry besides the finding kinds.
const (
	KindDecision = "decision"
	KindAttempt  = "attempt"
)

// hiddenStates are the attempt states the timeline shows only as the last
// state of an attempt.
var hiddenStates = map[string]bool{"running": true, "unknown": true}

// Entry is one line of a finding's timeline.
type Entry struct {
	At            time.Time
	Kind          string
	Detail        map[string]any
	Reconstructed bool
}

// Timeline returns what happened to finding findingID, newest first: its
// events, its decisions and the states of its fix attempts. Entries at the
// same instant keep their order, reversed.
func Timeline(ctx context.Context, db *sql.DB, findingID string) ([]Entry, error) {
	var out []Entry
	events, err := findingEvents(ctx, db, findingID)
	if err != nil {
		return nil, err
	}
	out = append(out, events...)
	decisions, err := decisionEntries(ctx, db, findingID)
	if err != nil {
		return nil, err
	}
	out = append(out, decisions...)
	attempts, err := attemptEntries(ctx, db, findingID)
	if err != nil {
		return nil, err
	}
	out = append(out, attempts...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if out == nil {
		out = []Entry{}
	}
	return out, nil
}

func parseAt(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }

func findingEvents(ctx context.Context, db *sql.DB, findingID string) ([]Entry, error) {
	rows, err := db.QueryContext(ctx, `SELECT at, kind, detail FROM finding_event WHERE finding_id = ? ORDER BY seq`, findingID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the history of the finding: %w", err)
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var at, kind, detail string
		if err := rows.Scan(&at, &kind, &detail); err != nil {
			return nil, fmt.Errorf("cannot read the history of the finding: %w", err)
		}
		e := Entry{Kind: kind, Detail: map[string]any{}}
		if e.At, err = parseAt(at); err != nil {
			return nil, fmt.Errorf("cannot read the history of the finding: %w", err)
		}
		if err := json.Unmarshal([]byte(detail), &e.Detail); err != nil {
			return nil, fmt.Errorf("cannot read the history of the finding: %w", err)
		}
		if e.Detail == nil {
			e.Detail = map[string]any{}
		}
		e.Reconstructed = e.Detail["reconstructed"] == true
		delete(e.Detail, "reconstructed")
		out = append(out, e)
	}
	return out, rows.Err()
}

func decisionEntries(ctx context.Context, db *sql.DB, findingID string) ([]Entry, error) {
	rows, err := db.QueryContext(ctx, `SELECT action, author, due_at, created_at, superseded_at, superseded_reason
		FROM decision WHERE finding_id = ? ORDER BY created_at, id`, findingID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the decisions: %w", err)
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var action, author, due, created, superseded, reason string
		if err := rows.Scan(&action, &author, &due, &created, &superseded, &reason); err != nil {
			return nil, fmt.Errorf("cannot read the decisions: %w", err)
		}
		at, err := parseAt(created)
		if err != nil {
			return nil, fmt.Errorf("cannot read the decisions: %w", err)
		}
		d := map[string]any{"action": action, "author": author}
		if due != "" {
			d["due"] = due
		}
		if superseded != "" {
			d["superseded_at"] = superseded
			d["reason"] = reason
		}
		out = append(out, Entry{At: at, Kind: KindDecision, Detail: d})
	}
	return out, rows.Err()
}

func attemptEntries(ctx context.Context, db *sql.DB, findingID string) ([]Entry, error) {
	rows, err := db.QueryContext(ctx, `SELECT e.attempt_id, e.at, e.state, e.reconstructed
		FROM fix_attempt_event e JOIN fix_attempt a ON a.id = e.attempt_id
		WHERE a.finding_id = ? ORDER BY a.created_at, e.attempt_id, e.seq`, findingID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the fix attempts: %w", err)
	}
	defer rows.Close()
	// The attempt id and the state stay typed until the entries are built.
	type state struct {
		attemptID, state string
		at               time.Time
		reconstructed    bool
	}
	var all []state
	for rows.Next() {
		var id, at, st string
		var rec int
		if err := rows.Scan(&id, &at, &st, &rec); err != nil {
			return nil, fmt.Errorf("cannot read the fix attempts: %w", err)
		}
		t, err := parseAt(at)
		if err != nil {
			return nil, fmt.Errorf("cannot read the fix attempts: %w", err)
		}
		all = append(all, state{attemptID: id, state: st, at: t, reconstructed: rec != 0})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the fix attempts: %w", err)
	}
	var out []Entry
	for i, s := range all {
		last := i == len(all)-1 || all[i+1].attemptID != s.attemptID
		if hiddenStates[s.state] && !last {
			continue
		}
		out = append(out, Entry{At: s.at, Kind: KindAttempt, Detail: map[string]any{"attempt_id": s.attemptID, "state": s.state},
			Reconstructed: s.reconstructed})
	}
	return out, nil
}
