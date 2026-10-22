package audit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kvarot/michel/internal/store"
)

// VerifyResult is the outcome of walking the chain.
type VerifyResult struct {
	Checked  int
	Broken   *Event
	Reason   string
	Expected int    // events the head file says exist (only set when the tail is truncated)
	Head     string // hash of the last verified event
}

// Verify recomputes every hash in insertion order and stops at the first
// event that does not match. It also compares the chain with the audit.head
// side file written next to the database: if the file records more events
// than the chain holds, or a different head hash, the Reason is
// "tail truncated". That file raises the bar against deleting the newest
// events, but it is not a signature: someone who can edit the database can
// edit the file too.
func Verify(ctx context.Context, s *store.Store) (VerifyResult, error) {
	rows, err := s.DB().QueryContext(ctx, `SELECT id, ts, actor, action, target, result,
		correlation_id, evidence, prev_hash, hash FROM audit_event ORDER BY rowid`)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("cannot read the audit log: %w", err)
	}
	defer rows.Close()
	var res VerifyResult
	prev := ""
	for rows.Next() {
		var e Event
		var evidence string
		if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.Target, &e.Result,
			&e.CorrelationID, &evidence, &e.PrevHash, &e.Hash); err != nil {
			return res, fmt.Errorf("cannot read the audit log: %w", err)
		}
		_ = json.Unmarshal([]byte(evidence), &e.Evidence)
		reason := ""
		switch {
		case e.PrevHash != prev:
			reason = "prev_hash mismatch"
		default:
			canon, err := canonical(e, json.RawMessage(evidence))
			if err != nil || chainHash(e.PrevHash, canon) != e.Hash {
				reason = "hash mismatch"
			}
		}
		if reason != "" {
			res.Broken, res.Reason = &e, reason
			return res, nil
		}
		res.Checked++
		prev = e.Hash
	}
	if err := rows.Err(); err != nil {
		return res, err
	}
	res.Head = prev
	if n, h, ok := readHead(s.Path()); ok && (n > res.Checked || (n == res.Checked && h != prev)) {
		res.Reason, res.Expected = "tail truncated", n
	}
	return res, nil
}
