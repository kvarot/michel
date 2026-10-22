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

// Head anchor reasons reported by Verify.
const (
	ReasonTailTruncated = "tail truncated"
	ReasonHeadAbsent    = "head anchor absent"
)

// Verify recomputes every hash in insertion order and stops at the first
// event that does not match. It also compares the chain with the audit.head
// side file written next to the database. The file is read before the chain
// is walked: events recorded after that read are expected and fine. The
// Reason is "tail truncated" when the chain no longer holds the event the
// head points at (fewer events than the head count) or holds a different
// one (hash mismatch at that position). When the file is missing the Reason
// is "head anchor absent", which is not a broken chain. That file raises
// the bar against deleting the newest events, but it is not a signature:
// someone who can edit the database can edit the file too.
func Verify(ctx context.Context, s *store.Store) (VerifyResult, error) {
	n, h, ok := readHead(s.Path())
	return verifyAgainst(ctx, s, n, h, ok)
}

// verifyAgainst walks the chain and checks it against a head read earlier.
func verifyAgainst(ctx context.Context, s *store.Store, headCount int, headHash string, headOK bool) (VerifyResult, error) {
	rows, err := s.DB().QueryContext(ctx, `SELECT id, ts, actor, action, target, result,
		correlation_id, evidence, prev_hash, hash FROM audit_event ORDER BY rowid`)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("cannot read the audit log: %w", err)
	}
	defer rows.Close()
	var res VerifyResult
	prev := ""
	atHead := "" // hash of the event at position headCount, once walked
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
		if res.Checked == headCount {
			atHead = e.Hash
		}
	}
	if err := rows.Err(); err != nil {
		return res, err
	}
	res.Head = prev
	switch {
	case !headOK:
		res.Reason = ReasonHeadAbsent
	case headCount > 0 && (res.Checked < headCount || atHead != headHash):
		res.Reason, res.Expected = ReasonTailTruncated, headCount
	}
	return res, nil
}
