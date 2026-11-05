package audit

import (
	"context"
	"crypto/hmac"
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
	// Sealed counts the events whose seal was checked; Unsealed those written
	// before the protection (no seal, before the first sealed event). Both
	// stay 0 when the seals are not checked.
	Sealed, Unsealed int
}

// Head anchor and seal reasons reported by Verify.
const (
	ReasonTailTruncated  = "tail truncated"
	ReasonHeadAbsent     = "head anchor absent"
	ReasonSealMismatch   = "seal mismatch"
	ReasonSealMissing    = "seal missing"
	ReasonSealKeyMissing = "seal key missing"
)

// VerifyOptions say how much Verify checks. Required (integrity_protection:
// required) checks the seals with Key and makes an absent head anchor a
// failure once there are events; without it the seals are not looked at.
type VerifyOptions struct {
	Key      []byte
	Required bool
}

// Failed says whether the result is a failure: a broken event, a truncated
// tail, or, when the protection is required, an absent anchor with events.
func (r VerifyResult) Failed(required bool) bool {
	return r.Broken != nil || r.Reason == ReasonTailTruncated || (required && r.Reason == ReasonHeadAbsent && r.Checked > 0)
}

// Verify is VerifyWith without the seals: the chain and the head anchor only.
func Verify(ctx context.Context, s *store.Store) (VerifyResult, error) {
	return VerifyWith(ctx, s, VerifyOptions{})
}

// VerifyWith recomputes every hash in chain order (seq) and stops at the
// first event that does not match. It also compares the chain with the
// audit.head side file written next to the database. The file is read before
// the chain is walked: events recorded after that read are expected and fine.
// The Reason is "tail truncated" when the chain no longer holds the event the
// head points at (fewer events than the head count) or holds a different one
// (hash mismatch at that position). When the file is missing the Reason is
// "head anchor absent", a failure only when the protection is required. With
// opt.Required, every event from the first sealed one on must carry a seal
// made with opt.Key: a wrong seal, a seal removed, or a seal that cannot be
// checked for want of the key is a broken event. Events before the first
// sealed one were written before the protection and are only counted.
func VerifyWith(ctx context.Context, s *store.Store, opt VerifyOptions) (VerifyResult, error) {
	n, h, ok := readHead(s.Path())
	return verifyAgainst(ctx, s, n, h, ok, opt)
}

// verifyAgainst walks the chain and checks it against a head read earlier.
func verifyAgainst(ctx context.Context, s *store.Store, headCount int, headHash string, headOK bool, opt VerifyOptions) (VerifyResult, error) {
	rows, err := s.DB().QueryContext(ctx, `SELECT seq, id, ts, actor, action, target, result,
		correlation_id, evidence, prev_hash, hash, hmac FROM audit_event ORDER BY seq`)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("cannot read the audit log: %w", err)
	}
	defer rows.Close()
	var res VerifyResult
	prev := ""
	atHead := "" // hash of the event at position headCount, once walked
	sealedSeen := false
	for rows.Next() {
		var e Event
		var evidence string
		if err := rows.Scan(&e.Seq, &e.ID, &e.TS, &e.Actor, &e.Action, &e.Target, &e.Result,
			&e.CorrelationID, &evidence, &e.PrevHash, &e.Hash, &e.HMAC); err != nil {
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
		if reason == "" && opt.Required {
			switch {
			case e.HMAC == "" && sealedSeen:
				reason = ReasonSealMissing
			case e.HMAC == "":
				res.Unsealed++
			case opt.Key == nil:
				reason = ReasonSealKeyMissing
			case !hmac.Equal([]byte(e.HMAC), []byte(seal(opt.Key, e.Hash))):
				reason = ReasonSealMismatch
			default:
				sealedSeen = true
				res.Sealed++
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
