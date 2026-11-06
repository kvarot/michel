package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
)

// sealedAnchor is the sealed part of audit_anchor: From is the seq of the
// first event that must carry a seal (0 while the log is not sealed), Seq and
// Head the place and hash of the last sealed event (0 and "" before the first
// one), MAC binds the three with the key of the seals.
type sealedAnchor struct {
	From, Seq int64
	Head, MAC string
	ok        bool // the row exists
}

// anchorMAC is the HMAC of a sealed anchor with key, hex. Its text starts
// with a label of its own, so it never equals the seal of an event.
func anchorMAC(key []byte, from, seq int64, head string) string {
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "michel audit sealed anchor\n%d\n%d\n%s", from, seq, head)
	return hex.EncodeToString(m.Sum(nil))
}

// valid says whether the anchor was made with key.
func (a sealedAnchor) valid(key []byte) bool {
	return a.ok && key != nil && a.From > 0 &&
		hmac.Equal([]byte(a.MAC), []byte(anchorMAC(key, a.From, a.Seq, a.Head)))
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func readSealedAnchor(ctx context.Context, q querier) (sealedAnchor, error) {
	var a sealedAnchor
	err := q.QueryRowContext(ctx, `SELECT sealed_from, sealed_seq, sealed_head, sealed_mac FROM audit_anchor WHERE id = 1`).
		Scan(&a.From, &a.Seq, &a.Head, &a.MAC)
	if errors.Is(err, sql.ErrNoRows) {
		return sealedAnchor{}, nil
	}
	if err != nil {
		return sealedAnchor{}, fmt.Errorf("cannot read the sealed anchor of the audit log: %w", err)
	}
	a.ok = true
	return a, nil
}

// startSealing starts the protection in tx: the next event is the first that
// must carry a seal made with key. Only the process that has just made the key
// calls it, so it never moves the start of seals made with that key.
func startSealing(ctx context.Context, tx *sql.Tx, key []byte) error {
	last, head := int64(0), ""
	err := tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_event ORDER BY seq DESC LIMIT 1`).Scan(&last, &head)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("cannot read the audit chain: %w", err)
	}
	from := last + 1
	res, err := tx.ExecContext(ctx, `UPDATE audit_anchor SET sealed_from = ?, sealed_seq = ?, sealed_head = ?, sealed_mac = ? WHERE id = 1`,
		from, last, head, anchorMAC(key, from, last, head))
	if err != nil {
		return fmt.Errorf("cannot start the seals of the audit log: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errors.New("cannot start the seals of the audit log: its anchor row is missing")
	}
	return nil
}

// advanceSealedAnchor moves the sealed anchor to e, sealed with key, in tx.
// It moves only an anchor made with key that points at the event just before
// e: an anchor that is missing, forged, or ahead of the chain (sealed events
// removed) stays as it is, so audit verify still reports it; ok is false then.
func advanceSealedAnchor(ctx context.Context, tx *sql.Tx, key []byte, e Event) (ok bool, err error) {
	a, err := readSealedAnchor(ctx, tx)
	if err != nil {
		return false, err
	}
	if !a.valid(key) || a.Seq != e.Seq-1 || a.Head != e.PrevHash {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE audit_anchor SET sealed_seq = ?, sealed_head = ?, sealed_mac = ? WHERE id = 1`,
		e.Seq, e.Hash, anchorMAC(key, a.From, e.Seq, e.Hash)); err != nil {
		return false, fmt.Errorf("cannot move the sealed anchor of the audit log: %w", err)
	}
	return true, nil
}
