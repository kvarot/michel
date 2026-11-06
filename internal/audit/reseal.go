package audit

import (
	"context"
	"errors"
	"fmt"

	"github.com/kvarot/michel/internal/store"
)

// ErrResealRefused is returned by Reseal when the log does not fail on its
// seals: it verifies, or its chain itself is broken or cut (evidence that a
// reseal must not hide).
var ErrResealRefused = errors.New("the audit log cannot be resealed")

// ResealResult says what a reseal did.
type ResealResult struct {
	// Reason is why the log failed before the reseal.
	Reason string
	// PreviousFrom is the old start of the seals (0: never set).
	PreviousFrom int64
	// From is the first event that must be sealed now; the Unprotected
	// events before it are no longer covered by the seals.
	From        int64
	Unprotected int
}

// ResealAllowed says whether res fails on its seals only: the sealed anchor
// is missing or wrong, or a seal is missing or wrong, while every hash of the
// chain holds and no event is missing.
func ResealAllowed(res VerifyResult) bool {
	switch res.Reason {
	case ReasonSealedAnchor, ReasonSealMissing, ReasonSealMismatch:
		return true
	}
	return false
}

// Reseal starts the seals again after the last event, with key, when the log
// fails on its seals only (see ResealAllowed): the events already there are
// no longer covered by the seals. It is the explicit repair of a key kept
// with a database made again; the caller records audit.reseal right after,
// so the reseal stays in the log.
func Reseal(ctx context.Context, st *store.Store, key []byte) (ResealResult, error) {
	tx, err := st.DB().BeginTx(ctx, nil) // immediate: no event is written meanwhile
	if err != nil {
		return ResealResult{}, fmt.Errorf("cannot reseal the audit log: %w", err)
	}
	defer tx.Rollback()
	n, h, ok := readHead(st.Path())
	res, err := verifyAgainst(ctx, tx, n, h, ok, VerifyOptions{Key: key, Required: true})
	if err != nil {
		return ResealResult{}, err
	}
	if !ResealAllowed(res) {
		return ResealResult{Reason: res.Reason}, ErrResealRefused
	}
	a, err := readSealedAnchor(ctx, tx)
	if err != nil {
		return ResealResult{}, err
	}
	if err := startSealing(ctx, tx, key); err != nil {
		return ResealResult{}, err
	}
	out := ResealResult{Reason: res.Reason, PreviousFrom: a.From}
	if err := tx.QueryRowContext(ctx, `SELECT sealed_from FROM audit_anchor WHERE id = 1`).Scan(&out.From); err != nil {
		return ResealResult{}, fmt.Errorf("cannot reseal the audit log: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_event WHERE seq < ?`, out.From).Scan(&out.Unprotected); err != nil {
		return ResealResult{}, fmt.Errorf("cannot reseal the audit log: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ResealResult{}, fmt.Errorf("cannot reseal the audit log: %w", err)
	}
	return out, nil
}

// ResealPlan says what Reseal would do now, without writing: the result of
// the verification, and how many events would leave the seals.
func ResealPlan(ctx context.Context, st *store.Store, key []byte) (VerifyResult, int, error) {
	res, err := VerifyWith(ctx, st, VerifyOptions{Key: key, Required: true})
	if err != nil {
		return res, 0, err
	}
	var n int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_event`).Scan(&n); err != nil {
		return res, 0, fmt.Errorf("cannot read the audit log: %w", err)
	}
	return res, n, nil
}
