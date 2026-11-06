package audit

import (
	"context"
	"errors"
	"testing"
)

// The key is kept but the sealed anchor was never made (michel.db made
// again): verify fails until a reseal, then passes, with every older event
// outside the seals.
func TestResealAfterANewDatabase(t *testing.T) {
	ctx := context.Background()
	l, s := newLogger(t)
	l.SetKey(testKey) // sealing without an anchor
	record3(t, l)
	before, err := VerifyWith(ctx, s, required(testKey))
	if err != nil || before.Reason != ReasonSealedAnchor || !ResealAllowed(before) {
		t.Fatalf("before: %+v %v", before, err)
	}
	r, err := Reseal(ctx, s, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if r.From != 4 || r.Unprotected != 3 {
		t.Errorf("reseal = %+v, want from 4 and 3 events outside the seals", r)
	}
	record3(t, l)
	after, err := VerifyWith(ctx, s, required(testKey))
	if err != nil || after.Failed(true) || after.Sealed != 3 || after.Unsealed != 3 {
		t.Errorf("after: %+v %v", after, err)
	}
}

// Seals made with a lost key, then a new key: the events of the old key are
// before the new seals, not failures.
func TestResealAfterANewKey(t *testing.T) {
	ctx := context.Background()
	l, s := fourSealed(t)
	newKey := []byte("fedcba9876543210fedcba9876543210")
	l.SetKey(newKey)
	record3(t, l)
	before, err := VerifyWith(ctx, s, required(newKey))
	if err != nil || !before.Failed(true) || !ResealAllowed(before) {
		t.Fatalf("before: %+v %v", before, err)
	}
	if _, err := Reseal(ctx, s, newKey); err != nil {
		t.Fatal(err)
	}
	record3(t, l)
	after, err := VerifyWith(ctx, s, required(newKey))
	if err != nil || after.Failed(true) || after.Sealed != 3 || after.Unsealed != 9 {
		t.Errorf("after: %+v %v", after, err)
	}
}

// Evidence of removed or rewritten events is never resealed.
func TestResealRefusesABrokenChain(t *testing.T) {
	ctx := context.Background()
	for name, q := range map[string]string{
		"rewritten": `UPDATE audit_event SET target = 'other' WHERE seq = 2`,
		"removed":   `DELETE FROM audit_event WHERE seq = (SELECT MAX(seq) FROM audit_event)`,
	} {
		_, s := fourSealed(t)
		if _, err := s.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
		res, err := VerifyWith(ctx, s, required(testKey))
		if err != nil || !res.Failed(true) {
			t.Fatalf("%s: verify %+v %v", name, res, err)
		}
		if ResealAllowed(res) {
			t.Errorf("%s: reseal allowed for %+v", name, res)
		}
		if _, err := Reseal(ctx, s, testKey); !errors.Is(err, ErrResealRefused) {
			t.Errorf("%s: Reseal = %v", name, err)
		}
	}
}

// A log that verifies needs no reseal.
func TestResealRefusesAGoodLog(t *testing.T) {
	ctx := context.Background()
	_, s := fourSealed(t)
	res, err := VerifyWith(ctx, s, required(testKey))
	if err != nil || res.Failed(true) || ResealAllowed(res) {
		t.Fatalf("%+v %v", res, err)
	}
}
