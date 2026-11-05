package audit

import (
	"context"
	"os"
	"testing"

	"github.com/kvarot/michel/internal/secret"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func required(key []byte) VerifyOptions { return VerifyOptions{Key: key, Required: true} }

func TestSealedEventsVerify(t *testing.T) {
	l, s := newLogger(t)
	l.SetKey(testKey)
	e1, _, _ := record3(t, l)
	if e1.HMAC == "" {
		t.Fatal("the event carries no seal")
	}
	res, err := VerifyWith(context.Background(), s, required(testKey))
	if err != nil || res.Broken != nil || res.Checked != 3 || res.Sealed != 3 || res.Unsealed != 0 {
		t.Errorf("verify = %+v %v", res, err)
	}
}

// Rewriting an event and its whole chain is caught by the seal, which only the
// key can make.
func TestWrongSealIsBroken(t *testing.T) {
	l, s := newLogger(t)
	l.SetKey(testKey)
	record3(t, l)
	res, err := VerifyWith(context.Background(), s, required([]byte("another key, of the same size..")))
	if err != nil || res.Broken == nil || res.Reason != ReasonSealMismatch {
		t.Errorf("verify with another key = %+v %v", res, err)
	}
	if _, err := s.DB().Exec(`UPDATE audit_event SET hmac = 'ab' WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	res, _ = VerifyWith(context.Background(), s, required(testKey))
	if res.Broken == nil || res.Broken.Seq != 2 || res.Reason != ReasonSealMismatch {
		t.Errorf("verify of a changed seal = %+v", res)
	}
}

func TestStrippedSealIsBroken(t *testing.T) {
	l, s := newLogger(t)
	l.SetKey(testKey)
	record3(t, l)
	if _, err := s.DB().Exec(`UPDATE audit_event SET hmac = '' WHERE seq = 3`); err != nil {
		t.Fatal(err)
	}
	res, _ := VerifyWith(context.Background(), s, required(testKey))
	if res.Broken == nil || res.Broken.Seq != 3 || res.Reason != ReasonSealMissing {
		t.Errorf("verify = %+v", res)
	}
	res, _ = VerifyWith(context.Background(), s, required(nil))
	if res.Broken == nil || res.Reason != ReasonSealKeyMissing {
		t.Errorf("verify without the key = %+v", res)
	}
}

// The events written before the protection have no seal: they are counted,
// not broken.
func TestOldEventsAreBeforeTheProtection(t *testing.T) {
	l, s := newLogger(t)
	record3(t, l)
	l.SetKey(testKey)
	if _, err := l.Record(context.Background(), Event{Actor: "cli", Action: "a.four", Result: "ok"}); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyWith(context.Background(), s, required(testKey))
	if err != nil || res.Broken != nil || res.Unsealed != 3 || res.Sealed != 1 {
		t.Errorf("verify = %+v %v", res, err)
	}
	// With integrity_protection: none, the seals are not looked at.
	if _, err := s.DB().Exec(`UPDATE audit_event SET hmac = 'ab' WHERE seq = 4`); err != nil {
		t.Fatal(err)
	}
	if res, _ := VerifyWith(context.Background(), s, VerifyOptions{}); res.Broken != nil {
		t.Errorf("none checks the seals: %+v", res)
	}
}

func TestAbsentAnchorFailsWhenRequired(t *testing.T) {
	l, s := newLogger(t)
	l.SetKey(testKey)
	record3(t, l)
	if err := os.Remove(HeadFile(s.Path())); err != nil {
		t.Fatal(err)
	}
	res, _ := VerifyWith(context.Background(), s, required(testKey))
	if res.Reason != ReasonHeadAbsent || !res.Failed(true) {
		t.Errorf("required = %+v", res)
	}
	if res.Failed(false) {
		t.Errorf("none fails on an absent anchor")
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	st, err := secret.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := LoadKey(st); ok || err != nil {
		t.Fatalf("a key before any was made: %v %v", ok, err)
	}
	k1, err := LoadOrCreateKey(st)
	if err != nil || len(k1) != 32 {
		t.Fatalf("key = %d bytes, %v", len(k1), err)
	}
	k2, err := LoadOrCreateKey(st)
	if err != nil || string(k1) != string(k2) {
		t.Errorf("the key changed: %v", err)
	}
	if k3, ok, err := LoadKey(st); !ok || err != nil || string(k3) != string(k1) {
		t.Errorf("LoadKey = %v %v", ok, err)
	}
}
