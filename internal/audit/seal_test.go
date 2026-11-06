package audit

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/store"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func required(key []byte) VerifyOptions { return VerifyOptions{Key: key, Required: true} }

// protect starts the protection with testKey as Michel does when it makes the
// key: the sealed anchor marks where the seals begin, then l seals.
func protect(t *testing.T, l *Logger, s *store.Store) {
	t.Helper()
	tx, err := s.DB().BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := startSealing(context.Background(), tx, testKey); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	l.SetKey(testKey)
}

// tamper runs SQL on the database as someone who can write michel.db and
// audit.head but has no key: the head file is rewritten to match the chain.
func tamper(t *testing.T, s *store.Store, stmts ...string) {
	t.Helper()
	for _, q := range stmts {
		if _, err := s.DB().Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	var n int
	var h string
	err := s.DB().QueryRow(`SELECT seq, hash FROM audit_event ORDER BY seq DESC LIMIT 1`).Scan(&n, &h)
	if err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`UPDATE audit_anchor SET events = ? WHERE id = 1`, n); err != nil {
		t.Fatal(err)
	}
	if err := writeHead(s.Path(), n, h); err != nil {
		t.Fatal(err)
	}
}

// fourSealed is three events before the protection, then three sealed ones.
func fourSealed(t *testing.T) (*Logger, *store.Store) {
	t.Helper()
	l, s := newLogger(t)
	record3(t, l)
	protect(t, l, s)
	record3(t, l)
	if res, err := VerifyWith(context.Background(), s, required(testKey)); err != nil || res.Failed(true) || res.Sealed != 3 || res.Unsealed != 3 {
		t.Fatalf("before tampering: %+v %v", res, err)
	}
	return l, s
}

func mustFail(t *testing.T, s *store.Store, what string) {
	t.Helper()
	res, err := VerifyWith(context.Background(), s, required(testKey))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Failed(true) {
		t.Errorf("%s: verify passes: %+v", what, res)
	}
}

func TestDroppedSealedEventsFail(t *testing.T) {
	_, s := fourSealed(t)
	tamper(t, s, `DELETE FROM audit_event WHERE seq >= 4`)
	mustFail(t, s, "sealed events dropped")
}

func TestChainRewrittenUnsealedFails(t *testing.T) {
	_, s := fourSealed(t)
	tamper(t, s, `UPDATE audit_event SET hmac = ''`)
	mustFail(t, s, "seals stripped")
}

func TestSealedAnchorRemovedFails(t *testing.T) {
	for name, q := range map[string]string{
		"blanked": `UPDATE audit_anchor SET sealed_from = 0, sealed_seq = 0, sealed_head = '', sealed_mac = ''`,
		"moved":   `UPDATE audit_anchor SET sealed_from = 7`,
		"deleted": `DELETE FROM audit_anchor`,
	} {
		_, s := fourSealed(t)
		tamper(t, s, `UPDATE audit_event SET hmac = ''`)
		if _, err := s.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
		mustFail(t, s, "anchor "+name)
	}
}

func TestTruncatedLastEventFails(t *testing.T) {
	_, s := fourSealed(t)
	tamper(t, s, `DELETE FROM audit_event WHERE seq = 6`)
	mustFail(t, s, "last event removed")
}

// Michel keeps writing after the tampering: its next events do not hide it.
func TestNextEventsDoNotHideTampering(t *testing.T) {
	for name, q := range map[string][]string{
		"truncated": {`DELETE FROM audit_event WHERE seq = 6`},
		"blanked": {`UPDATE audit_event SET hmac = ''`,
			`UPDATE audit_anchor SET sealed_from = 0, sealed_seq = 0, sealed_head = '', sealed_mac = ''`},
	} {
		l, s := fourSealed(t)
		tamper(t, s, q...)
		record3(t, l)
		mustFail(t, s, name+", then three events")
	}
}

// The protection began, the key cannot be read: the seals cannot be checked,
// even once every seal is gone.
func TestSealedAnchorWithoutTheKeyFails(t *testing.T) {
	_, s := fourSealed(t)
	tamper(t, s, `UPDATE audit_event SET hmac = ''`)
	res, err := VerifyWith(context.Background(), s, required(nil))
	if err != nil || !res.Failed(true) || res.Reason != ReasonSealKeyMissing {
		t.Errorf("verify without the key = %+v %v", res, err)
	}
}

// integrity_protection: none keeps the old answer: no seal, no sealed anchor.
func TestNoneIgnoresTheSealedAnchor(t *testing.T) {
	_, s := fourSealed(t)
	tamper(t, s, `UPDATE audit_event SET hmac = ''`)
	if res, err := VerifyWith(context.Background(), s, VerifyOptions{}); err != nil || res.Failed(false) {
		t.Errorf("none = %+v %v", res, err)
	}
}

func TestSealedEventsVerify(t *testing.T) {
	l, s := newLogger(t)
	protect(t, l, s)
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
	protect(t, l, s)
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
	protect(t, l, s)
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
	protect(t, l, s)
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
	protect(t, l, s)
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
	l, db := newLogger(t)
	record3(t, l) // events of before the protection
	st, err := secret.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, ok, err := LoadKey(st); ok || err != nil {
		t.Fatalf("a key before any was made: %v %v", ok, err)
	}
	k1, err := LoadOrCreateKey(ctx, st, db)
	if err != nil || len(k1) != 32 {
		t.Fatalf("key = %d bytes, %v", len(k1), err)
	}
	k2, err := LoadOrCreateKey(ctx, st, db)
	if err != nil || string(k1) != string(k2) {
		t.Errorf("the key changed: %v", err)
	}
	if k3, ok, err := LoadKey(st); !ok || err != nil || string(k3) != string(k1) {
		t.Errorf("LoadKey = %v %v", ok, err)
	}
	// Making the key started the protection: the old events stay before it.
	l.SetKey(k1)
	record3(t, l)
	res, err := VerifyWith(ctx, db, required(k1))
	if err != nil || res.Failed(true) || res.Unsealed != 3 || res.Sealed != 3 {
		t.Errorf("verify = %+v %v", res, err)
	}
}

// Several processes start on a fresh data folder at once: they all end with
// the one key that is stored, so no event is sealed with a lost key.
func TestLoadOrCreateKeyConcurrent(t *testing.T) {
	for round := 0; round < 5; round++ {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "michel.db")
		first, err := store.Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		const n = 8
		keys := make([][]byte, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				sec, err := secret.Open(dir)
				if err != nil {
					errs[i] = err
					return
				}
				db, err := store.Open(dbPath)
				if err != nil {
					errs[i] = err
					return
				}
				defer db.Close()
				<-start
				keys[i], errs[i] = LoadOrCreateKey(context.Background(), sec, db)
				if errs[i] == nil {
					l := NewLogger(db, time.Now)
					l.SetKey(keys[i])
					_, errs[i] = l.Record(context.Background(), Event{Actor: "cli", Action: "app.start", Result: "ok"})
				}
			}(i)
		}
		close(start)
		wg.Wait()
		sec, err := secret.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		stored, ok, err := LoadKey(sec)
		if !ok || err != nil {
			t.Fatalf("round %d: stored key = %v %v", round, ok, err)
		}
		for i := range keys {
			if errs[i] != nil {
				t.Fatalf("round %d, process %d: %v", round, i, errs[i])
			}
			if string(keys[i]) != string(stored) {
				t.Fatalf("round %d, process %d uses a key that is not the stored one", round, i)
			}
		}
		res, err := VerifyWith(context.Background(), first, required(stored))
		if err != nil || res.Failed(true) || res.Sealed != n {
			t.Errorf("round %d: verify = %+v %v", round, res, err)
		}
		first.Close()
	}
}
