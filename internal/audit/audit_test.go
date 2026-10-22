package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/store"
)

func newLogger(t *testing.T) (*Logger, *store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	base := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	n := 0
	now := func() time.Time { n++; return base.Add(time.Duration(n) * time.Second) }
	return NewLogger(s, now), s
}

func record3(t *testing.T, l *Logger) (e1, e2, e3 Event) {
	t.Helper()
	ctx := context.Background()
	var err error
	e1, err = l.Record(ctx, Event{Actor: "cli", Action: "a.one", Target: "t1", Result: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	e2, err = l.Record(ctx, Event{Actor: "cli", Action: "a.two", Target: "t2", Result: "denied", Evidence: map[string]any{"k": "v"}})
	if err != nil {
		t.Fatal(err)
	}
	e3, err = l.Record(ctx, Event{Actor: "cli", Action: "a.three", Target: "t3", Result: "ok", CorrelationID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestRecordChainsHashes(t *testing.T) {
	l, _ := newLogger(t)
	e1, e2, e3 := record3(t, l)
	if e1.PrevHash != "" || e2.PrevHash != e1.Hash || e3.PrevHash != e2.Hash {
		t.Fatalf("chain broken: %+v %+v %+v", e1, e2, e3)
	}
	if !(e1.ID < e2.ID && e2.ID < e3.ID) {
		t.Errorf("ids not sorted by insertion: %s %s %s", e1.ID, e2.ID, e3.ID)
	}
	canon, _ := json.Marshal(map[string]any{
		"id": e2.ID, "ts": e2.TS, "actor": e2.Actor, "action": e2.Action, "target": e2.Target,
		"result": e2.Result, "correlation_id": e2.CorrelationID, "evidence": map[string]any{"k": "v"},
	})
	sum := sha256.Sum256([]byte(e1.Hash + "\n" + string(canon)))
	if want := hex.EncodeToString(sum[:]); e2.Hash != want {
		t.Errorf("hash = %s, want %s", e2.Hash, want)
	}
	if !strings.HasSuffix(e1.TS, "Z") {
		t.Errorf("ts %q is not UTC", e1.TS)
	}
}

func TestVerifyCleanChain(t *testing.T) {
	l, s := newLogger(t)
	record3(t, l)
	res, err := Verify(context.Background(), s)
	if err != nil || res.Broken != nil || res.Checked != 3 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestVerifyEmptyChain(t *testing.T) {
	_, s := newLogger(t)
	res, err := Verify(context.Background(), s)
	if err != nil || res.Broken != nil || res.Checked != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestVerifyDetectsTamperedEvent(t *testing.T) {
	l, s := newLogger(t)
	_, e2, _ := record3(t, l)
	if _, err := s.DB().Exec(`UPDATE audit_event SET result='allowed' WHERE id=?`, e2.ID); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(context.Background(), s)
	if err != nil || res.Broken == nil || res.Broken.ID != e2.ID || res.Reason != "hash mismatch" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestVerifyDetectsDeletedEvent(t *testing.T) {
	l, s := newLogger(t)
	_, e2, e3 := record3(t, l)
	if _, err := s.DB().Exec(`DELETE FROM audit_event WHERE id=?`, e2.ID); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(context.Background(), s)
	if err != nil || res.Broken == nil || res.Broken.ID != e3.ID || res.Reason != "prev_hash mismatch" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestEgressSinkRecordsDeniedWithoutSecrets(t *testing.T) {
	l, s := newLogger(t)
	l.EgressSink().Record(egress.Attempt{Host: "evil.example", Purpose: "osv", Allowed: false, At: time.Now(), Reason: "host not in allowlist"})
	l.EgressSink().Record(egress.Attempt{Host: "ok.example", Purpose: "osv", Allowed: true})
	rows, err := s.DB().Query(`SELECT action, target, result, evidence FROM audit_event ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got [][4]string
	for rows.Next() {
		var r [4]string
		if err := rows.Scan(&r[0], &r[1], &r[2], &r[3]); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	if len(got) != 2 {
		t.Fatalf("rows = %v", got)
	}
	if got[0][0] != "egress.attempt" || got[0][1] != "evil.example" || got[0][2] != "denied" {
		t.Errorf("row0 = %v", got[0])
	}
	if got[1][2] != "allowed" {
		t.Errorf("row1 = %v", got[1])
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(got[0][3]), &ev); err != nil || ev["purpose"] != "osv" || ev["reason"] != "host not in allowlist" || len(ev) != 2 {
		t.Errorf("evidence = %v err %v", got[0][3], err)
	}
}

func TestEgressSinkDoesNotPanicOnClosedStore(t *testing.T) {
	l, s := newLogger(t)
	s.Close()
	l.EgressSink().Record(egress.Attempt{Host: "x", Purpose: "p"})
}

func TestConcurrentRecordKeepsChainValid(t *testing.T) {
	l, s := newLogger(t)
	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			l.EgressSink().Record(egress.Attempt{Host: "h", Purpose: "p"})
			done <- struct{}{}
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
	res, err := Verify(context.Background(), s)
	if err != nil || res.Broken != nil || res.Checked != 20 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}
