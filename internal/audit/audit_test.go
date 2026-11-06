package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
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
	if err := l.EgressSink().Record(egress.Attempt{Host: "x", Purpose: "p"}); err == nil {
		t.Fatal("expected the sink to report the write error")
	}
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

func TestVerifyDetectsTruncatedTail(t *testing.T) {
	l, s := newLogger(t)
	_, _, e3 := record3(t, l)
	s.DB().Exec(`DELETE FROM audit_event WHERE id=?`, e3.ID)
	res, err := Verify(context.Background(), s)
	if err != nil || res.Reason != "tail truncated" || res.Checked != 2 || res.Expected != 3 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	s.DB().Exec(`DELETE FROM audit_event`)
	res, err = Verify(context.Background(), s)
	if err != nil || res.Reason != "tail truncated" || res.Checked != 0 || res.Expected != 3 {
		t.Fatalf("all deleted: res=%+v err=%v", res, err)
	}
}

func TestTwoStoresRecordConcurrently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "michel.db")
	s1, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	s2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	l1, l2 := NewLogger(s1, time.Now), NewLogger(s2, time.Now)
	errs := make(chan error, 40)
	for i := 0; i < 20; i++ {
		for _, l := range []*Logger{l1, l2} {
			go func(l *Logger) {
				_, err := l.Record(context.Background(), Event{Actor: "t", Action: "x", Target: "y", Result: "ok"})
				errs <- err
			}(l)
		}
	}
	for i := 0; i < 40; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	res, err := Verify(context.Background(), s1)
	if err != nil || res.Broken != nil || res.Reason != "" || res.Checked != 40 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestGatewayRefusesAllowedRequestWhenAuditStoreClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached the server although the audit write failed")
	}))
	t.Cleanup(srv.Close)
	l, s := newLogger(t)
	p := policy.Defaults()
	p.Sovereignty.Network.Allow = []policy.AllowRule{{Host: "127.0.0.1", Purpose: "osv.db"}}
	g := egress.New(p, l.EgressSink())
	s.Close()
	resp, err := g.Client("osv.db").Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected a refusal")
	}
	if !errors.Is(err, egress.ErrEgressDenied) || !strings.Contains(err.Error(), "audit unavailable") {
		t.Fatalf("err = %v", err)
	}
	if len(g.Attempts()) != 1 {
		t.Fatalf("attempts = %+v", g.Attempts())
	}
}

func TestVerifyIgnoresEventsWrittenAfterHeadWasRead(t *testing.T) {
	l, s := newLogger(t)
	record3(t, l)
	n, h, ok := readHead(s.Path()) // verify reads the head first...
	if !ok || n != 3 {
		t.Fatalf("head = %d %s %v", n, h, ok)
	}
	record3(t, l) // ...a concurrent writer appends before the walk
	res, err := verifyAgainst(context.Background(), s.DB(), n, h, ok, VerifyOptions{})
	if err != nil || res.Broken != nil || res.Reason != "" || res.Checked != 6 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestVerifyCleanWhenHeadBehindChain(t *testing.T) {
	// Two processes write the head after their commits: the older count may
	// land last. A head behind the chain is not truncation.
	l, s := newLogger(t)
	e1, _, _ := record3(t, l)
	if err := writeHead(s.Path(), 1, e1.Hash); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(context.Background(), s)
	if err != nil || res.Broken != nil || res.Reason != "" || res.Checked != 3 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestFailedCommitLeavesHeadUntouched(t *testing.T) {
	l, s := newLogger(t)
	record3(t, l)
	before, err := os.ReadFile(HeadFile(s.Path()))
	if err != nil {
		t.Fatal(err)
	}
	l.commit = func(tx *sql.Tx) error { tx.Rollback(); return errors.New("disk full") }
	if _, err := l.Record(context.Background(), Event{Actor: "t", Action: "x", Target: "y", Result: "ok"}); err == nil {
		t.Fatal("expected Record to fail")
	}
	after, _ := os.ReadFile(HeadFile(s.Path()))
	if string(before) != string(after) {
		t.Fatalf("head moved past the chain: %q -> %q", before, after)
	}
	res, err := Verify(context.Background(), s)
	if err != nil || res.Broken != nil || res.Reason != "" || res.Checked != 3 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestVerifyDetectsReplacedEventAtHeadPosition(t *testing.T) {
	l, s := newLogger(t)
	_, _, e3 := record3(t, l)
	n, h, _ := readHead(s.Path())
	// Drop the last event and append a new one: same count, other hash.
	if _, err := s.DB().Exec(`DELETE FROM audit_event WHERE id=?`, e3.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Record(context.Background(), Event{Actor: "t", Action: "x", Target: "y", Result: "ok"}); err != nil {
		t.Fatal(err)
	}
	res, err := verifyAgainst(context.Background(), s.DB(), n, h, true, VerifyOptions{})
	if err != nil || res.Reason != ReasonTailTruncated || res.Expected != 3 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestVerifyReportsMissingHead(t *testing.T) {
	l, s := newLogger(t)
	record3(t, l)
	if err := os.Remove(HeadFile(s.Path())); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(context.Background(), s)
	if err != nil || res.Broken != nil || res.Reason != ReasonHeadAbsent || res.Checked != 3 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestHeadWriteFailureDoesNotFailRecord(t *testing.T) {
	l, s := newLogger(t)
	calls := 0
	rename = func(string, string) error { calls++; return errors.New("sharing violation") }
	t.Cleanup(func() { rename = os.Rename })
	if _, err := l.Record(context.Background(), Event{Actor: "t", Action: "x", Target: "y", Result: "ok"}); err != nil {
		t.Fatalf("Record failed on a head write error: %v", err)
	}
	if calls != renameAttempts {
		t.Fatalf("rename tried %d times, want %d", calls, renameAttempts)
	}
	if _, err := os.Stat(HeadFile(s.Path()) + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp head left behind: %v", err)
	}
}

func TestHeadRenameRetriesTransientFailure(t *testing.T) {
	_, s := newLogger(t)
	calls := 0
	rename = func(a, b string) error {
		calls++
		if calls < 3 {
			return errors.New("sharing violation")
		}
		return os.Rename(a, b)
	}
	t.Cleanup(func() { rename = os.Rename })
	if err := writeHead(s.Path(), 7, "abc"); err != nil {
		t.Fatal(err)
	}
	if n, h, ok := readHead(s.Path()); !ok || n != 7 || h != "abc" {
		t.Fatalf("head = %d %s %v", n, h, ok)
	}
}
