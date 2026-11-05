package audit

import (
	"context"
	"testing"
)

// The head count comes from the anchor kept in the database, incremented in
// the transaction of each event: Record never counts the table. An event
// removed by hand leaves the anchor ahead of the table, which a COUNT(*) would
// have hidden.
func TestRecordDoesNotCountTheTable(t *testing.T) {
	l, s := newLogger(t)
	record3(t, l)
	if _, err := s.DB().Exec(`DELETE FROM audit_event WHERE seq = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Record(context.Background(), Event{Actor: "cli", Action: "a.four", Target: "t4", Result: "ok"}); err != nil {
		t.Fatal(err)
	}
	n, _, ok := readHead(s.Path())
	if !ok || n != 4 {
		t.Errorf("head count = %d (%v), want 4 from the anchor", n, ok)
	}
	var events int
	if err := s.DB().QueryRow(`SELECT events FROM audit_anchor WHERE id = 1`).Scan(&events); err != nil || events != 4 {
		t.Errorf("anchor = %d %v", events, err)
	}
}

// The chain is walked by seq, whatever the physical order of the rows.
func TestEventsOrderBySeq(t *testing.T) {
	l, s := newLogger(t)
	e1, e2, e3 := record3(t, l)
	rows, err := s.DB().Query(`SELECT id, seq FROM audit_event ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	var seqs []int64
	for rows.Next() {
		var id string
		var seq int64
		if err := rows.Scan(&id, &seq); err != nil {
			t.Fatal(err)
		}
		got, seqs = append(got, id), append(seqs, seq)
	}
	rows.Close()
	if len(got) != 3 || got[0] != e1.ID || got[1] != e2.ID || got[2] != e3.ID || seqs[0] != 1 || seqs[2] != 3 {
		t.Fatalf("order = %v %v", got, seqs)
	}
	// The first event is written again at the end of the table, its seq kept.
	for _, q := range []string{
		`CREATE TEMP TABLE keep AS SELECT * FROM audit_event WHERE seq = 1`,
		`DELETE FROM audit_event WHERE seq = 1`,
		`INSERT INTO audit_event SELECT * FROM keep`,
	} {
		if _, err := s.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Verify(context.Background(), s)
	if err != nil || res.Broken != nil || res.Checked != 3 {
		t.Errorf("verify = %+v %v", res, err)
	}
	if res, _ := l.Record(context.Background(), Event{Actor: "cli", Action: "a.four", Result: "ok"}); res.PrevHash != e3.Hash {
		t.Errorf("the new event follows %q, want the last by seq", res.PrevHash)
	}
}
