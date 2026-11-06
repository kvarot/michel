package history

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/store"
)

func TestStatusEvents(t *testing.T) {
	for _, c := range []struct {
		from, to, reason string
		want             string
	}{
		{"", "new", "", "seen"},
		{"new", "gone", "", "gone"},
		{"pending", "gone", "", "gone"},
		{"decided", "gone", "", "gone"},
		{"gone", "gone", "", ""},
		{"gone", "decided", "", "back"},
		{"gone", "pending", "", "back"},
		{"gone", "pending", "severity_changed", "back,reopened"},
		{"decided", "pending", "due_reached", "reopened"},
		{"new", "pending", "", ""},
		{"pending", "decided", "", ""},
		{"decided", "decided", "", ""},
	} {
		if got := strings.Join(StatusEvents(c.from, c.to, c.reason), ","); got != c.want {
			t.Errorf("%q -> %q (%q) = %q, want %q", c.from, c.to, c.reason, got, c.want)
		}
	}
}

func TestAddFindingEventNumbersPerFinding(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	tx, err := st.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	at := time.Date(2026, 11, 6, 10, 0, 0, 0, time.FixedZone("x", 3600))
	for _, e := range []struct{ id, kind string }{{"f1", KindSeen}, {"f1", KindGone}, {"f2", KindSeen}} {
		if err := AddFindingEvent(ctx, tx, e.id, at, e.kind, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := AddFindingEvent(ctx, tx, "f2", at, KindReopened, map[string]any{"reason": "due_reached"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	rows, err := st.DB().Query(`SELECT finding_id, seq, at, kind, detail FROM finding_event ORDER BY finding_id, seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var id, ts, kind, detail string
		var seq int
		if err := rows.Scan(&id, &seq, &ts, &kind, &detail); err != nil {
			t.Fatal(err)
		}
		got = append(got, id+":"+strconv.Itoa(seq)+":"+ts+":"+kind+":"+detail)
	}
	want := "f1:1:2026-11-06T09:00:00Z:seen:{} f1:2:2026-11-06T09:00:00Z:gone:{} " +
		"f2:1:2026-11-06T09:00:00Z:seen:{} f2:2:2026-11-06T09:00:00Z:reopened:{\"reason\":\"due_reached\"}"
	if strings.Join(got, " ") != want {
		t.Errorf("events =\n%v\nwant\n%v", strings.Join(got, " "), want)
	}
}

func TestAddFindingEventRefusesAPath(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	tx, err := st.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, v := range []string{"/home/demo/x", `C:\demo`} {
		if err := AddFindingEvent(ctx, tx, "f1", time.Now(), KindSeen, map[string]any{"where": v}); err == nil {
			t.Errorf("detail %q was written", v)
		}
	}
}

func TestAddAttemptEventNumbersPerAttempt(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	at := time.Date(2026, 11, 6, 9, 30, 15, 0, time.FixedZone("x", 3600))
	tx, err := st.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{"a1", "preparing"}, {"a1", "proposed"}, {"a2", "preparing"}} {
		if err := AddAttemptEvent(ctx, tx, c[0], at, c[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// also works straight on the DB
	if err := AddAttemptEvent(ctx, st.DB(), "a1", at, "approved"); err != nil {
		t.Fatal(err)
	}
	var got []string
	rows, err := st.DB().Query(`SELECT attempt_id, seq, at, state, reconstructed FROM fix_attempt_event ORDER BY attempt_id, seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, atS, state string
		var seq, rec int
		if err := rows.Scan(&id, &seq, &atS, &state, &rec); err != nil {
			t.Fatal(err)
		}
		got = append(got, id+" "+strconv.Itoa(seq)+" "+atS+" "+state+" "+strconv.Itoa(rec))
	}
	want := "a1 1 2026-11-06T08:30:15Z preparing 0|a1 2 2026-11-06T08:30:15Z proposed 0|a1 3 2026-11-06T08:30:15Z approved 0|a2 1 2026-11-06T08:30:15Z preparing 0"
	if strings.Join(got, "|") != want {
		t.Errorf("rows = %v", got)
	}
}
