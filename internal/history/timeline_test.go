package history

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTimelineMergesSources(t *testing.T) {
	db := testDB(t)
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	at := func(h int) time.Time { return base.Add(time.Duration(h) * time.Hour) }
	addFinding(t, db, "f1", "p1", "dependency", "high", base)
	addFinding(t, db, "f2", "p1", "dependency", "high", base)
	// a reconstructed seen, as the migration writes it, then live events.
	mustExec(t, db, `INSERT INTO finding_event (finding_id, seq, at, kind, detail) VALUES ('f1', 1, ?, 'seen', '{"reconstructed":true}')`, rfc(at(0)))
	addEvent(t, db, "f1", at(10), KindGone, nil)
	addEvent(t, db, "f1", at(10), KindBack, nil) // same second: kept in order
	addEvent(t, db, "f1", at(20), KindReopened, map[string]any{"reason": "due_reached"})
	addEvent(t, db, "f2", at(3), KindSeen, nil) // another finding: not shown
	addDecision(t, db, "d1", "f1", "defer", at(1), at(500), at(20), "due_reached")
	addDecision(t, db, "d2", "f1", "fix", at(21), time.Time{}, time.Time{}, "")
	mustExec(t, db, `INSERT INTO fix_attempt (id, finding_id, project_id, origin, state, created_at, updated_at)
		VALUES ('a1', 'f1', 'p1', 'web', 'applied', ?, ?)`, rfc(at(2)), rfc(at(6)))
	for i, s := range []struct {
		h     int
		state string
		rec   int
	}{{2, "preparing", 1}, {3, "running", 0}, {4, "proposed", 0}, {5, "approved", 0}, {6, "applied", 0}} {
		mustExec(t, db, `INSERT INTO fix_attempt_event (attempt_id, seq, at, state, reconstructed) VALUES ('a1', ?, ?, ?, ?)`,
			i+1, rfc(at(s.h)), s.state, s.rec)
	}
	// a second attempt still running: its last state shows.
	mustExec(t, db, `INSERT INTO fix_attempt (id, finding_id, project_id, origin, state, created_at, updated_at)
		VALUES ('a2', 'f1', 'p1', 'web', 'running', ?, ?)`, rfc(at(22)), rfc(at(23)))
	mustExec(t, db, `INSERT INTO fix_attempt_event (attempt_id, seq, at, state) VALUES ('a2', 1, ?, 'preparing'), ('a2', 2, ?, 'running')`,
		rfc(at(22)), rfc(at(23)))

	entries, err := Timeline(context.Background(), db, "f1")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		s := fmt.Sprintf("%d:%s", int(e.At.Sub(base).Hours()), e.Kind)
		switch e.Kind {
		case "attempt":
			s += ":" + e.Detail["attempt_id"].(string) + ":" + e.Detail["state"].(string)
		case "decision":
			s += ":" + e.Detail["action"].(string)
			if r, ok := e.Detail["reason"]; ok {
				s += ":" + r.(string) + ":" + e.Detail["superseded_at"].(string) + ":" + e.Detail["due"].(string)
			}
		case KindReopened:
			s += ":" + e.Detail["reason"].(string)
		}
		if e.Reconstructed {
			s += ":R"
		}
		got = append(got, s)
	}
	want := []string{
		"23:attempt:a2:running",
		"22:attempt:a2:preparing",
		"21:decision:fix",
		"20:reopened:due_reached",
		"10:back",
		"10:gone",
		"6:attempt:a1:applied",
		"5:attempt:a1:approved",
		"4:attempt:a1:proposed",
		"2:attempt:a1:preparing:R",
		"1:decision:defer:due_reached:" + rfc(at(20)) + ":" + rfc(at(500)),
		"0:seen:R",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("timeline =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, e := range entries {
		if _, ok := e.Detail["reconstructed"]; ok {
			t.Errorf("%s keeps reconstructed in its detail", e.Kind)
		}
		if e.Kind == "decision" && e.Detail["author"] != "web" {
			t.Errorf("decision author = %v", e.Detail["author"])
		}
	}
	if empty, err := Timeline(context.Background(), db, "nope"); err != nil || len(empty) != 0 {
		t.Errorf("unknown finding = %v %v", empty, err)
	}
}
