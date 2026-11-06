package history

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// addAttempt stores a fix attempt of finding findingID with its states,
// written the way the fix package writes them.
func addAttempt(t *testing.T, db *sql.DB, id, findingID string, states map[time.Time]string, order []time.Time) {
	t.Helper()
	mustExec(t, db, `INSERT INTO fix_attempt (id, finding_id, project_id, origin, state, created_at, updated_at)
		VALUES (?, ?, 'p1', 'web', 'preparing', ?, ?)`, id, findingID, rfc(order[0]), rfc(order[len(order)-1]))
	for _, at := range order {
		if err := AddAttemptEvent(context.Background(), db, id, at, states[at]); err != nil {
			t.Fatal(err)
		}
	}
}

func addScan(t *testing.T, db *sql.DB, id, project, status string, started time.Time) {
	t.Helper()
	mustExec(t, db, `INSERT INTO scan (id, project_id, started_at, status) VALUES (?, ?, ?, ?)`, id, project, rfc(started), status)
}

func addInventory(t *testing.T, db *sql.DB, target string, at time.Time) {
	t.Helper()
	mustExec(t, db, `INSERT INTO target_inventory (target_id, at, body) VALUES (?, ?, '{}')`, target, rfc(at))
}

func paris(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// seedWeek fills the week of Monday 2026-10-05 to Sunday 2026-10-11 in
// Paris, with activity before and after it.
func seedWeek(t *testing.T, db *sql.DB, loc *time.Location) {
	day := func(d, h int) time.Time { return time.Date(2026, 10, d, h, 0, 0, 0, loc) }
	before := time.Date(2026, 9, 20, 10, 0, 0, 0, loc)
	// f0 was open before the week; it is ignored on Wednesday.
	addFinding(t, db, "f0", "p1", "dependency", "medium", before)
	addEvent(t, db, "f0", before, KindSeen, nil)
	addDecision(t, db, "d0", "f0", "ignore", day(7, 10), time.Time{}, time.Time{}, "")
	// a decision before the week does not count.
	addDecision(t, db, "dold", "f0", "defer", before, time.Time{}, day(7, 10), "superseded")
	// f1 is seen Tuesday, fixed by Michel, gone Friday.
	addFinding(t, db, "f1", "p1", "dependency", "high", day(6, 9))
	addEvent(t, db, "f1", day(6, 9), KindSeen, nil)
	order := []time.Time{day(7, 9), day(7, 11), day(8, 9), day(9, 9)}
	addAttempt(t, db, "a1", "f1", map[time.Time]string{order[0]: "preparing", order[1]: "proposed", order[2]: "applied", order[3]: "proven_fixed"}, order)
	addEvent(t, db, "f1", day(9, 10), KindGone, nil)
	// f2 is seen Wednesday, gone Saturday without Michel.
	addFinding(t, db, "f2", "p1", "dependency", "critical", day(7, 9))
	addEvent(t, db, "f2", day(7, 9), KindSeen, nil)
	addEvent(t, db, "f2", day(10, 9), KindGone, nil)
	// f3 is seen Thursday at midnight and decided fix: it stays open.
	addFinding(t, db, "f3", "p1", "dependency", "low", day(8, 0))
	addEvent(t, db, "f3", day(8, 0), KindSeen, nil)
	addDecision(t, db, "d3", "f3", "fix", day(8, 12), time.Time{}, time.Time{}, "")
	// f4 is seen the next Monday at midnight: after the week.
	addFinding(t, db, "f4", "p1", "dependency", "high", day(12, 0))
	addEvent(t, db, "f4", day(12, 0), KindSeen, nil)
	// a server finding, seen and gone in the week: counted apart.
	addFinding(t, db, "fs", "t1", "server_package", "critical", day(6, 9))
	addEvent(t, db, "fs", day(6, 9), KindSeen, nil)
	addEvent(t, db, "fs", day(9, 9), KindGone, nil)
	// a finding of the removed project: left out.
	addFinding(t, db, "fr", "p2", "dependency", "critical", day(6, 9))
	addEvent(t, db, "fr", day(6, 9), KindSeen, nil)
	// checks.
	addScan(t, db, "s1", "p1", "ok", day(5, 3))
	addScan(t, db, "s2", "p1", "failed", day(6, 3))
	addScan(t, db, "s3", "p1", "partial", day(11, 23))
	addScan(t, db, "s4", "p1", "running", day(11, 23))
	addScan(t, db, "s5", "p1", "ok", day(12, 0))
	addScan(t, db, "s6", "p2", "ok", day(6, 3))
	addInventory(t, db, "t1", day(6, 9))
	addInventory(t, db, "t1", day(4, 23))
}

func TestReportCountsPeriod(t *testing.T) {
	loc := paris(t)
	db := testDB(t)
	seedWeek(t, db, loc)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, loc)
	r, err := BuildReport(context.Background(), db, "2026-10-05", "2026-10-11", loc, now, sev)
	if err != nil {
		t.Fatal(err)
	}
	if r.From != "2026-10-05" || r.To != "2026-10-11" {
		t.Errorf("period = %s..%s", r.From, r.To)
	}
	eq := func(name string, got map[string]int, want map[string]int) {
		t.Helper()
		total := 0
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s = %v, want %v", name, got, want)
				return
			}
			total += v
		}
		n := 0
		for _, v := range got {
			n += v
		}
		if n != total {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	eq("found", r.Found, map[string]int{"high": 1, "critical": 1, "low": 1})
	eq("gone_by_michel", r.GoneByMichel, map[string]int{"high": 1})
	eq("gone_elsewhere", r.GoneElsewhere, map[string]int{"critical": 1})
	eq("decisions", r.Decisions, map[string]int{"ignore": 1, "fix": 1})
	if r.Fixes != (FixCounts{Proposed: 1, Applied: 1, Proven: 1}) {
		t.Errorf("fixes = %+v", r.Fixes)
	}
	eq("open_start", r.OpenStart, map[string]int{"medium": 1})
	eq("open_end", r.OpenEnd, map[string]int{"low": 1})
	if r.OldestOpen == nil || r.OldestOpen.FindingID != "f3" || r.OldestOpen.Package != "pkg" || r.OldestOpen.OSVID != "OSV-f3" ||
		r.OldestOpen.FirstSeenAt != rfc(time.Date(2026, 10, 8, 0, 0, 0, 0, loc)) {
		t.Errorf("oldest_open = %+v", r.OldestOpen)
	}
	if r.Checks.Projects != (CheckCount{Done: 2, Failed: 1}) {
		t.Errorf("project checks = %+v", r.Checks.Projects)
	}
	if r.Checks.Servers.Done != 1 || r.Checks.Servers.Failed != nil {
		t.Errorf("server checks = %+v", r.Checks.Servers)
	}
	if r.Servers != (ServerCounts{Found: 1, Closed: 1}) {
		t.Errorf("servers = %+v", r.Servers)
	}
	if len(r.Projects) != 1 || r.Projects[0] != (ProjectLine{Name: "demo", Found: 3, Gone: 2, OpenEnd: 1, Decisions: 2}) {
		t.Errorf("projects = %+v", r.Projects)
	}
	if !r.Reconstructed {
		t.Error("a period before history_start is not flagged reconstructed")
	}
}

func TestReportEmptyPeriodIsZeros(t *testing.T) {
	loc := paris(t)
	db := testDB(t)
	mustExec(t, db, `UPDATE history_start SET at = '2026-01-01T00:00:00Z' WHERE id = 1`)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, loc)
	r, err := BuildReport(context.Background(), db, "2026-10-05", "2026-10-11", loc, now, sev)
	if err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]map[string]int{"found": r.Found, "gone_by_michel": r.GoneByMichel, "gone_elsewhere": r.GoneElsewhere,
		"decisions": r.Decisions, "open_start": r.OpenStart, "open_end": r.OpenEnd} {
		if m == nil {
			t.Errorf("%s is nil", name)
		}
		for k, v := range m {
			if v != 0 {
				t.Errorf("%s[%s] = %d", name, k, v)
			}
		}
	}
	if r.Fixes != (FixCounts{}) || r.Checks.Projects != (CheckCount{}) || r.Checks.Servers.Done != 0 || r.Servers != (ServerCounts{}) {
		t.Errorf("report = %+v", r)
	}
	if r.OldestOpen != nil {
		t.Errorf("oldest_open = %+v", r.OldestOpen)
	}
	if len(r.Projects) != 1 || r.Projects[0] != (ProjectLine{Name: "demo"}) {
		t.Errorf("projects = %+v", r.Projects)
	}
	if r.Reconstructed {
		t.Error("a period after history_start is flagged reconstructed")
	}
}

func TestReportOpenStartEndMatchOpenAt(t *testing.T) {
	loc := paris(t)
	db := testDB(t)
	seedWeek(t, db, loc)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, loc)
	tracked, err := LoadTracked(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range [][2]string{{"2026-10-05", "2026-10-11"}, {"2026-10-08", "2026-10-08"}, {"2026-09-01", "2026-10-20"}, {"2026-10-12", "2026-10-12"}} {
		r, err := BuildReport(context.Background(), db, p[0], p[1], loc, now, sev)
		if err != nil {
			t.Fatal(err)
		}
		from, _ := time.ParseInLocation("2006-01-02", p[0], loc)
		to, _ := time.ParseInLocation("2006-01-02", p[1], loc)
		start := from
		end := time.Date(to.Year(), to.Month(), to.Day()+1, 0, 0, 0, 0, loc)
		want := func(at time.Time) map[string]int {
			m := map[string]int{}
			for _, x := range tracked {
				if OpenAt(x.Events, x.Ignores, at) {
					m[sev(x.Row)]++
				}
			}
			return m
		}
		for name, c := range map[string][2]map[string]int{
			"open_start": {r.OpenStart, want(start.Add(-time.Nanosecond))},
			"open_end":   {r.OpenEnd, want(end.Add(-time.Nanosecond))}} {
			for k, v := range c[1] {
				if c[0][k] != v {
					t.Errorf("%v %s = %v, want %v", p, name, c[0], c[1])
				}
			}
			for k, v := range c[0] {
				if c[1][k] != v {
					t.Errorf("%v %s = %v, want %v", p, name, c[0], c[1])
				}
			}
		}
	}
}

func TestParsePeriod(t *testing.T) {
	loc := paris(t)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, loc)
	start, end, err := ParsePeriod("2026-10-24", "2026-10-25", loc, now)
	if err == nil {
		t.Errorf("a period after today is accepted: %v %v", start, end)
	}
	// the DST change of 2026-10-25 makes the day 25 hours long.
	start, end, err = ParsePeriod("2026-10-20", "2026-10-25", loc, now)
	if err != nil || !start.Equal(time.Date(2026, 10, 20, 0, 0, 0, 0, loc)) || !end.Equal(time.Date(2026, 10, 26, 0, 0, 0, 0, loc)) ||
		end.Sub(start) != 6*24*time.Hour+time.Hour {
		t.Errorf("period = %v..%v %v", start, end, err)
	}
	for _, bad := range [][2]string{{"", "2026-10-01"}, {"2026-10-01", ""}, {"2026-1-01", "2026-10-02"}, {"2026-02-30", "2026-03-01"},
		{"2026-10-02", "2026-10-01"}, {"2026-08-01", "2026-10-02"}, {"abc", "2026-10-01"}} {
		if _, _, err := ParsePeriod(bad[0], bad[1], loc, now); err == nil {
			t.Errorf("%v is accepted", bad)
		}
	}
	if _, _, err := ParsePeriod("2026-08-01", "2026-10-01", loc, now); err != nil {
		t.Errorf("62 days are refused: %v", err)
	}
}
