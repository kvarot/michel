package history

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/store"
)

// testDB is a migrated store with the active project demo (id p1), the
// removed project old (id p2) and a server target (id t1).
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	db := st.DB()
	mustExec(t, db, `INSERT INTO project (id, name, source_type, path, classification, active, created_at)
		VALUES ('p1', 'demo', 'local_path', 'x', 'normal', 1, '2026-01-01T00:00:00Z'),
		       ('p2', 'old', 'local_path', 'y', 'normal', 0, '2026-01-01T00:00:00Z')`)
	mustExec(t, db, `INSERT INTO target (id, name, host, kind, env, classification, active, created_at)
		VALUES ('t1', 'web1', 'web1.example', 'vps', 'prod', 'normal', 1, '2026-01-01T00:00:00Z')`)
	return db
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// addFinding stores a finding of project (or server) owner with kind and
// severity.
func addFinding(t *testing.T, db *sql.DB, id, owner, kind, severity string, first time.Time) {
	t.Helper()
	mustExec(t, db, `INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, severity_label,
		installed_version, status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, kind)
		VALUES (?, ?, 'composer.lock', 'npm', 'pkg', ?, ?, '1.0.0', 'new', 's1', 's1', ?, ?, ?)`,
		id, owner, "OSV-"+id, severity, rfc(first), rfc(first), kind)
}

// addEvent writes one finding event the way the writers do.
func addEvent(t *testing.T, db *sql.DB, id string, at time.Time, kind string, detail map[string]any) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := AddFindingEvent(context.Background(), tx, id, at, kind, detail); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// addDecision stores a decision; superseded zero means in force.
func addDecision(t *testing.T, db *sql.DB, id, findingID, action string, created, due, superseded time.Time, reason string) {
	t.Helper()
	str := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return rfc(t)
	}
	mustExec(t, db, `INSERT INTO decision (id, finding_id, project_id, action, justification, due_at, author, created_at, superseded_at, superseded_reason)
		VALUES (?, ?, 'p1', ?, 'because', ?, 'web', ?, ?, ?)`,
		id, findingID, action, str(due), rfc(created), str(superseded), reason)
}

func sev(r FindingRow) string { return r.SeverityLabel }

func TestOpenAtReplaysSameDayChanges(t *testing.T) {
	paris, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Fatal(err)
	}
	db := testDB(t)
	d1 := time.Date(2026, 10, 10, 9, 0, 0, 0, paris)
	addFinding(t, db, "f1", "p1", "dependency", "high", d1)
	// seen, gone and back the same day: open at the end of it.
	addEvent(t, db, "f1", d1, KindSeen, nil)
	addEvent(t, db, "f1", d1.Add(2*time.Hour), KindGone, nil)
	addEvent(t, db, "f1", d1.Add(5*time.Hour), KindBack, nil)
	// gone the next day at 23:30 local, back the day after at 00:10.
	addEvent(t, db, "f1", time.Date(2026, 10, 11, 23, 30, 0, 0, paris), KindGone, nil)
	addEvent(t, db, "f1", time.Date(2026, 10, 12, 0, 10, 0, 0, paris), KindBack, nil)
	// a second finding seen and gone the same day: closed at its end.
	addFinding(t, db, "f2", "p1", "dependency", "low", d1)
	addEvent(t, db, "f2", d1, KindSeen, nil)
	addEvent(t, db, "f2", d1.Add(time.Hour), KindGone, nil)

	now := time.Date(2026, 10, 12, 12, 0, 0, 0, paris)
	days, _, err := OpenByDay(context.Background(), db, now, paris, 4, sev)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range days {
		got = append(got, fmt.Sprintf("%s:%d:%d", d.Date, d.Open["high"], d.Open["low"]))
	}
	want := "2026-10-09:0:0 2026-10-10:1:0 2026-10-11:0:0 2026-10-12:1:0"
	if strings.Join(got, " ") != want {
		t.Errorf("days = %v, want %s", got, want)
	}

	tr, err := LoadTracked(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	var f1 Tracked
	for _, x := range tr {
		if x.Row.ID == "f1" {
			f1 = x
		}
	}
	for _, c := range []struct {
		at   time.Time
		want bool
	}{
		{d1.Add(-time.Second), false}, // not seen yet
		{d1, true},
		{d1.Add(3 * time.Hour), false}, // gone
		{d1.Add(5 * time.Hour), true},  // back
		{time.Date(2026, 10, 12, 0, 0, 0, 0, paris), false},
	} {
		if got := OpenAt(f1.Events, f1.Ignores, c.at); got != c.want {
			t.Errorf("OpenAt(%v) = %v, want %v", c.at, got, c.want)
		}
	}
}

func TestOpenAtFollowsIgnoreDecisions(t *testing.T) {
	db := testDB(t)
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	addFinding(t, db, "f1", "p1", "dependency", "high", base)
	addEvent(t, db, "f1", base, KindSeen, nil)
	ignored, superseded := base.Add(48*time.Hour), base.Add(96*time.Hour)
	addDecision(t, db, "d1", "f1", "ignore", ignored, time.Time{}, superseded, "severity_changed")
	// a fix and a defer decision leave the finding open.
	addFinding(t, db, "f2", "p1", "dependency", "high", base)
	addEvent(t, db, "f2", base, KindSeen, nil)
	addDecision(t, db, "d2", "f2", "fix", ignored, time.Time{}, time.Time{}, "")
	addFinding(t, db, "f3", "p1", "dependency", "high", base)
	addEvent(t, db, "f3", base, KindSeen, nil)
	addDecision(t, db, "d3", "f3", "defer", ignored, base.Add(30*24*time.Hour), time.Time{}, "")

	tr, err := LoadTracked(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Tracked{}
	for _, x := range tr {
		byID[x.Row.ID] = x
	}
	f1 := byID["f1"]
	for _, c := range []struct {
		at   time.Time
		want bool
	}{
		{ignored.Add(-time.Second), true},
		{ignored, false},
		{superseded.Add(-time.Second), false},
		{superseded, true},
	} {
		if got := OpenAt(f1.Events, f1.Ignores, c.at); got != c.want {
			t.Errorf("f1 OpenAt(%v) = %v, want %v", c.at, got, c.want)
		}
	}
	for _, id := range []string{"f2", "f3"} {
		x := byID[id]
		if !OpenAt(x.Events, x.Ignores, ignored.Add(time.Hour)) {
			t.Errorf("%s closed by a fix or defer decision", id)
		}
	}
}

func TestOpenByDayExcludesServerAndInactive(t *testing.T) {
	db := testDB(t)
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	addFinding(t, db, "f1", "p1", "dependency", "high", base)
	addFinding(t, db, "f2", "p2", "dependency", "high", base) // removed project
	addFinding(t, db, "f3", "t1", "server_package", "high", base)
	addFinding(t, db, "f4", "t1", "server_config", "high", base)
	addFinding(t, db, "f5", "t1", "server_exposure", "high", base)
	addFinding(t, db, "f6", "p1", "server_package", "high", base) // server kind on a project id
	for _, id := range []string{"f1", "f2", "f3", "f4", "f5", "f6"} {
		addEvent(t, db, id, base, KindSeen, nil)
	}
	days, _, err := OpenByDay(context.Background(), db, base.Add(24*time.Hour), time.UTC, 2, func(r FindingRow) string { return "x" + r.SeverityLabel })
	if err != nil {
		t.Fatal(err)
	}
	if len(days) != 2 || days[0].Open["xhigh"] != 1 || days[1].Open["xhigh"] != 1 || len(days[1].Open) != 1 {
		t.Errorf("days = %+v, want one open finding each day, counted by the severity func", days)
	}
}

func TestOpenByDayFlagsReconstructedDays(t *testing.T) {
	db := testDB(t)
	mustExec(t, db, `UPDATE history_start SET at = '2026-09-02T12:00:00Z' WHERE id = 1`)
	days, start, err := OpenByDay(context.Background(), db, time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC), time.UTC, 3, sev)
	if err != nil {
		t.Fatal(err)
	}
	if !start.Equal(time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("history start = %v", start)
	}
	var got []string
	for _, d := range days {
		got = append(got, fmt.Sprintf("%s:%v", d.Date, d.Reconstructed))
	}
	// 09-01 ends on 09-02 00:00, before the start: reconstructed. 09-02
	// ends after it.
	if want := "2026-09-01:true 2026-09-02:false 2026-09-03:false"; strings.Join(got, " ") != want {
		t.Errorf("days = %v, want %s", got, want)
	}
}

func TestDaysAcrossDST(t *testing.T) {
	paris, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		date string
		long time.Duration
	}{{"2026-03-29", 23 * time.Hour}, {"2026-10-25", 25 * time.Hour}} {
		day, _ := time.ParseInLocation("2006-01-02", c.date, paris)
		now := day.AddDate(0, 0, 1).Add(15 * time.Hour) // the next day, 15:00
		days := LocalDays(now, paris, 3)
		if len(days) != 3 {
			t.Fatalf("%s: %d days", c.date, len(days))
		}
		var dates []string
		for i, d := range days {
			dates = append(dates, d.Date)
			if d.Start.Hour() != 0 || d.Start.Minute() != 0 || d.Start.Location() != paris {
				t.Errorf("%s: day %d starts at %v", c.date, i, d.Start)
			}
			if i > 0 && !days[i-1].End.Equal(d.Start) {
				t.Errorf("%s: gap between day %d and %d", c.date, i-1, i)
			}
		}
		prev := day.AddDate(0, 0, -1).Format("2006-01-02")
		next := day.AddDate(0, 0, 1).Format("2006-01-02")
		if want := prev + " " + c.date + " " + next; strings.Join(dates, " ") != want {
			t.Errorf("dates = %v, want %s", dates, want)
		}
		if got := days[1].End.Sub(days[1].Start); got != c.long {
			t.Errorf("%s lasts %v, want %v", c.date, got, c.long)
		}
		if got := days[0].End.Sub(days[0].Start); got != 24*time.Hour {
			t.Errorf("the day before %s lasts %v", c.date, got)
		}
	}
}

func TestOpenByDayIsFast(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	db := testDB(t)
	start := time.Date(2025, 11, 6, 8, 0, 0, 0, time.UTC)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	labels := []string{"critical", "high", "medium", "low", "unknown"}
	for i := 0; i < 5000; i++ {
		id := fmt.Sprintf("f%05d", i)
		seen := start.Add(time.Duration(i%365) * 24 * time.Hour)
		if _, err := tx.Exec(`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, severity_label,
			installed_version, status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at)
			VALUES (?, 'p1', 'composer.lock', 'npm', 'pkg', ?, ?, '1.0.0', 'new', 's1', 's1', ?, ?)`,
			id, "OSV-"+id, labels[i%5], rfc(seen), rfc(seen)); err != nil {
			t.Fatal(err)
		}
		events := []struct {
			at   time.Time
			kind string
		}{{seen, KindSeen}, {seen.Add(72 * time.Hour), KindGone}, {seen.Add(120 * time.Hour), KindBack}}
		for n, e := range events {
			if _, err := tx.Exec(`INSERT INTO finding_event (finding_id, seq, at, kind, detail) VALUES (?, ?, ?, ?, '{}')`,
				id, n+1, rfc(e.at), e.kind); err != nil {
				t.Fatal(err)
			}
		}
		if i%3 == 0 {
			if _, err := tx.Exec(`INSERT INTO decision (id, finding_id, project_id, action, author, created_at, superseded_at)
				VALUES (?, ?, 'p1', 'ignore', 'web', ?, ?)`, "d"+id, id, rfc(seen.Add(200*time.Hour)), rfc(seen.Add(400*time.Hour))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	days, _, err := OpenByDay(context.Background(), db, start.AddDate(1, 0, 0), time.UTC, 365, sev)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(began); took > time.Second {
		t.Errorf("OpenByDay took %v for 5 000 findings and 365 days", took)
	}
	if len(days) != 365 {
		t.Errorf("%d days", len(days))
	}
}
