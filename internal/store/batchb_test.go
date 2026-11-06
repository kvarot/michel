package store

import (
	"database/sql"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// oldDatabase builds at path a database of the version that ends with
// migration upTo, the way an older Michel left it, and runs the statements
// of seed in it.
func oldDatabase(t *testing.T, path string, upTo int, seed ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:///"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		v, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil || v > upTo {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations VALUES (?, '2026-01-01T00:00:00Z')`, v); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range seed {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func TestMigration0024AddsAutoScanToAnOldDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "michel.db")
	oldDatabase(t, path, 22, `INSERT INTO project (id, name, source_type, path, classification, created_at)
		VALUES ('p1','demo','local_path','/x','sensitive','2026-01-01T00:00:00Z')`)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var auto int
	if err := s.DB().QueryRow(`SELECT auto_scan FROM project WHERE id = 'p1'`).Scan(&auto); err != nil || auto != 1 {
		t.Errorf("auto_scan = %d, %v", auto, err)
	}
}

// 0026 numbers the events of an old database in their order (the old rowid
// column, copied as seq), keeps every hashed field and counts them in the
// anchor.
func TestMigration0026KeepsTheChainOfAnOldDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "michel.db")
	var seed []string
	for _, r := range []struct{ rowid, id, prev, hash string }{{"1", "e1", "", "h1"}, {"2", "e2", "h1", "h2"}, {"5", "e5", "h2", "h5"}} {
		seed = append(seed, `INSERT INTO audit_event (rowid, id, ts, actor, action, target, result, correlation_id, evidence, prev_hash, hash)
			VALUES (`+r.rowid+`, '`+r.id+`', '2026-01-01T00:00:00Z', 'cli', 'app.start', 'v', 'ok', '', '{}', '`+r.prev+`', '`+r.hash+`')`)
	}
	oldDatabase(t, path, 22, seed...)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.DB().Query(`SELECT seq, id, prev_hash, hash, hmac FROM audit_event ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var seq int
		var id, prev, hash, mac string
		if err := rows.Scan(&seq, &id, &prev, &hash, &mac); err != nil {
			t.Fatal(err)
		}
		got = append(got, strconv.Itoa(seq)+":"+id+":"+prev+">"+hash+":"+mac)
	}
	rows.Close()
	if strings.Join(got, " ") != "1:e1:>h1: 2:e2:h1>h2: 5:e5:h2>h5:" {
		t.Errorf("events = %v", got)
	}
	var events int
	if err := s.DB().QueryRow(`SELECT events FROM audit_anchor WHERE id = 1`).Scan(&events); err != nil || events != 3 {
		t.Errorf("anchor = %d %v", events, err)
	}
	for _, idx := range []string{"idx_audit_event_action", "idx_audit_event_action_target"} {
		var n int
		if err := s.DB().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s: n=%d err=%v", idx, n, err)
		}
	}
}

// 0028 reconstructs the past of an old database: a seen event per finding, a
// gone event for the gone ones, a start and a current state per attempt, all
// flagged as reconstructed, and notes when the history begins.
func TestMigrationReconstructsHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "michel.db")
	finding := func(id, status, changed string) string {
		return `INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, installed_version, status,
			first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, status_changed_at)
			VALUES ('` + id + `','p1','composer.lock','Packagist','acme/lib','ACME-` + id + `','1.0.0','` + status + `',
			's1','s2','2026-01-01T00:00:00Z','2026-01-05T00:00:00Z','` + changed + `')`
	}
	attempt := func(id, state, updated string) string {
		return `INSERT INTO fix_attempt (id, finding_id, project_id, origin, state, created_at, updated_at)
			VALUES ('` + id + `','f1','p1','manual','` + state + `','2026-01-02T00:00:00Z','` + updated + `')`
	}
	oldDatabase(t, path, 27,
		finding("f1", "gone", "2026-01-04T00:00:00Z"),
		finding("f2", "pending", "2026-01-03T00:00:00Z"),
		attempt("a1", "applied", "2026-01-03T12:00:00Z"),
		attempt("a2", "preparing", "2026-01-02T00:00:00Z"))
	before := time.Now().UTC().Truncate(time.Second)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	rows, err := s.DB().Query(`SELECT finding_id, seq, at, kind, detail FROM finding_event ORDER BY finding_id, seq`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var id, at, kind, detail string
		var seq int
		if err := rows.Scan(&id, &seq, &at, &kind, &detail); err != nil {
			t.Fatal(err)
		}
		got = append(got, id+":"+strconv.Itoa(seq)+":"+at+":"+kind+":"+detail)
	}
	rows.Close()
	want := `f1:1:2026-01-01T00:00:00Z:seen:{"reconstructed":true} f1:2:2026-01-04T00:00:00Z:gone:{"reconstructed":true} ` +
		`f2:1:2026-01-01T00:00:00Z:seen:{"reconstructed":true}`
	if strings.Join(got, " ") != want {
		t.Errorf("finding events =\n%s\nwant\n%s", strings.Join(got, " "), want)
	}
	rows, err = s.DB().Query(`SELECT attempt_id, seq, at, state, reconstructed FROM fix_attempt_event ORDER BY attempt_id, seq`)
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	for rows.Next() {
		var id, at, state string
		var seq, rec int
		if err := rows.Scan(&id, &seq, &at, &state, &rec); err != nil {
			t.Fatal(err)
		}
		got = append(got, id+":"+strconv.Itoa(seq)+":"+at+":"+state+":"+strconv.Itoa(rec))
	}
	rows.Close()
	want = "a1:1:2026-01-02T00:00:00Z:preparing:1 a1:2:2026-01-03T12:00:00Z:applied:1 a2:1:2026-01-02T00:00:00Z:preparing:1"
	if strings.Join(got, " ") != want {
		t.Errorf("attempt events =\n%s\nwant\n%s", strings.Join(got, " "), want)
	}
	var startText string
	if err := s.DB().QueryRow(`SELECT at FROM history_start WHERE id = 1`).Scan(&startText); err != nil {
		t.Fatal(err)
	}
	start, err := time.Parse(time.RFC3339, startText)
	if err != nil || start.Before(before) || start.After(time.Now()) || start.Location() != time.UTC {
		t.Errorf("history_start = %q (%v), want the migration instant in UTC", startText, err)
	}
	for _, idx := range []string{"idx_finding_event_at", "idx_finding_event_finding", "idx_fix_attempt_event_at"} {
		var n int
		if err := s.DB().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s: n=%d err=%v", idx, n, err)
		}
	}
	// Opening again neither adds events nor moves the start.
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	var again string
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM finding_event`).Scan(&n); err != nil || n != 3 {
		t.Errorf("finding events after reopening = %d %v", n, err)
	}
	if err := s.DB().QueryRow(`SELECT at FROM history_start`).Scan(&again); err != nil || again != startText {
		t.Errorf("history_start after reopening = %q %v", again, err)
	}
}

// 0028 is portable like the others: no rowid, no SQLite date function.
func TestMigration0028IsPortable(t *testing.T) {
	body, err := migrationFS.ReadFile("migrations/0028_history.sql")
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(body))
	for _, banned := range []string{"rowid", "autoincrement", "datetime(", "strftime(", "insert or replace"} {
		if strings.Contains(lower, banned) {
			t.Errorf("0028 is not portable: it contains %q", banned)
		}
	}
}
