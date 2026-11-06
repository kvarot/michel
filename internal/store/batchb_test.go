package store

import (
	"database/sql"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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
