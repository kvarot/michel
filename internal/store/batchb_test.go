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
