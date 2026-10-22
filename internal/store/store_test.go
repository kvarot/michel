package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenAppliesMigrationsIdempotently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "michel.db")
	for i := 0; i < 2; i++ {
		s, err := Open(path)
		if err != nil {
			t.Fatalf("open #%d: %v", i, err)
		}
		var n int
		if err := s.DB().QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n != 2 {
			t.Fatalf("schema_migrations rows = %d, err %v", n, err)
		}
		var mode string
		if err := s.DB().QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
			t.Fatalf("journal_mode = %q, err %v", mode, err)
		}
		var fk int
		if err := s.DB().QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
			t.Fatalf("foreign_keys = %d, err %v", fk, err)
		}
		for _, tbl := range []string{"audit_event", "project", "scan", "scan_manifest", "finding"} {
			if _, err := s.DB().Exec(`SELECT 1 FROM ` + tbl + ` LIMIT 1`); err != nil {
				t.Errorf("table %s: %v", tbl, err)
			}
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMigrationAppliedByAnotherProcessMeanwhileIsSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "michel.db")
	// Another process applies the migrations between this process's
	// "already applied?" check and its transaction.
	beforeMigrationTx = func() {
		beforeMigrationTx = nil
		other, err := Open(path)
		if err != nil {
			t.Errorf("other process: %v", err)
			return
		}
		other.Close()
	}
	t.Cleanup(func() { beforeMigrationTx = nil })
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open after a concurrent migration: %v", err)
	}
	defer s.Close()
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("schema_migrations rows = %d err %v", n, err)
	}
}

func TestOpenErrorDoesNotAdviseDeletingTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "michel.db")
	if err := os.WriteFile(path, []byte("this is not a SQLite database, just enough bytes to look like a damaged file....."), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(path)
	if err == nil {
		t.Fatal("expected an error on a damaged file")
	}
	msg := err.Error()
	if strings.Contains(msg, "move it aside") || strings.Contains(msg, "start fresh") ||
		!strings.Contains(msg, "restore it from a backup; Michel never deletes it for you") {
		t.Errorf("message = %q", msg)
	}
}

func TestMigration0002Applies(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	have := map[string]bool{}
	rows, err := s.DB().Query(`PRAGMA table_info(project)`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		have[name] = true
	}
	rows.Close()
	for _, c := range []string{"core_packages", "risk_overrides"} {
		if !have[c] {
			t.Errorf("project.%s missing", c)
		}
	}
	if _, err := s.DB().Exec(`SELECT finding_id, risk_score, recommendation, warning FROM analysis LIMIT 1`); err != nil {
		t.Errorf("analysis table: %v", err)
	}
}

func TestMigration0002UpgradesExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "michel.db")
	db, err := sql.Open("sqlite", "file:///"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	body, err := migrationFS.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		string(body),
		`INSERT INTO schema_migrations VALUES (1, '2026-01-01T00:00:00Z')`,
		`INSERT INTO project (id, name, source_type, path, classification, created_at) VALUES ('p1','old','local_path','/x','sensitive','2026-01-01T00:00:00Z')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var name, core, over string
	if err := s.DB().QueryRow(`SELECT name, core_packages, risk_overrides FROM project WHERE id='p1'`).Scan(&name, &core, &over); err != nil {
		t.Fatal(err)
	}
	if name != "old" || core != "[]" || over != "{}" {
		t.Errorf("row = %q %q %q", name, core, over)
	}
	var versions string
	if err := s.DB().QueryRow(`SELECT group_concat(version) FROM (SELECT version FROM schema_migrations ORDER BY version)`).Scan(&versions); err != nil || versions != "1,2" {
		t.Errorf("versions = %q err %v", versions, err)
	}
}
