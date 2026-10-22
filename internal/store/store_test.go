package store

import (
	"path/filepath"
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
		if err := s.DB().QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n != 1 {
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
