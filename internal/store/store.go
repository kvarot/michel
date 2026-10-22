// Package store owns the SQLite database: opening it and applying migrations.
package store

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite" // pure Go driver, registered as "sqlite"
)

// Store is an open, migrated SQLite database.
type Store struct {
	db *sql.DB
}

// Open creates the parent directory, opens the database at path in WAL mode
// with foreign keys on, and applies pending migrations.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("cannot create the data folder %s: %w. Check its permissions or pass another --data-dir", filepath.Dir(path), err)
	}
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	dsn := "file:" + filepath.ToSlash(path) + "?" + q.Encode()
	if filepath.IsAbs(path) && filepath.VolumeName(path) != "" {
		dsn = "file:///" + filepath.ToSlash(path) + "?" + q.Encode()
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("cannot open the database %s: %w", path, err)
	}
	db.SetMaxOpenConns(1) // one writer; serializes access and keeps pragmas per connection
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("cannot prepare the database %s: %w. The file may be damaged; move it aside to start fresh", path, err)
	}
	return &Store{db: db}, nil
}

// DB returns the underlying handle.
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }
