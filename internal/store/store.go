// Package store owns the SQLite database: opening it and applying migrations.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	_ "modernc.org/sqlite" // pure Go driver, registered as "sqlite"
)

// Store is an open, migrated SQLite database.
type Store struct {
	db   *sql.DB
	path string
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
	q.Add("_txlock", "immediate") // BeginTx takes the write lock up front, so read-then-write is atomic across processes
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
		return nil, fmt.Errorf("cannot prepare the database %s: %w. The file may be damaged. If the file is corrupted, restore it from a backup; Michel never deletes it for you.", path, err)
	}
	if err := tighten(path); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, path: path}, nil
}

// tighten makes the data folder the user's only (0700) and the database
// files too (0600), outside Windows (no Unix permission bits there; the
// folder inherits the user profile's ACL). The -wal and -shm files exist
// once the migrations ran; SQLite gives later ones the mode of the database.
func tighten(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("cannot restrict the data folder %s to you: %w", filepath.Dir(path), err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Chmod(path+suffix, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("cannot restrict the database file %s to you: %w", path+suffix, err)
		}
	}
	return nil
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// DB returns the underlying handle.
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }
