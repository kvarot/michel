// Package store owns the SQLite database: opening it and applying migrations.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
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
	_, serr := os.Stat(filepath.Dir(path))
	created := errors.Is(serr, os.ErrNotExist)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("cannot create the data folder %s: %w. Check its permissions or pass another --data-dir", filepath.Dir(path), err)
	}
	// A new database file is the user's only from its first byte.
	if f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
		f.Close()
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
	tighten(path, created)
	return &Store{db: db, path: path}, nil
}

// unixPerms and chmod are what tighten uses; tests replace them.
var (
	unixPerms = runtime.GOOS != "windows"
	chmod     = os.Chmod
)

// tighten makes a data folder Michel just created the user's only (0700)
// and the database files too (0600), outside Windows (no Unix permission
// bits there; the folder inherits the user profile's ACL). A folder that
// already existed keeps its mode: it is the user's. The -wal and -shm files
// exist once the migrations ran; SQLite gives later ones the mode of the
// database. A chmod that fails is a warning: the database still opens.
func tighten(path string, created bool) {
	if !unixPerms {
		return
	}
	if created {
		if err := chmod(filepath.Dir(path), 0o700); err != nil {
			slog.Warn("store: cannot restrict the data folder to you", "folder", filepath.Dir(path), "err", err)
		}
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := chmod(path+suffix, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("store: cannot restrict a database file to you", "file", path+suffix, "err", err)
		}
	}
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// DB returns the underlying handle.
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }
