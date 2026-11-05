package store

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Outside Windows a data folder Michel creates is the user's only (0700),
// and the database files are too (0600), whatever they were before.
func TestOpenTightensPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix permission bits")
	}
	dir := filepath.Join(t.TempDir(), "data")
	path := filepath.Join(dir, "michel.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("data folder mode = %v (%v), want 0700", info.Mode().Perm(), err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(path+suffix), err)
			continue
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", filepath.Base(path+suffix), info.Mode().Perm())
		}
	}
}

// A folder that already existed is the user's choice: Michel leaves its
// mode alone, and still tightens the database files in it.
func TestOpenLeavesAnExistingFolderAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix permission bits")
	}
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "michel.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o755 {
		t.Errorf("existing folder mode = %v, want 0755 kept", info.Mode().Perm())
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("database mode = %v, want 0600", info.Mode().Perm())
	}
}

// A chmod that fails is a warning, not a database that cannot open.
func TestOpenWarnsWhenItCannotTighten(t *testing.T) {
	savedUnix, savedChmod := unixPerms, chmod
	unixPerms = true
	chmod = func(string, os.FileMode) error { return errors.New("operation not permitted") }
	var buf bytes.Buffer
	savedLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { unixPerms, chmod = savedUnix, savedChmod; slog.SetDefault(savedLog) })
	s, err := Open(filepath.Join(t.TempDir(), "data", "michel.db"))
	if err != nil {
		t.Fatalf("Open failed on a chmod error: %v", err)
	}
	s.Close()
	if out := buf.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "not permitted") {
		t.Errorf("no warning: %q", out)
	}
}
