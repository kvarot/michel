package gitrepo

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteOwnedDirWritesMarkerAndFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "skills", "michel-fix-1")
	files := map[string][]byte{"SKILL.md": []byte("one"), "sub/note.txt": []byte("two")}
	if err := WriteOwnedDir(dir, "fix:f1", files); err != nil {
		t.Fatal(err)
	}
	if !ownedBy(dir, "fix:f1") {
		t.Fatal("no marker for the key")
	}
	if b, err := os.ReadFile(filepath.Join(dir, "sub", "note.txt")); err != nil || string(b) != "two" {
		t.Errorf("nested file: %q %v", b, err)
	}
	// A second write replaces the content.
	if err := WriteOwnedDir(dir, "fix:f1", map[string][]byte{"SKILL.md": []byte("three")}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "SKILL.md")); string(b) != "three" {
		t.Errorf("not replaced: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "sub")); err == nil {
		t.Error("old file kept")
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(dir), ".michel-*"))
	if len(left) != 0 {
		t.Errorf("temporary folders left: %v", left)
	}
}

func TestWriteOwnedDirRefusesForeignDir(t *testing.T) {
	root := t.TempDir()
	foreign := filepath.Join(root, "mine")
	if err := os.MkdirAll(foreign, 0o755); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(foreign, "keep.txt")
	if err := os.WriteFile(keep, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteOwnedDir(foreign, "fix:f1", map[string][]byte{"SKILL.md": []byte("y")}); !errors.Is(err, ErrForeignDir) {
		t.Errorf("err = %v, want ErrForeignDir", err)
	}
	// Another key's marker is foreign too.
	other := filepath.Join(root, "other")
	if err := WriteOwnedDir(other, "fix:f2", map[string][]byte{"a": nil}); err != nil {
		t.Fatal(err)
	}
	if err := WriteOwnedDir(other, "fix:f1", map[string][]byte{"a": nil}); !errors.Is(err, ErrForeignDir) {
		t.Errorf("other key: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Error("foreign file touched")
	}
}

func TestWriteOwnedDirRefusesBadNames(t *testing.T) {
	for _, name := range []string{"../x", "/abs", MarkerFile, ""} {
		dir := filepath.Join(t.TempDir(), "d")
		if err := WriteOwnedDir(dir, "k", map[string][]byte{name: []byte("x")}); err == nil {
			t.Errorf("%q accepted", name)
		}
		if _, err := os.Stat(dir); err == nil {
			t.Errorf("%q: folder created", name)
		}
	}
}

func TestRemoveOwnedDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "d")
	if err := WriteOwnedDir(dir, "k", map[string][]byte{"a": []byte("1")}); err != nil {
		t.Fatal(err)
	}
	if ok, err := RemoveOwnedDir(dir, "other"); ok || err != nil {
		t.Errorf("other key: %v %v", ok, err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("removed with the wrong key")
	}
	if ok, err := RemoveOwnedDir(dir, "k"); !ok || err != nil {
		t.Errorf("remove: %v %v", ok, err)
	}
	if ok, err := RemoveOwnedDir(dir, "k"); ok || err != nil {
		t.Errorf("already gone: %v %v", ok, err)
	}
}
