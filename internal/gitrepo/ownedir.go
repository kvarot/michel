package gitrepo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// WriteOwnedDir writes files (slash-separated relative names) in dir, with
// MarkerFile carrying key, through a temporary folder next to dir renamed
// into place. An existing dir that does not carry the marker of key (or is a
// link) is never touched: the error is ErrForeignDir. The parent folder is
// created when missing.
func WriteOwnedDir(dir, key string, files map[string][]byte) error {
	if key == "" {
		return fmt.Errorf("an owned folder needs a key")
	}
	names := make([]string, 0, len(files))
	for name := range files {
		clean := filepath.FromSlash(name)
		if name == "" || !filepath.IsLocal(clean) || filepath.Base(clean) == MarkerFile && filepath.Dir(clean) == "." {
			return fmt.Errorf("cannot write %q in %s: not a plain relative file name", name, filepath.Base(dir))
		}
		names = append(names, name)
	}
	sort.Strings(names)
	dir = filepath.Clean(dir)
	if fi, err := os.Lstat(dir); err == nil && (fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() || !ownedBy(dir, key)) {
		return fmt.Errorf("%w: %s", ErrForeignDir, dir)
	}
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("cannot create %s: %w", parent, err)
	}
	tmp, err := os.MkdirTemp(parent, ".michel-install-")
	if err != nil {
		return fmt.Errorf("cannot write in %s: %w", parent, err)
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(tmp)
		}
	}()
	h := sha256.New()
	for _, name := range names {
		to := filepath.Join(tmp, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(to, files[name], 0o644); err != nil {
			return err
		}
		h.Write([]byte(name + "\x00"))
		h.Write(files[name])
	}
	m, _ := json.Marshal(marker{Key: key, SHA: hex.EncodeToString(h.Sum(nil)), InstalledAt: time.Now().UTC().Format(time.RFC3339)})
	if err := os.WriteFile(filepath.Join(tmp, MarkerFile), m, 0o644); err != nil {
		return fmt.Errorf("cannot write the marker: %w", err)
	}
	if err := swapDir(parent, tmp, dir, filepath.Base(dir)); err != nil {
		return err
	}
	ok = true
	return nil
}

// RemoveOwnedDir removes dir when it is a real folder carrying the marker of
// key, and reports whether it did. A missing, foreign or linked dir is left
// as it is (false, nil).
func RemoveOwnedDir(dir, key string) (bool, error) {
	fi, err := os.Lstat(dir)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() || !ownedBy(dir, key) {
		return false, nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return false, fmt.Errorf("cannot remove %s: %w", dir, err)
	}
	return true, nil
}
