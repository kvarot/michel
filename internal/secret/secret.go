// Package secret keeps small secrets (SMTP password, webhook token, the local
// API token) in the data folder, one file per name under <data-dir>/secrets.
// On Windows each file is encrypted with DPAPI for the current user; on
// other systems the file is plain text, readable by its owner only (0600).
// No function of this package puts a secret value in an error.
package secret

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// ErrNotFound is returned when no secret has that name.
var ErrNotFound = errors.New("secret not found")

// ErrInvalidName is returned for a name outside [a-z0-9-]{1,64}.
var ErrInvalidName = errors.New("invalid secret name: use 1 to 64 lowercase letters, digits or hyphens")

var namePattern = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// ReservedAPIToken is the name of the local API token, written by michel
// serve and never by michel secret set.
const ReservedAPIToken = "api-token"

// GitHubToken is the name of the GitHub token: when set, it goes with the
// GitHub API requests of the sources (advisories, repository status,
// discovery) and raises the request budget of an update.
const GitHubToken = "github-token"

// Store reads and writes named secrets.
type Store interface {
	Set(name string, value []byte) error
	Get(name string) ([]byte, error)
	Delete(name string) error
	List() ([]string, error)
}

// fileStore keeps one file per secret in dir.
type fileStore struct{ dir string }

// tempPrefix starts the name of a file being written; such files are never
// listed (a name cannot start with a dot).
const tempPrefix = ".tmp-"

// Open returns the store of dataDir/secrets: DPAPI-protected files on Windows (user scope), 0600 plain files elsewhere.
func Open(dataDir string) (Store, error) {
	dir := filepath.Join(dataDir, "secrets")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create the secrets folder: %w", err)
	}
	// MkdirAll keeps the mode of an existing folder: tighten it (a no-op on
	// Windows, where DPAPI protects the values).
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot restrict the secrets folder: %w", err)
	}
	return &fileStore{dir: dir}, nil
}

// ValidName reports whether name may name a secret: [a-z0-9-]{1,64}.
func ValidName(name string) bool { return namePattern.MatchString(name) }

func checkName(name string) error {
	if !ValidName(name) {
		return ErrInvalidName
	}
	return nil
}

// Set stores value under name, replacing any previous value. The write is
// atomic: a temporary file is renamed over the old one.
func (s *fileStore) Set(name string, value []byte) error {
	if err := checkName(name); err != nil {
		return err
	}
	data, err := protect(value)
	if err != nil {
		return fmt.Errorf("cannot encrypt secret %s: %w", name, err)
	}
	f, err := os.CreateTemp(s.dir, tempPrefix+name+"-*")
	if err != nil {
		return fmt.Errorf("cannot write secret %s: %w", name, err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil { // CreateTemp already uses 0600; keep it explicit
		return fmt.Errorf("cannot restrict secret %s: %w", name, err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("cannot write secret %s: %w", name, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("cannot write secret %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("cannot write secret %s: %w", name, err)
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, name)); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("cannot write secret %s: %w", name, err)
	}
	ok = true
	return nil
}

// Get returns the value stored under name.
func (s *fileStore) Get(name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(s.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read secret %s: %w", name, err)
	}
	v, err := unprotect(data)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt secret %s (written by another Windows user or damaged): %w", name, err)
	}
	return v, nil
}

// Delete removes the secret name.
func (s *fileStore) Delete(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(s.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("cannot delete secret %s: %w", name, err)
	}
	return nil
}

// List returns the names of the stored secrets, sorted. Temporary and
// foreign files are ignored.
func (s *fileStore) List() ([]string, error) {
	entries, err := os.ReadDir(s.dir) // sorted by file name
	if err != nil {
		return nil, fmt.Errorf("cannot read the secrets folder: %w", err)
	}
	names := []string{}
	for _, e := range entries {
		if e.Type().IsRegular() && namePattern.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// Protect encrypts plain for the current user: DPAPI on Windows, a copy of
// the value elsewhere (the file mode is the protection there).
func Protect(plain []byte) ([]byte, error) { return protect(plain) }

// Unprotect reverses Protect for the same user.
func Unprotect(data []byte) ([]byte, error) { return unprotect(data) }
