package analyze

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxComposerJSON caps the bytes read from an installed package's composer.json.
const maxComposerJSON = 1 << 20

var (
	errBadPackageName = errors.New("invalid package name")
	errNotInstalled   = errors.New("not installed locally")
	errSymlink        = errors.New("symbolic link refused")
	errOutside        = errors.New("resolves outside the project")
)

// validPackageName rejects names that could leave the modules directory.
func validPackageName(pkg string) bool {
	return pkg != "" && !filepath.IsAbs(pkg) && !strings.HasPrefix(pkg, "/") &&
		!strings.Contains(pkg, "..") && !strings.Contains(pkg, `\`) && !strings.Contains(pkg, ":")
}

// installedPackageDir returns <manifestDir>/<modules>/<pkg> when it is a real
// directory (not a symbolic link) whose resolved path stays under manifestDir.
// Dependency folders are untrusted: a link could point anywhere on the disk.
func installedPackageDir(manifestDir, modules, pkg string) (string, error) {
	if !validPackageName(pkg) {
		return "", errBadPackageName
	}
	dir := filepath.Join(manifestDir, modules, filepath.FromSlash(pkg))
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", errNotInstalled
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", errSymlink
	}
	if !fi.IsDir() {
		return "", errNotInstalled
	}
	if err := staysUnder(manifestDir, dir); err != nil {
		return "", err
	}
	return dir, nil
}

// staysUnder checks that p, once every link is resolved, is inside base.
func staysUnder(base, p string) error {
	rb, err := filepath.EvalSymlinks(base)
	if err != nil {
		return errOutside
	}
	rp, err := filepath.EvalSymlinks(p)
	if err != nil {
		return errOutside
	}
	rel, err := filepath.Rel(rb, rp)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return errOutside
	}
	return nil
}

// openRegular opens dir/name when it is a regular file (not a link) that
// stays under base. It fails when the file does not exist or is refused.
func openRegular(base, dir, name string) (*os.File, os.FileInfo, error) {
	p := filepath.Join(dir, name)
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errSymlink
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, errNotInstalled
	}
	if err := staysUnder(base, p); err != nil {
		return nil, nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, nil, err
	}
	return f, fi, nil
}

// readLimited reads at most limit bytes of f and closes it; more is an error.
func readLimited(f *os.File, limit int64) ([]byte, error) {
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file too large")
	}
	return b, nil
}
