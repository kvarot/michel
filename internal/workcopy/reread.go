package workcopy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/project"
)

// Reread reads the copy as it is now, without git: sum covers the path and
// the content of every file outside .git (what git ignores too), and hits is
// what the secret detectors find in them, never a value. Anything but a
// folder or a regular file counts by its path and kind.
func Reread(d Deps, c Copy) (sum string, hits []mask.Hit, err error) {
	if err := checkCopy(d, c); err != nil {
		return "", nil, err
	}
	h := sha256.New()
	files := []string{}
	err = filepath.WalkDir(c.Dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(c.Dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if e.IsDir() {
			if rel == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		fmt.Fprintf(h, "%s\x00%d\x00", rel, e.Type())
		if !e.Type().IsRegular() {
			return nil
		}
		files = append(files, rel)
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(h, f)
		return err
	})
	if err != nil {
		return "", nil, fmt.Errorf("Michel cannot read the fix copy: %w", noPath(err))
	}
	return hex.EncodeToString(h.Sum(nil)), mask.ScanFiles(c.Dir, files), nil
}

// Head is the commit of the project's HEAD now ("" without a commit).
func Head(ctx context.Context, d Deps, p project.Project) (string, error) {
	if !filepath.IsAbs(p.Path) || !IsGitRepo(p.Path) {
		return "", ErrNotGitRepo
	}
	h, err := ensureHome(d)
	if err != nil {
		return "", err
	}
	return h.revParseCommit(ctx, d, p.Path, "HEAD")
}
