package workcopy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/project"
)

var (
	// ErrNotGitRepo: the project folder is not the top of a git repository.
	ErrNotGitRepo = errors.New("this project is not in git")
	// ErrNoCommit: the project's repository has no commit to copy.
	ErrNoCommit = errors.New("the project's repository has no commit yet")
	// ErrInvalidID: a project or attempt id that cannot name a folder.
	ErrInvalidID = errors.New("invalid project or attempt id")
	// ErrCopyExists: the copy of this attempt was already prepared.
	ErrCopyExists = errors.New("the copy of this attempt already exists")
	// ErrNotACopy: a folder that is not a fix copy of Michel's data folder.
	ErrNotACopy = errors.New("not a fix copy")
	// ErrCopyTampered: the git configuration of the copy changed since it
	// was prepared (it could make git run a program, through a filter or a
	// diff driver).
	ErrCopyTampered = errors.New("the git configuration of the fix copy was changed")
)

// Copy is the fix copy of one attempt.
type Copy struct {
	// Dir is <data>/worktrees/<project id>/<attempt id>. Never shown.
	Dir string
	// Base is the commit of the project's HEAD the copy was made from.
	Base string
	// Excluded lists the tracked files left out of the copy (slash paths,
	// sorted): they are in its index, never on its disk, and stay unchanged
	// in its commits.
	Excluded []string
	// Exclude repeats the project's excluded folder names, so that a new
	// file under one of them never becomes part of the change.
	Exclude []string
	// SecretHits are the secrets the detectors found in the files of the
	// copy (file, line and kind, never the value).
	SecretHits []mask.Hit
	// ConfigSHA is the SHA-256 of the copy's .git/config as git clone wrote
	// it. Diff, Commit and Apply refuse a copy whose configuration changed
	// since (an agent could add a filter or a driver that git would run).
	ConfigSHA string
}

// idShape is a project or attempt id usable as a folder name (a ULID).
var idShape = regexp.MustCompile(`^[0-9A-Za-z]{1,64}$`)

// excludedFiles are the file name patterns never copied, at any depth.
var excludedFiles = []string{".env*", "*.pem", "*.key", "id_*"}

// IsGitRepo reports whether path is the top folder of a git repository: it
// holds a .git folder with a HEAD, or a .git file pointing to one (a linked
// worktree or a submodule). It runs nothing and writes nothing.
func IsGitRepo(path string) bool {
	if path == "" {
		return false
	}
	dotgit := filepath.Join(path, ".git")
	info, err := os.Lstat(dotgit)
	if err != nil {
		return false
	}
	if info.IsDir() {
		head, err := os.Stat(filepath.Join(dotgit, "HEAD"))
		return err == nil && head.Mode().IsRegular()
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return false
	}
	b, err := os.ReadFile(dotgit)
	return err == nil && bytes.HasPrefix(b, []byte("gitdir:"))
}

// sparsePatterns is the sparse-checkout definition of a copy: everything
// but the excluded files and folders. The excluded tracked files keep their
// index entry (skip-worktree) and are never written on disk.
func sparsePatterns(exclude []string) string {
	var b strings.Builder
	b.WriteString("/*\n")
	for _, p := range excludedFiles {
		b.WriteString("!" + p + "\n")
	}
	for _, n := range exclude {
		b.WriteString("!" + n + "/\n")
	}
	return b.String()
}

// excludePathspecs keep the same files out of git add in the copy: a file
// the agent creates there (a new .env, a key) never becomes part of the
// change.
func excludePathspecs(exclude []string) []string {
	out := []string{"."}
	for _, p := range excludedFiles {
		out = append(out, ":(exclude,glob)**/"+p)
	}
	for _, n := range exclude {
		out = append(out, ":(exclude,glob)**/"+n+"/**")
	}
	return out
}

// validFolderName reports whether n is a plain folder name (project.Exclude
// is validated when stored; checked again before it reaches git).
func validFolderName(n string) bool {
	return n != "" && n != "." && n != ".." && !strings.ContainsAny(n, "/\\:*?[]!\n\r\x00") && filepath.IsLocal(n)
}

// Prepare makes the fix copy of attempt attemptID of p in
// <data>/worktrees/<project id>/<attempt id>: git clone --local
// --no-checkout of the project folder, then a checkout of its HEAD commit
// without the excluded files (.env*, *.pem, *.key, id_*, the folders of
// p.Exclude). Nothing is written under p.Path: the clone only reads it, and
// git runs there without hooks, file system monitor, automatic gc, system or
// global configuration. The secret detectors run on the files of the copy.
func Prepare(ctx context.Context, d Deps, p project.Project, attemptID string) (Copy, error) {
	if !idShape.MatchString(p.ID) || !idShape.MatchString(attemptID) {
		return Copy{}, ErrInvalidID
	}
	exclude := []string{}
	for _, n := range p.Exclude {
		if !validFolderName(n) {
			return Copy{}, fmt.Errorf("%w: %q", project.ErrInvalidExclude, n)
		}
		exclude = append(exclude, n)
	}
	if !filepath.IsAbs(p.Path) || !IsGitRepo(p.Path) {
		return Copy{}, ErrNotGitRepo
	}
	h, err := ensureHome(d)
	if err != nil {
		return Copy{}, err
	}
	base, err := h.revParseCommit(ctx, d, p.Path, "HEAD")
	if err != nil {
		return Copy{}, err
	}
	if base == "" {
		return Copy{}, ErrNoCommit
	}
	parent := filepath.Join(d.DataDir, "worktrees", p.ID)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return Copy{}, fmt.Errorf("Michel cannot create the fix copy: %w", noPath(err))
	}
	dir := filepath.Join(parent, attemptID)
	if _, err := os.Lstat(dir); err == nil {
		return Copy{}, ErrCopyExists
	}
	c := Copy{Dir: dir, Base: base, Exclude: exclude}
	fail := func(err error) (Copy, error) {
		_ = os.RemoveAll(dir)
		return Copy{}, err
	}
	if _, stderr, err := h.git(ctx, d, parent, "", localTransport, nil,
		"clone", "--local", "--no-checkout", "--no-hardlinks", "--quiet", "--", p.Path, dir); err != nil {
		return fail(gitErr("clone", err, stderr))
	}
	info := filepath.Join(dir, ".git", "info")
	if err := os.MkdirAll(info, 0o700); err != nil {
		return fail(fmt.Errorf("Michel cannot prepare the fix copy: %w", noPath(err)))
	}
	if err := os.WriteFile(filepath.Join(info, "sparse-checkout"), []byte(sparsePatterns(exclude)), 0o600); err != nil {
		return fail(fmt.Errorf("Michel cannot prepare the fix copy: %w", noPath(err)))
	}
	sparse := []string{"-c", "core.sparseCheckout=true", "-c", "core.sparseCheckoutCone=false"}
	if _, stderr, err := h.git(ctx, d, dir, dir, sparse, nil, "checkout", "--quiet", "--detach", base); err != nil {
		return fail(gitErr("checkout", err, stderr))
	}
	out, stderr, err := h.git(ctx, d, dir, dir, nil, nil, "ls-files", "-t", "-z")
	if err != nil {
		return fail(gitErr("ls-files", err, stderr))
	}
	var kept []string
	for _, e := range strings.Split(string(out), "\x00") {
		tag, rel, ok := strings.Cut(e, " ")
		if !ok {
			continue
		}
		if tag == "S" {
			c.Excluded = append(c.Excluded, rel)
		} else {
			kept = append(kept, rel)
		}
	}
	slices.Sort(c.Excluded)
	c.SecretHits = mask.ScanFiles(dir, kept)
	if c.ConfigSHA, err = configSHA(dir); err != nil {
		return fail(err)
	}
	return c, nil
}

// configSHA is the SHA-256 of the copy's git configuration. A .git/commondir
// (which would make git read another configuration) is refused.
func configSHA(dir string) (string, error) {
	if _, err := os.Lstat(filepath.Join(dir, ".git", "commondir")); err == nil {
		return "", ErrCopyTampered
	}
	b, err := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if err != nil {
		return "", fmt.Errorf("Michel cannot read the git configuration of the fix copy: %w", noPath(err))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// checkCopy checks that c is a fix copy whose git configuration is the one
// Prepare recorded.
func checkCopy(c Copy) error {
	if err := copyDir(c.Dir); err != nil {
		return err
	}
	got, err := configSHA(c.Dir)
	if err != nil {
		return err
	}
	if c.ConfigSHA == "" || got != c.ConfigSHA {
		return ErrCopyTampered
	}
	return nil
}

// copyDir checks that dir is a fix copy: an absolute
// .../worktrees/<project id>/<attempt id> folder holding a .git folder.
func copyDir(dir string) error {
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return ErrNotACopy
	}
	attempt, projectDir := filepath.Base(dir), filepath.Dir(dir)
	if !idShape.MatchString(attempt) || !idShape.MatchString(filepath.Base(projectDir)) || filepath.Base(filepath.Dir(projectDir)) != "worktrees" {
		return ErrNotACopy
	}
	if info, err := os.Lstat(filepath.Join(dir, ".git")); err != nil || !info.IsDir() {
		return ErrNotACopy
	}
	return nil
}

// Remove deletes the fix copy c, and nothing that is not a fix copy.
func Remove(c Copy) error {
	if err := copyDir(c.Dir); err != nil {
		return err
	}
	if err := os.RemoveAll(c.Dir); err != nil {
		return fmt.Errorf("Michel cannot delete the fix copy: %w", noPath(err))
	}
	// The project's folder of copies goes when it is empty.
	_ = os.Remove(filepath.Dir(c.Dir))
	return nil
}
