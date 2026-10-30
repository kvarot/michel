package workcopy

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
)

var (
	// ErrOutsideCopy: the change touches a path outside the copy (absolute,
	// "..", under .git) or adds a symbolic link or a submodule.
	ErrOutsideCopy = errors.New("the change touches a file outside the copy")
	// ErrDiffTooLarge: the change is too large to be shown in full.
	ErrDiffTooLarge = errors.New("the change is too large to be shown")
	// ErrNothingToCommit: the copy holds no change.
	ErrNothingToCommit = errors.New("the copy holds no change")
	// ErrInvalidBranch: a branch name other than michel/fix-<short id>.
	ErrInvalidBranch = errors.New("invalid fix branch name")
	// ErrBranchExists: the fix branch already exists in the project.
	ErrBranchExists = errors.New("the fix branch already exists in the project")
	// ErrInvalidCommit: not a full commit id of the copy that descends from
	// its base.
	ErrInvalidCommit = errors.New("invalid fix commit")
)

// branchShape is the only branch name Apply creates.
var branchShape = regexp.MustCompile(`^michel/fix-[0-9a-z]{8,26}$`)

// rawEntry is one line of git diff --raw: the path and its new mode.
type rawEntry struct{ path, mode string }

// parseRaw reads git diff --raw -z --no-renames output.
func parseRaw(out []byte) ([]rawEntry, error) {
	fields := strings.Split(string(out), "\x00")
	var entries []rawEntry
	for i := 0; i < len(fields); i++ {
		meta := fields[i]
		if meta == "" {
			continue
		}
		parts := strings.Fields(strings.TrimPrefix(meta, ":"))
		if !strings.HasPrefix(meta, ":") || len(parts) != 5 || i+1 >= len(fields) {
			return nil, errors.New("git diff returned an unexpected listing")
		}
		i++
		entries = append(entries, rawEntry{path: fields[i], mode: parts[1]})
	}
	return entries, nil
}

// checkEntry refuses a changed path that is not a plain file or folder
// path inside the copy: absolute, with a drive, a backslash, "." or ".."
// segments, under a .git folder (any case, or its short name), or a new
// symbolic link (120000) or submodule (160000).
func checkEntry(e rawEntry) error {
	p := e.path
	bad := p == "" || strings.ContainsAny(p, "\\:\x00") || strings.HasPrefix(p, "/") || !filepath.IsLocal(filepath.FromSlash(p))
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.EqualFold(seg, ".git") || strings.EqualFold(seg, "git~1") {
			bad = true
		}
	}
	if e.mode == "120000" || e.mode == "160000" {
		bad = true
	}
	if bad {
		return fmt.Errorf("%w: %s", ErrOutsideCopy, scan.SanitizeText(strings.ToValidUTF8(p, "")))
	}
	return nil
}

// checkRange checks every path changed between two revisions of the copy
// (to "" means the index) and returns them, sorted.
func (h home) checkRange(ctx context.Context, d Deps, c Copy, from, to string) ([]string, error) {
	args := []string{"--raw", "-z", "--no-renames", "--no-ext-diff", "--no-textconv"}
	if to == "" {
		args = append(args, "--cached", from)
	} else {
		args = append(args, from, to)
	}
	out, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "diff", append(args, "--")...)
	if err != nil {
		return nil, gitErr("diff", err, stderr)
	}
	if len(out) >= maxGitOutput {
		return nil, ErrDiffTooLarge
	}
	entries, err := parseRaw(out)
	if err != nil {
		return nil, err
	}
	files := []string{}
	for _, e := range entries {
		if err := checkEntry(e); err != nil {
			return nil, err
		}
		files = append(files, e.path)
	}
	slices.Sort(files)
	return files, nil
}

// Diff stages every change of the copy (git add -A, the excluded files
// left out) and returns the diff against c.Base, computed by Michel and
// sanitized for display, with the changed files (slash paths, sorted). A
// path outside the copy, a symbolic link or a submodule is ErrOutsideCopy.
func Diff(ctx context.Context, d Deps, c Copy) (diff string, files []string, err error) {
	if err := checkCopy(c); err != nil {
		return "", nil, err
	}
	if !shaShape.MatchString(c.Base) {
		return "", nil, ErrInvalidCommit
	}
	h, err := ensureHome(d)
	if err != nil {
		return "", nil, err
	}
	if _, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "add", append([]string{"-A", "--"}, excludePathspecs(c.Exclude)...)...); err != nil {
		return "", nil, gitErr("add", err, stderr)
	}
	files, err = h.checkRange(ctx, d, c, c.Base, "")
	if err != nil {
		return "", nil, err
	}
	out, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "diff",
		"--cached", "--no-renames", "--no-ext-diff", "--no-textconv", "--no-color", c.Base, "--")
	if err != nil {
		return "", nil, gitErr("diff", err, stderr)
	}
	if len(out) >= maxGitOutput {
		return "", nil, ErrDiffTooLarge
	}
	return scan.SanitizeText(strings.ToValidUTF8(string(out), "�")), files, nil
}

// Commit stages and checks the change of the copy (as Diff), commits it as
// Michel and returns the commit id. The committed tree is checked again
// against c.Base.
func Commit(ctx context.Context, d Deps, c Copy, message string) (string, error) {
	_, files, err := Diff(ctx, d, c)
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", ErrNothingToCommit
	}
	h, err := ensureHome(d)
	if err != nil {
		return "", err
	}
	message = strings.TrimSpace(scan.SanitizeText(strings.ToValidUTF8(message, "")))
	if message == "" {
		message = "fix: Michel"
	}
	date := d.now().UTC().Format(time.RFC3339)
	ident := []string{"GIT_AUTHOR_NAME=Michel", "GIT_AUTHOR_EMAIL=michel@localhost", "GIT_AUTHOR_DATE=" + date,
		"GIT_COMMITTER_NAME=Michel", "GIT_COMMITTER_EMAIL=michel@localhost", "GIT_COMMITTER_DATE=" + date}
	if _, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, ident, "commit", "--quiet", "--no-verify", "--no-gpg-sign", "-m", message); err != nil {
		return "", gitErr("commit", err, stderr)
	}
	sha, err := h.revParseCommit(ctx, d, c.Dir, "HEAD")
	if err != nil {
		return "", err
	}
	if sha == "" || sha == c.Base {
		return "", ErrNothingToCommit
	}
	if _, err := h.checkRange(ctx, d, c, c.Base, sha); err != nil {
		return "", err
	}
	return sha, nil
}

// Apply creates branch (michel/fix-<short id>, which must not exist) in the
// user's repository, pointing to the commit sha of the copy:
// git -C <project> fetch --no-tags --no-write-fetch-head <copy> <sha>:refs/heads/<branch>.
// It is the only write Michel makes in the project: git objects and that
// one ref in its .git. No checkout, merge, reset or stash: the user's
// working tree, index, HEAD and current branch are untouched.
func Apply(ctx context.Context, d Deps, p project.Project, c Copy, sha, branch string) error {
	if !branchShape.MatchString(branch) {
		return ErrInvalidBranch
	}
	if !shaShape.MatchString(sha) || !shaShape.MatchString(c.Base) || sha == c.Base {
		return ErrInvalidCommit
	}
	if err := checkCopy(c); err != nil {
		return err
	}
	if !filepath.IsAbs(p.Path) || !IsGitRepo(p.Path) {
		return ErrNotGitRepo
	}
	h, err := ensureHome(d)
	if err != nil {
		return err
	}
	// The commit is one of the copy's, made on top of its base, and its
	// change stays inside the copy.
	if got, err := h.revParseCommit(ctx, d, c.Dir, sha); err != nil {
		return err
	} else if got != sha {
		return ErrInvalidCommit
	}
	if _, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "merge-base", "--is-ancestor", c.Base, sha); err != nil {
		if exitCode(err) == 1 {
			return ErrInvalidCommit
		}
		return gitErr("merge-base", err, stderr)
	}
	if _, err := h.checkRange(ctx, d, c, c.Base, sha); err != nil {
		return err
	}
	ref := "refs/heads/" + branch
	if _, stderr, err := h.git(ctx, d, d.DataDir, p.Path, nil, nil, "rev-parse", "--verify", "--quiet", "--end-of-options", ref); err == nil {
		return ErrBranchExists
	} else if exitCode(err) != 1 {
		return gitErr("rev-parse", err, stderr)
	}
	if _, stderr, err := h.git(ctx, d, d.DataDir, p.Path, localTransport, nil, "fetch",
		"--quiet", "--no-tags", "--no-write-fetch-head", "--no-auto-maintenance", "--no-recurse-submodules",
		c.Dir, sha+":"+ref); err != nil {
		return gitErr("fetch", err, stderr)
	}
	got, err := h.revParseCommit(ctx, d, p.Path, ref)
	if err != nil {
		return err
	}
	if got != sha {
		return fmt.Errorf("the branch %s does not point to the fix commit after the fetch", branch)
	}
	return nil
}

// IsMerged reports whether the commit sha is contained in the current
// branch of the user's repository (git merge-base --is-ancestor sha HEAD),
// reading only. A commit the repository does not know is not merged.
func IsMerged(ctx context.Context, d Deps, p project.Project, sha string) (bool, error) {
	if !shaShape.MatchString(sha) {
		return false, ErrInvalidCommit
	}
	if !filepath.IsAbs(p.Path) || !IsGitRepo(p.Path) {
		return false, ErrNotGitRepo
	}
	h, err := ensureHome(d)
	if err != nil {
		return false, err
	}
	if got, err := h.revParseCommit(ctx, d, p.Path, sha); err != nil || got == "" {
		return false, err
	}
	_, stderr, err := h.git(ctx, d, d.DataDir, p.Path, nil, nil, "merge-base", "--is-ancestor", sha, "HEAD")
	switch {
	case err == nil:
		return true, nil
	case exitCode(err) == 1:
		return false, nil
	default:
		return false, gitErr("merge-base", err, stderr)
	}
}
