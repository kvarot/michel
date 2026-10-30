package workcopy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

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
	// ErrInvalidCommit: not a fix commit of the mirror (full id, exactly one
	// parent, Base).
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

// checkRange checks every path changed between two revisions of repo (to
// "" means the index) and returns them, sorted.
func (h home) checkRange(ctx context.Context, d Deps, repo, from, to string) ([]string, error) {
	args := []string{"--raw", "-z", "--no-renames", "--no-ext-diff", "--no-textconv"}
	if to == "" {
		args = append(args, "--cached", from)
	} else {
		args = append(args, from, to)
	}
	out, stderr, err := h.git(ctx, d, repo, repo, nil, nil, "diff", append(args, "--")...)
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

// Change is the change of a fix copy, computed by Michel.
type Change struct {
	// Raw is the binary patch (git diff --binary) from the copy's base to
	// its working tree: the exact bytes Commit applies. A proposal's
	// fingerprint hashes Raw, never Display.
	Raw []byte
	// Display is the text diff for people: binary files summarized,
	// sanitized (scan.SanitizeText). Shown, never hashed.
	Display string
	// Files are the changed paths (slash paths, sorted).
	Files []string
}

// Diff stages every change of the agent's copy (git add -A, the excluded
// files left out) and returns it against the copy's base commit c.Root:
// whatever the agent committed in the copy, the change is its working
// tree. A path outside the copy, a symbolic link or a submodule is
// ErrOutsideCopy.
func Diff(ctx context.Context, d Deps, c Copy) (Change, error) {
	if err := checkCopy(d, c); err != nil {
		return Change{}, err
	}
	if !shaShape.MatchString(c.Root) {
		return Change{}, ErrInvalidCommit
	}
	h, err := ensureHome(d)
	if err != nil {
		return Change{}, err
	}
	if _, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "add", append([]string{"-A", "--"}, excludePathspecs(c.Exclude)...)...); err != nil {
		return Change{}, gitErr("add", err, stderr)
	}
	files, err := h.checkRange(ctx, d, c.Dir, c.Root, "")
	if err != nil {
		return Change{}, err
	}
	common := []string{"--cached", "--no-renames", "--no-ext-diff", "--no-textconv", "--no-color"}
	raw, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "diff", append(common, "--binary", c.Root, "--")...)
	if err != nil {
		return Change{}, gitErr("diff", err, stderr)
	}
	text, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "diff", append(common, c.Root, "--")...)
	if err != nil {
		return Change{}, gitErr("diff", err, stderr)
	}
	if len(raw) >= maxGitOutput || len(text) >= maxGitOutput {
		return Change{}, ErrDiffTooLarge
	}
	return Change{Raw: raw, Display: scan.SanitizeText(strings.ToValidUTF8(string(text), "\uFFFD")), Files: files}, nil
}

// Commit computes the change of the copy (as Diff) and builds one commit
// in the private mirror: the tree of Base with the change applied (a
// temporary index in the data folder, git apply --cached), parent Base,
// author and committer Michel. It returns that commit's id. Commits the
// agent made in its copy are ignored: nothing of them reaches the mirror.
func Commit(ctx context.Context, d Deps, c Copy, message string) (string, error) {
	ch, err := Diff(ctx, d, c)
	if err != nil {
		return "", err
	}
	if len(ch.Files) == 0 {
		return "", ErrNothingToCommit
	}
	if !shaShape.MatchString(c.Base) {
		return "", ErrInvalidCommit
	}
	h, err := ensureHome(d)
	if err != nil {
		return "", err
	}
	message = strings.TrimSpace(scan.SanitizeText(strings.ToValidUTF8(message, "")))
	if message == "" {
		message = "fix: Michel"
	}
	index, patch := c.Dir+".index", c.Dir+".patch"
	defer os.Remove(index)
	defer os.Remove(patch)
	_ = os.Remove(index)
	_ = os.Remove(patch)
	if err := os.WriteFile(patch, ch.Raw, 0o600); err != nil {
		return "", fmt.Errorf("Michel cannot prepare the fix commit: %w", noPath(err))
	}
	withIndex := []string{"GIT_INDEX_FILE=" + index}
	if _, stderr, err := h.git(ctx, d, c.Mirror, c.Mirror, nil, withIndex, "read-tree", c.Base); err != nil {
		return "", gitErr("read-tree", err, stderr)
	}
	if _, stderr, err := h.git(ctx, d, c.Mirror, c.Mirror, nil, withIndex, "apply", "--cached", "--binary", "--whitespace=nowarn", patch); err != nil {
		return "", gitErr("apply", err, stderr)
	}
	out, stderr, err := h.git(ctx, d, c.Mirror, c.Mirror, nil, withIndex, "write-tree")
	if err != nil {
		return "", gitErr("write-tree", err, stderr)
	}
	tree := strings.TrimSpace(string(out))
	if !shaShape.MatchString(tree) {
		return "", errors.New("git write-tree returned an unexpected tree id")
	}
	out, stderr, err = h.git(ctx, d, c.Mirror, c.Mirror, nil, michelIdent(d), "commit-tree", tree, "-p", c.Base, "-m", message)
	if err != nil {
		return "", gitErr("commit-tree", err, stderr)
	}
	sha := strings.TrimSpace(string(out))
	if !shaShape.MatchString(sha) {
		return "", errors.New("git commit-tree returned an unexpected commit id")
	}
	if err := h.checkFixCommit(ctx, d, c, sha); err != nil {
		return "", err
	}
	return sha, nil
}

// checkFixCommit checks that sha is a commit of the mirror with exactly one
// parent, Base, and a change that stays inside the copy.
func (h home) checkFixCommit(ctx context.Context, d Deps, c Copy, sha string) error {
	if got, err := h.revParseCommit(ctx, d, c.Mirror, sha); err != nil {
		return err
	} else if got != sha {
		return ErrInvalidCommit
	}
	out, stderr, err := h.git(ctx, d, c.Mirror, c.Mirror, nil, nil, "rev-parse", sha+"^@") // sha is a validated full id
	if err != nil {
		return gitErr("rev-parse", err, stderr)
	}
	if parents := strings.Fields(string(out)); len(parents) != 1 || parents[0] != c.Base {
		return ErrInvalidCommit
	}
	files, err := h.checkRange(ctx, d, c.Mirror, c.Base, sha)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return ErrNothingToCommit
	}
	return nil
}

// Apply creates branch (michel/fix-<short id>, which must not exist) in the
// user's repository, pointing to the fix commit sha of the mirror:
// git -C <project> fetch --no-tags --no-write-fetch-head <mirror> <sha>:refs/heads/<branch>.
// The commit must have exactly one parent, Base, and a change inside the
// copy. It is the only write Michel makes in the project: git objects and
// that one ref in its .git. No checkout, merge, reset or stash: the user's
// working tree, index, HEAD and current branch are untouched.
func Apply(ctx context.Context, d Deps, p project.Project, c Copy, sha, branch string) error {
	if !branchShape.MatchString(branch) {
		return ErrInvalidBranch
	}
	if !shaShape.MatchString(sha) || !shaShape.MatchString(c.Base) || sha == c.Base {
		return ErrInvalidCommit
	}
	if err := checkCopy(d, c); err != nil {
		return err
	}
	if !filepath.IsAbs(p.Path) || !IsGitRepo(p.Path) {
		return ErrNotGitRepo
	}
	h, err := ensureHome(d)
	if err != nil {
		return err
	}
	if err := h.checkFixCommit(ctx, d, c, sha); err != nil {
		return err
	}
	ref := "refs/heads/" + branch
	if _, stderr, err := h.git(ctx, d, d.DataDir, p.Path, nil, nil, "rev-parse", "--verify", "--quiet", "--end-of-options", ref); err == nil {
		return ErrBranchExists
	} else if exitCode(err) != 1 {
		return gitErr("rev-parse", err, stderr)
	}
	// The fix commit has no ref in the mirror: its upload-pack must accept a
	// want of any object (git passes -c options on to it).
	fetchCfg := append(append([]string{}, localTransport...), "-c", "uploadpack.allowAnySHA1InWant=true")
	if _, stderr, err := h.git(ctx, d, d.DataDir, p.Path, fetchCfg, nil, "fetch",
		"--quiet", "--no-tags", "--no-write-fetch-head", "--no-auto-maintenance", "--no-recurse-submodules",
		c.Mirror, sha+":"+ref); err != nil {
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
