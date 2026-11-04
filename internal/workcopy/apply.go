package workcopy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

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
	// ErrExcludedPath: the change touches a file left out of the copy (a
	// .env, a key, an excluded folder, in any case).
	ErrExcludedPath = errors.New("the change touches a file Michel keeps out of the copy")
	// ErrBinaryChange: a text file would be shown as a binary change, so
	// its content would not be visible before validation.
	ErrBinaryChange = errors.New("a text file of the change would be shown as binary")
	// ErrInvalidCommit: not a fix commit of the mirror (full id, exactly one
	// parent, Base).
	ErrInvalidCommit = errors.New("invalid fix commit")
)

// gitShortName is the 8.3 short name of .git (GIT~1, GIT~2...).
var gitShortName = regexp.MustCompile(`^git~[0-9]+$`)

// reservedName is a Windows device name, with or without extension.
var reservedName = regexp.MustCompile(`^(?:con|prn|aux|nul|com[0-9]|lpt[0-9]|conin\$|conout\$)$`)

// safeSegment reports whether one path segment is a plain name on every
// file system, read the way NTFS reads it (trailing dots and spaces
// dropped): not empty, ".", "..", .git (any case) or its short name, not a
// Windows device name (CON, NUL.txt...), without a backslash, a colon (an
// alternate data stream), a control character or <>"|?*.
func safeSegment(seg string) bool {
	if strings.ContainsAny(seg, "\\:<>\"|?*") || strings.ContainsFunc(seg, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return false
	}
	n := strings.ToLower(strings.TrimRight(seg, ". "))
	if n == "" || n == ".git" || gitShortName.MatchString(n) {
		return false
	}
	stem, _, _ := strings.Cut(n, ".")
	return !reservedName.MatchString(strings.TrimRight(stem, " "))
}

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
	bad := p == "" || strings.HasPrefix(p, "/") || !filepath.IsLocal(filepath.FromSlash(p))
	for _, seg := range strings.Split(p, "/") {
		if !safeSegment(seg) {
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
	entries, err := h.changedEntries(ctx, d, repo, from, to)
	if err != nil {
		return nil, err
	}
	files := []string{}
	for _, e := range entries {
		files = append(files, e.path)
	}
	slices.Sort(files)
	return files, nil
}

// changedEntries lists the entries changed between two revisions of repo
// (to "" means the index), each checked by checkEntry.
func (h home) changedEntries(ctx context.Context, d Deps, repo, from, to string) ([]rawEntry, error) {
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
	for _, e := range entries {
		if err := checkEntry(e); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// shortName is a segment shaped like an 8.3 short name (PRIVAT~1,
// SERVER~1.KEY): Windows would read it as another, maybe excluded, name.
var shortName = regexp.MustCompile(`~[0-9]+(?:\.[^/]*)?(?:/|$)`)

// checkExcluded refuses a change touching an excluded file: a name or
// folder of the exclusions, or a file of c.Excluded, ignoring case.
func checkExcluded(c Copy, files []string) error {
	for _, f := range files {
		bad := isExcluded(f, c.Exclude) || shortName.MatchString(f)
		for _, x := range c.Excluded {
			if strings.EqualFold(f, x) {
				bad = true
			}
		}
		if bad {
			return fmt.Errorf("%w: %s", ErrExcludedPath, scan.SanitizeText(strings.ToValidUTF8(f, "")))
		}
	}
	return nil
}

// checkBinary refuses a binary change of a file whose new content (in dir,
// read through an os.Root of it) is text: valid UTF-8 without a NUL byte.
// A deleted file (deleted[p]) is not checked; any other file that cannot
// be read as a plain file of the copy is ErrOutsideCopy, one over
// maxCopyFile is ErrDiffTooLarge.
func checkBinary(dir string, paths []string, deleted map[string]bool) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return ErrNotACopy
	}
	defer root.Close()
	for _, p := range paths {
		if deleted[p] {
			continue
		}
		shown := scan.SanitizeText(strings.ToValidUTF8(p, ""))
		if info, err := root.Lstat(p); err == nil && info.Mode().IsRegular() && info.Size() > maxCopyFile {
			return fmt.Errorf("%w: %s", ErrDiffTooLarge, shown)
		}
		b, err := readIn(root, p, maxCopyFile)
		if err != nil {
			return fmt.Errorf("%w: %s cannot be read in the copy", ErrOutsideCopy, shown)
		}
		if utf8.Valid(b) && !bytes.Contains(b, []byte{0}) {
			return fmt.Errorf("%w: %s", ErrBinaryChange, scan.SanitizeText(strings.ToValidUTF8(p, "")))
		}
	}
	return nil
}

// binaryPaths are the paths git diff --numstat -z reports as binary.
func binaryPaths(out []byte) []string {
	var paths []string
	for _, e := range strings.Split(string(out), "\x00") {
		if strings.HasPrefix(e, "-\t-\t") {
			paths = append(paths, strings.TrimPrefix(e, "-\t-\t"))
		}
	}
	return paths
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

// stage restarts the copy's index from Root and adds every file (the
// excluded files left out): nothing the agent staged itself survives.
func (h home) stage(ctx context.Context, d Deps, c Copy) error {
	if _, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "read-tree", c.Root); err != nil {
		return gitErr("read-tree", err, stderr)
	}
	if _, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "add", append([]string{"-A", "--"}, c.pathspecs()...)...); err != nil {
		return gitErr("add", err, stderr)
	}
	return nil
}

// indexChange is the change of the copy's index against Root (see change).
func (h home) indexChange(ctx context.Context, d Deps, c Copy) (Change, error) {
	return h.change(ctx, d, c, "")
}

// change is the change of the copy against Root: of its index when to is
// "", of the tree object to otherwise (one immutable object: the entries,
// the patch and the text all come from it). It is checked: a path outside
// the copy, a symbolic link or a submodule is ErrOutsideCopy, an excluded
// file ErrExcludedPath, a text file shown as binary ErrBinaryChange.
func (h home) change(ctx context.Context, d Deps, c Copy, to string) (Change, error) {
	entries, err := h.changedEntries(ctx, d, c.Dir, c.Root, to)
	if err != nil {
		return Change{}, err
	}
	files, deleted := []string{}, map[string]bool{}
	for _, e := range entries {
		files = append(files, e.path)
		if e.mode == "000000" {
			deleted[e.path] = true
		}
	}
	slices.Sort(files)
	if err := checkExcluded(c, files); err != nil {
		return Change{}, err
	}
	common := []string{"--no-renames", "--no-ext-diff", "--no-textconv", "--no-color"}
	span := []string{"--cached", c.Root, "--"}
	if to != "" {
		span = []string{c.Root, to, "--"}
	}
	numstat, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "diff", slices.Concat(common, []string{"--numstat", "-z"}, span)...)
	if err != nil {
		return Change{}, gitErr("diff", err, stderr)
	}
	if to == "" {
		err = checkBinary(c.Dir, binaryPaths(numstat), deleted)
	} else {
		err = h.checkBinaryTree(ctx, d, c, to, binaryPaths(numstat), deleted)
	}
	if err != nil {
		return Change{}, err
	}
	raw, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "diff", slices.Concat(common, []string{"--binary"}, span)...)
	if err != nil {
		return Change{}, gitErr("diff", err, stderr)
	}
	// --text: whatever the attributes say, the text of every change is shown.
	text, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "diff", slices.Concat(common, []string{"--text"}, span)...)
	if err != nil {
		return Change{}, gitErr("diff", err, stderr)
	}
	if len(raw) >= maxGitOutput || len(text) >= maxGitOutput {
		return Change{}, ErrDiffTooLarge
	}
	return Change{Raw: raw, Display: scan.SanitizeText(strings.ToValidUTF8(string(text), "\uFFFD")), Files: files}, nil
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
	if err := h.stage(ctx, d, c); err != nil {
		return Change{}, err
	}
	return h.indexChange(ctx, d, c)
}

// checkBinaryTree is checkBinary for the content of a tree object: a
// binary change whose new content in the tree is text is ErrBinaryChange.
func (h home) checkBinaryTree(ctx context.Context, d Deps, c Copy, tree string, paths []string, deleted map[string]bool) error {
	for _, p := range paths {
		if deleted[p] {
			continue
		}
		shown := scan.SanitizeText(strings.ToValidUTF8(p, ""))
		b, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "show", tree+":"+p)
		if err != nil {
			return fmt.Errorf("%w: %s cannot be read in the snapshot (%v)", ErrOutsideCopy, shown, gitErr("show", err, stderr))
		}
		if len(b) >= maxGitOutput {
			return fmt.Errorf("%w: %s", ErrDiffTooLarge, shown)
		}
		if utf8.Valid(b) && !bytes.Contains(b, []byte{0}) {
			return fmt.Errorf("%w: %s", ErrBinaryChange, shown)
		}
	}
	return nil
}

// commitMatches checks that the fix commit sha of the mirror holds exactly
// the snapshot's change: the same changed paths as snap.Change.Files
// (Base to sha), and for each of them the same blob as the snapshot's tree
// (none on both sides for a deleted file).
func (h home) commitMatches(ctx context.Context, d Deps, c Copy, sha string, snap Snapshot) (bool, error) {
	files, err := h.checkRange(ctx, d, c.Mirror, c.Base, sha)
	if err != nil {
		return false, err
	}
	if !slices.Equal(files, snap.Change.Files) {
		return false, nil
	}
	blob := func(repo, rev, path string) (string, error) {
		out, stderr, err := h.git(ctx, d, repo, repo, nil, nil, "rev-parse", "--verify", "--quiet", "--end-of-options", rev+":"+path)
		if err != nil {
			if exitCode(err) == 1 || exitCode(err) == 128 {
				return "", nil // no such path in that tree
			}
			return "", gitErr("rev-parse", err, stderr)
		}
		id := strings.TrimSpace(string(out))
		if !shaShape.MatchString(id) {
			return "", errors.New("git rev-parse returned an unexpected object id")
		}
		return id, nil
	}
	for _, f := range files {
		inCommit, err := blob(c.Mirror, sha, f)
		if err != nil {
			return false, err
		}
		inSnapshot, err := blob(c.Dir, snap.Tree, f)
		if err != nil {
			return false, err
		}
		if inCommit != inSnapshot {
			return false, nil
		}
	}
	return true, nil
}

// commitPatch builds one commit in the private mirror: the tree of Base
// with the raw patch applied (a temporary index in the data folder, git
// apply --cached), parent Base, author and committer Michel. It returns
// that commit's id, checked by checkFixCommit.
func (h home) commitPatch(ctx context.Context, d Deps, c Copy, raw []byte, message string) (string, error) {
	message = strings.TrimSpace(scan.SanitizeText(strings.ToValidUTF8(message, "")))
	if message == "" {
		message = "fix: Michel"
	}
	tmp := tmpPath(d, filepath.Base(c.Dir))
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return "", fmt.Errorf("Michel cannot prepare the fix commit: %w", noPath(err))
	}
	index, patch := filepath.Join(tmp, "fix.index"), filepath.Join(tmp, "fix.patch")
	defer func() {
		_ = os.Remove(index)
		_ = os.Remove(patch)
		_ = os.Remove(tmp) // only when nothing else is left in it
	}()
	if err := os.WriteFile(patch, raw, 0o600); err != nil {
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

// Commit computes the change of the copy (as Diff) and builds one commit
// in the private mirror from it (commitPatch). Commits the agent made in
// its copy are ignored: nothing of them reaches the mirror.
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
	return h.commitPatch(ctx, d, c, ch.Raw, message)
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
	if err := checkExcluded(c, files); err != nil {
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

// IsMerged reports whether the change of the commit sha is in the current branch
// of the user's repository, reading only: the commit itself (git merge-base
// --is-ancestor sha HEAD), or, because "Squash" and "Rebase" on a host's site
// change the commit, the same exact change (git cherry HEAD sha sha^ marks it
// with "-"). A squash with other commits is not the same change. A commit the
// repository does not know is not merged.
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
		return h.sameChangeInHead(ctx, d, p, sha)
	default:
		return false, gitErr("merge-base", err, stderr)
	}
}

// sameChangeInHead reports whether HEAD holds the exact change of the commit sha:
// git cherry answers in exactly one line, starting with "- ". A commit without a
// parent has no change to compare.
func (h home) sameChangeInHead(ctx context.Context, d Deps, p project.Project, sha string) (bool, error) {
	parent := sha + "^"
	if got, err := h.revParseCommit(ctx, d, p.Path, parent); err != nil || got == "" {
		return false, err
	}
	out, stderr, err := h.git(ctx, d, d.DataDir, p.Path, nil, nil, "cherry", "HEAD", sha, parent)
	if err != nil {
		return false, gitErr("cherry", err, stderr)
	}
	line, rest, _ := strings.Cut(string(out), "\n")
	return rest == "" && strings.HasPrefix(line, "- "), nil
}
