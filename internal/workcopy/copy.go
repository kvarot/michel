package workcopy

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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
	// ErrCopyTooLarge: the project's files exceed the limits of a copy.
	ErrCopyTooLarge = errors.New("the project is too large for a fix copy")
)

// Copy is the fix copy of one attempt. It is two folders of the data
// folder, in separate trees:
//   - Mirror, <data>/fix-mirrors/<project id>/<attempt id>.git: a bare
//     clone of the user's repository (every blob, the excluded ones too),
//     private to Michel and never in or next to the agent's copy, where the
//     fix commit is built and from which it is fetched;
//   - Dir, <data>/worktrees/<project id>/<attempt id>: the agent's copy, a
//     fresh repository holding the files of Base minus the excluded ones
//     and one synthetic commit (Root). It has no history, no excluded
//     blob, no remote and no absolute path.
type Copy struct {
	Dir    string
	Mirror string `json:"-"`
	// Base is the commit of the project's HEAD the copy was made from.
	Base string
	// Root is the synthetic commit "michel: base" of the agent's copy: the
	// change is the copy's working tree against it.
	Root string
	// Excluded lists the files of Base left out of the copy (slash paths,
	// sorted). They stay unchanged in the fix commit.
	Excluded []string
	// Exclude repeats the project's excluded folder names, so that a new
	// file under one of them never becomes part of the change.
	Exclude []string
	// InstallDirs are the folders Michel's own installs fill in the copy
	// (vendor next to a composer.json or composer.lock, node_modules next
	// to a package.json or package-lock.json) under which Base tracks no
	// file (slash paths, sorted). Michel's output, never the agent's (it
	// cannot write there) nor the user's: removed from the copy after
	// Michel's update and left out of every add, tree and archive, so that
	// it never becomes part of a change.
	InstallDirs []string `json:",omitempty"`
	// SecretHits are the secrets the detectors found in the files of the
	// copy (file, line and kind, never the value).
	SecretHits []mask.Hit
	// ConfigSHA is the SHA-256 of the copy's .git/config and
	// .git/info/attributes as Michel made them. Diff, Commit and Apply
	// refuse a copy whose configuration changed since (an agent could add
	// a filter or a driver that git would run).
	ConfigSHA string
}

// idShape is a project or attempt id usable as a folder name (a ULID).
var idShape = regexp.MustCompile(`^[0-9A-Za-z]{1,64}$`)

// excludedFiles are the file name patterns never copied, at any depth.
var excludedFiles = []string{".env*", "*.pem", "*.key", "id_*"}

// Limits of a copy: per file, in all, and in number of files (excluded
// files not counted). They are checked on the tree of Base (git ls-tree)
// before anything is archived, and again while extracting. Variables so
// that tests can lower them.
var (
	maxCopyFile  int64 = 256 << 20
	maxCopyTotal int64 = 4 << 30
	maxCopyFiles       = 30000
)

// listingCap is the longest ls-tree listing read: 256 bytes per allowed
// file (about 60 bytes plus the path each). With 30,000 files it is 7.5
// MiB, below maxGitOutput (8 MiB), so a longer listing is refused as
// ErrCopyTooLarge before the output cap cuts it.
func listingCap() int { return maxCopyFiles * 256 }

// plainAttributes turn off, for every path, what git would otherwise do
// to a file's bytes or presence between the repository and the disk:
// export-ignore and export-subst (archive), end-of-line conversion,
// filters, ident and re-encoding. Written in the info/attributes of the
// mirror and of the copy, it wins over the project's .gitattributes.
// "!diff" drops any diff attribute of the project (a "-diff" would show a
// text change as "Binary files differ").
const plainAttributes = "* -export-ignore -export-subst -text -eol -filter -ident -working-tree-encoding !diff\n"

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

// excludePathspecs keep the excluded files out of git add in the copy: a
// file the agent creates there (a new .env, a key) never becomes part of
// the change. installDirs (Copy.InstallDirs) are left out too: what
// Michel's install writes there is never part of a change.
func excludePathspecs(exclude, installDirs []string) []string {
	out := []string{"."}
	for _, p := range excludedFiles {
		out = append(out, ":(exclude,glob,icase)**/"+p)
	}
	for _, n := range exclude {
		out = append(out, ":(exclude,glob,icase)**/"+n+"/**")
	}
	for _, d := range installDirs {
		out = append(out, ":(exclude,glob,icase)"+d+"/**")
	}
	return out
}

// pathspecs are the pathspecs of every add, tree and archive of c.
func (c Copy) pathspecs() []string { return excludePathspecs(c.Exclude, c.InstallDirs) }

// installOutputs maps a manifest or lockfile name to the folder its
// install fills next to it.
var installOutputs = map[string]string{
	"composer.json": "vendor", "composer.lock": "vendor",
	"package.json": "node_modules", "package-lock.json": "node_modules",
}

// installDirs lists, from the files tracked by Base (slash paths), the
// install output folders next to a manifest or lockfile under which Base
// tracks no file (Copy.InstallDirs), sorted. A folder whose name could
// not be a plain pathspec is left out (its files then stay visible).
func installDirs(tracked []string) []string {
	cand := map[string]bool{}
	for _, name := range tracked {
		out, ok := installOutputs[strings.ToLower(path.Base(name))]
		if !ok {
			continue
		}
		if dir := path.Dir(name); dir != "." {
			out = dir + "/" + out
		}
		cand[out] = true
	}
	dirs := []string{}
	for f := range cand {
		plain := true
		for _, seg := range strings.Split(f, "/") {
			if !safeSegment(seg) || strings.ContainsAny(seg, "[]*?!") {
				plain = false
			}
		}
		if !plain {
			continue
		}
		prefix := strings.ToLower(f) + "/"
		if slices.ContainsFunc(tracked, func(n string) bool { return strings.HasPrefix(strings.ToLower(n), prefix) }) {
			continue // the user's own files: they stay part of the copy
		}
		dirs = append(dirs, f)
	}
	slices.Sort(dirs)
	return dirs
}

// removeInstallOutput deletes the folders dirs (Copy.InstallDirs) from the
// copy through its root: a link (or junction) is removed itself, never
// followed.
func removeInstallOutput(root *os.Root, dirs []string) error {
	var errs []error
	for _, d := range dirs {
		info, err := root.Lstat(d)
		if err != nil {
			continue
		}
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			err = root.Remove(d)
		} else {
			err = root.RemoveAll(d)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("Michel cannot remove %s from the copy: %w", d, noPath(err)))
		}
	}
	return errors.Join(errs...)
}

// isExcluded reports whether the slash path of a file, rel, is left out of
// a copy, ignoring case (.ENV and SERVER.KEY are excluded too: Windows and
// macOS file systems do not tell them apart).
func isExcluded(rel string, exclude []string) bool {
	segs := strings.Split(strings.ToLower(rel), "/")
	// Read the way NTFS reads names: ".ENV." is .env.
	for i, s := range segs {
		segs[i] = strings.TrimRight(s, ". ")
	}
	base := segs[len(segs)-1]
	for _, p := range excludedFiles {
		if ok, _ := path.Match(p, base); ok {
			return true
		}
	}
	return inExcludedFolder(segs[:len(segs)-1], exclude)
}

// inExcludedFolder reports whether one of the folder names segs is an
// excluded folder, ignoring case.
func inExcludedFolder(segs, exclude []string) bool {
	for _, s := range segs {
		for _, n := range exclude {
			if strings.EqualFold(s, n) {
				return true
			}
		}
	}
	return false
}

// checkTreeSize refuses a Base tree over the limits of a copy, before
// anything is archived: git ls-tree -r -l of the mirror. It returns the
// excluded files of the tree (slash paths, sorted), which the archive will
// not hold, the number of files the copy will hold, and the install output
// folders Base tracks nothing under (installDirs).
func (h home) checkTreeSize(ctx context.Context, d Deps, mirror, base string, exclude []string) (excluded []string, files int, outputs []string, err error) {
	out, stderr, err := h.git(ctx, d, mirror, mirror, nil, nil, "ls-tree", "-r", "-l", "-z", "--full-tree", base)
	if err != nil {
		return nil, 0, nil, gitErr("ls-tree", err, stderr)
	}
	if len(out) >= maxGitOutput || len(out) > listingCap() {
		return nil, 0, nil, ErrCopyTooLarge
	}
	var total int64
	var tracked []string
	excluded = []string{}
	for _, e := range strings.Split(string(out), "\x00") {
		meta, name, ok := strings.Cut(e, "\t")
		if !ok {
			continue
		}
		f := strings.Fields(meta) // mode type id size
		if len(f) != 4 || f[1] != "blob" {
			continue
		}
		tracked = append(tracked, name)
		if isExcluded(name, exclude) {
			excluded = append(excluded, name)
			continue
		}
		size, err := strconv.ParseInt(f[3], 10, 64)
		if err != nil {
			return nil, 0, nil, errors.New("git ls-tree returned an unexpected listing")
		}
		files++
		total += size
		if size > maxCopyFile || total > maxCopyTotal || files > maxCopyFiles {
			return nil, 0, nil, ErrCopyTooLarge
		}
	}
	slices.Sort(excluded)
	return excluded, files, installDirs(tracked), nil
}

// validFolderName reports whether n is a plain folder name (project.Exclude
// is validated when stored; checked again before it reaches git).
func validFolderName(n string) bool {
	return n != "" && n != "." && n != ".." && !strings.ContainsAny(n, "/\\:*?[]!\n\r\x00") && filepath.IsLocal(n)
}

// michelIdent is the author and committer of every commit Michel makes.
func michelIdent(d Deps) []string {
	date := d.now().UTC().Format("2006-01-02T15:04:05Z")
	return []string{"GIT_AUTHOR_NAME=Michel", "GIT_AUTHOR_EMAIL=michel@localhost", "GIT_AUTHOR_DATE=" + date,
		"GIT_COMMITTER_NAME=Michel", "GIT_COMMITTER_EMAIL=michel@localhost", "GIT_COMMITTER_DATE=" + date}
}

// Prepare makes the fix copy of attempt attemptID of p: a private bare
// mirror of the project (git clone --bare --local --no-hardlinks, which
// only reads p.Path), then the agent's copy, a fresh repository filled from
// git archive of the project's HEAD commit without the excluded files
// (.env*, *.pem, *.key, id_*, the folders of p.Exclude), symbolic links or
// special files, and one synthetic commit. git runs without hooks, file
// system monitor, automatic gc, system or global configuration. The secret
// detectors run on the files of the copy.
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
	c := Copy{Dir: filepath.Join(parent, attemptID), Mirror: mirrorPath(d, p.ID, attemptID), Base: base, Exclude: exclude}
	tmp := tmpPath(d, attemptID)
	for _, f := range []string{c.Dir, c.Mirror, tmp} {
		if _, err := os.Lstat(f); err == nil {
			return Copy{}, ErrCopyExists
		}
	}
	for _, f := range []string{filepath.Dir(c.Mirror), tmp} {
		if err := os.MkdirAll(f, 0o700); err != nil {
			return Copy{}, fmt.Errorf("Michel cannot create the fix copy: %w", noPath(err))
		}
	}
	archive := filepath.Join(tmp, "base.tar")
	defer os.RemoveAll(tmp)
	fail := func(err error) (Copy, error) {
		_ = os.RemoveAll(c.Dir)
		_ = os.RemoveAll(c.Mirror)
		return Copy{}, err
	}
	if _, stderr, err := h.git(ctx, d, filepath.Dir(c.Mirror), "", localTransport, nil,
		"clone", "--bare", "--local", "--no-hardlinks", "--quiet", "--", p.Path, c.Mirror); err != nil {
		return fail(gitErr("clone", err, stderr))
	}
	if err := writeAttributes(c.Mirror); err != nil {
		return fail(err)
	}
	excluded, files, outputs, err := h.checkTreeSize(ctx, d, c.Mirror, base, exclude)
	if err != nil {
		return fail(err)
	}
	c.InstallDirs = outputs
	// The archive holds only the counted files: the excluded ones are left
	// out by pathspec (extract leaves them out again, should one slip
	// through). With no file to copy (an empty tree, or only excluded
	// files) git archive would fail on the pathspec: the copy starts empty.
	if files > 0 {
		if _, stderr, err := h.git(ctx, d, tmp, c.Mirror, nil, nil, "archive",
			append([]string{"--format=tar", "-o", archive, base, "--"}, c.pathspecs()...)...); err != nil {
			return fail(gitErr("archive", err, stderr))
		}
	}
	if _, stderr, err := h.git(ctx, d, parent, "", nil, nil, "init", "--quiet", "--template=", "--initial-branch=main", c.Dir); err != nil {
		return fail(gitErr("init", err, stderr))
	}
	if err := writeAttributes(filepath.Join(c.Dir, ".git")); err != nil {
		return fail(err)
	}
	var kept, slipped []string
	if files > 0 {
		if kept, slipped, err = extract(archive, c.Dir, exclude); err != nil {
			return fail(err)
		}
	}
	excluded = append(excluded, slipped...)
	slices.Sort(excluded)
	c.Excluded = slices.Compact(excluded)
	if _, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "add", append([]string{"-A", "--"}, c.pathspecs()...)...); err != nil {
		return fail(gitErr("add", err, stderr))
	}
	if _, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, michelIdent(d),
		"commit", "--quiet", "--no-verify", "--no-gpg-sign", "--allow-empty", "-m", "michel: base"); err != nil {
		return fail(gitErr("commit", err, stderr))
	}
	if c.Root, err = h.revParseCommit(ctx, d, c.Dir, "HEAD"); err != nil || c.Root == "" {
		return fail(errors.Join(err, errors.New("Michel cannot read the base commit of the fix copy")))
	}
	c.SecretHits = mask.ScanFiles(c.Dir, kept)
	if c.ConfigSHA, err = configSHA(c.Dir); err != nil {
		return fail(err)
	}
	return c, nil
}

// writeAttributes writes plainAttributes in <gitDir>/info/attributes.
func writeAttributes(gitDir string) error {
	info := filepath.Join(gitDir, "info")
	if err := os.MkdirAll(info, 0o700); err != nil {
		return fmt.Errorf("Michel cannot prepare the fix copy: %w", noPath(err))
	}
	if err := os.WriteFile(filepath.Join(info, "attributes"), []byte(plainAttributes), 0o600); err != nil {
		return fmt.Errorf("Michel cannot prepare the fix copy: %w", noPath(err))
	}
	return nil
}

// extract writes the regular files and folders of the tar archive under
// dir, Michel's own reader: no symbolic or hard link, no special file, no
// path outside dir or under a .git folder, sizes capped. Every write goes
// through an os.Root of dir, so nothing can land outside it. It returns
// the files written and the excluded files left out (slash paths, sorted).
func extract(archive, dir string, exclude []string) (kept, excluded []string, err error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, nil, fmt.Errorf("Michel cannot read the project's files: %w", noPath(err))
	}
	defer f.Close()
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("Michel cannot write the fix copy: %w", noPath(err))
	}
	defer root.Close()
	tr := tar.NewReader(f)
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("Michel cannot read the project's files: %w", err)
		}
		rel := strings.TrimSuffix(hdr.Name, "/")
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir {
			continue // links, pax headers, special files
		}
		if rel == "" || checkEntry(rawEntry{path: rel, mode: "100644"}) != nil {
			continue
		}
		full := filepath.FromSlash(rel)
		if hdr.Typeflag == tar.TypeDir {
			if inExcludedFolder(strings.Split(rel, "/"), exclude) {
				continue
			}
			if err := root.MkdirAll(full, 0o755); err != nil {
				return nil, nil, fmt.Errorf("Michel cannot write the fix copy: %w", noPath(err))
			}
			continue
		}
		if isExcluded(rel, exclude) {
			excluded = append(excluded, rel)
			continue
		}
		total += hdr.Size
		if hdr.Size > maxCopyFile || total > maxCopyTotal || len(kept) >= maxCopyFiles {
			return nil, nil, ErrCopyTooLarge
		}
		if parent := filepath.Dir(full); parent != "." {
			if err := root.MkdirAll(parent, 0o755); err != nil {
				return nil, nil, fmt.Errorf("Michel cannot write the fix copy: %w", noPath(err))
			}
		}
		mode := os.FileMode(0o644)
		if hdr.Mode&0o111 != 0 {
			mode = 0o755
		}
		out, err := root.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return nil, nil, fmt.Errorf("Michel cannot write the fix copy: %w", noPath(err))
		}
		_, cerr := io.Copy(out, io.LimitReader(tr, maxCopyFile))
		if err := errors.Join(cerr, out.Close()); err != nil {
			return nil, nil, fmt.Errorf("Michel cannot write the fix copy: %w", noPath(err))
		}
		kept = append(kept, rel)
	}
	slices.Sort(excluded)
	return kept, excluded, nil
}

// configSHA is the SHA-256 of the copy's .git/config and
// .git/info/attributes. A .git/commondir (which would make git read
// another configuration) is refused.
func configSHA(dir string) (string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", ErrNotACopy
	}
	defer root.Close()
	if _, err := root.Lstat(".git/commondir"); err == nil {
		return "", ErrCopyTampered
	}
	h := sha256.New()
	for _, f := range []string{".git/config", ".git/info/attributes"} {
		b, err := readIn(root, f, maxSettingsFile)
		if err != nil {
			return "", fmt.Errorf("Michel cannot read the git configuration of the fix copy: %w", noPath(err))
		}
		fmt.Fprintf(h, "%d\x00", len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// inDataDir checks that p is a path under d.DataDir.
func inDataDir(d Deps, p string) error {
	if d.DataDir == "" || !filepath.IsAbs(d.DataDir) {
		return ErrNotACopy
	}
	rel, err := filepath.Rel(d.DataDir, p)
	if err != nil || !filepath.IsLocal(rel) {
		return ErrNotACopy
	}
	return nil
}

// copyDir checks that c.Dir is an agent copy of the data folder: an
// absolute <data>/worktrees/<project id>/<attempt id> folder holding a .git
// folder. A scratch worktree is not one (see runDir): Diff, Commit, Apply
// and Remove never take it.
func copyDir(d Deps, c Copy) error {
	dir := c.Dir
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || inDataDir(d, dir) != nil {
		return ErrNotACopy
	}
	attempt, projectDir := filepath.Base(dir), filepath.Dir(dir)
	if !idShape.MatchString(attempt) || !idShape.MatchString(filepath.Base(projectDir)) || filepath.Dir(projectDir) != filepath.Join(d.DataDir, "worktrees") {
		return ErrNotACopy
	}
	for _, f := range []string{dir, filepath.Join(dir, ".git")} {
		if info, err := os.Lstat(f); err != nil || !info.IsDir() {
			return ErrNotACopy
		}
	}
	return nil
}

// runDir checks that c.Dir is a folder Michel runs installs and tests in:
// an agent copy (copyDir) or the scratch worktree of an attempt,
// <data>/fix-tmp/<attempt id>/run, holding a .git folder (Materialize).
func runDir(d Deps, c Copy) error {
	if err := copyDir(d, c); err == nil {
		return nil
	}
	dir := c.Dir
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || inDataDir(d, dir) != nil || !isScratch(d, dir) {
		return ErrNotACopy
	}
	for _, f := range []string{dir, filepath.Join(dir, ".git")} {
		if info, err := os.Lstat(f); err != nil || !info.IsDir() {
			return ErrNotACopy
		}
	}
	return nil
}

// checkCopy checks that c is a fix copy with its mirror, whose git
// configuration is the one Prepare recorded.
func checkCopy(d Deps, c Copy) error {
	if err := copyDir(d, c); err != nil {
		return err
	}
	if c.Mirror != mirrorOf(d, c) {
		return ErrNotACopy
	}
	if info, err := os.Lstat(c.Mirror); err != nil || !info.IsDir() {
		return ErrNotACopy
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

// Remove deletes the fix copy c and its mirror, and nothing that is not a
// fix copy under d.DataDir.
func Remove(d Deps, c Copy) error {
	if err := copyDir(d, c); err != nil {
		return err
	}
	mirror := mirrorOf(d, c)
	if c.Mirror != "" && c.Mirror != mirror {
		return ErrNotACopy
	}
	for _, p := range []string{c.Dir, mirror, tmpPath(d, filepath.Base(c.Dir))} {
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("Michel cannot delete the fix copy: %w", noPath(err))
		}
	}
	// The project's folders of copies and mirrors go when they are empty.
	_ = os.Remove(filepath.Dir(c.Dir))
	_ = os.Remove(filepath.Dir(mirror))
	return nil
}

// mirrorPath is the private mirror of an attempt,
// <data>/fix-mirrors/<project id>/<attempt id>.git: a tree apart from the
// copies (it holds every blob of the project, the excluded ones too), never
// inside or next to the agent's copy.
func mirrorPath(d Deps, projectID, attemptID string) string {
	return filepath.Join(d.DataDir, "fix-mirrors", projectID, attemptID+".git")
}

// mirrorOf is the mirror of the copy c.
func mirrorOf(d Deps, c Copy) string {
	return mirrorPath(d, filepath.Base(filepath.Dir(c.Dir)), filepath.Base(c.Dir))
}

// tmpPath is the folder of an attempt's temporary files (archive, index,
// patch), <data>/fix-tmp/<attempt id>, apart from the copies.
func tmpPath(d Deps, attemptID string) string {
	return filepath.Join(d.DataDir, "fix-tmp", attemptID)
}
