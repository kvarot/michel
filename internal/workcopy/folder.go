package workcopy

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/project"
)

// mergeTimeout bounds the write in the person's folder. It does not depend on
// the page: closing it or stopping the server does not cut a write in progress.
const mergeTimeout = 2 * time.Minute

// maxAttrBatch caps the paths of one git check-attr: ExecFunc has no stdin.
const maxAttrBatch = 100

// maxBranchName caps a branch name Michel puts in a refspec.
const maxBranchName = 200

// UpdateResult outcomes.
const (
	FolderUpdated  = "updated"
	FolderUpToDate = "up_to_date"
)

// Classes of a GitFailure of the update of a folder.
const (
	classDetached       = "detached"
	classDefaultUnknown = "default_unknown"
	classDirty          = "dirty"
	classInProgress     = "in_progress"
	classFilter         = "filter"
	classDiverged       = "diverged"
	classUntracked      = "untracked"
	classUpdateFailed   = "update_failed"
)

// UpdateResult is what happened to the current branch of the folder.
type UpdateResult struct {
	Outcome  string // FolderUpdated or FolderUpToDate
	From, To string
}

// UpdatePlan names the branches of a folder that can be updated.
type UpdatePlan struct {
	Current, Default string
}

// branchInRefspec is a branch name that means one thing in a refspec.
var branchInRefspec = regexp.MustCompile(`^[^-+\s~^:?*\[\\\x00-\x1f\x7f][^\s~^:?*\[\\\x00-\x1f\x7f]*$`)

func validBranchName(s string) bool {
	return len(s) <= maxBranchName && utf8.ValidString(s) && branchInRefspec.MatchString(s) &&
		!strings.Contains(s, "..") && !strings.Contains(s, "@{")
}

// folderHome checks what UpdateCheck and UpdateFolder receive.
func folderHome(d Deps, p project.Project, remote string) (home, *GitFailure) {
	if !remoteName.MatchString(remote) || !filepath.IsAbs(p.Path) || !IsGitRepo(p.Path) {
		return home{}, failure(classUpdateFailed)
	}
	h, err := ensureHome(d)
	if err != nil {
		return home{}, failure(classUpdateFailed)
	}
	return h, nil
}

// checkFolderConfig refuses a folder whose own configuration names a filter or
// moves its working tree. It runs before any git status, which starts the clean
// program of such a key on a file changed with the same size (R34). It also
// refuses a folder that declares a remote fetching on its own, before any read of
// an object. runGit checks the same keys and says no more than that it refuses:
// here the person gets the reason.
func (h home) checkFolderConfig(ctx context.Context, d Deps, p project.Project) *GitFailure {
	keys, err := h.localConfigKeys(ctx, d, p.Path)
	if err != nil {
		return failure(classUpdateFailed)
	}
	if slices.ContainsFunc(keys, isFolderKey) {
		return failure(classFilter)
	}
	if slices.ContainsFunc(keys, isPromisorKey) {
		return failure(classUpdateFailed)
	}
	return nil
}

// symbolicRef reads where a symbolic reference points, in full: the --short form
// says heads/main when a tag is named main. A reference that is absent or not
// symbolic gives "".
func (h home) symbolicRef(ctx context.Context, d Deps, p project.Project, ref string) (string, *GitFailure) {
	out, _, err := h.git(ctx, d, d.DataDir, p.Path, nil, nil, "symbolic-ref", "--quiet", ref)
	if err != nil {
		if exitCode(err) == 1 {
			return "", nil
		}
		return "", failure(classUpdateFailed)
	}
	return strings.TrimSpace(string(out)), nil
}

// defaultBranch is the branch refs/remotes/<remote>/HEAD names, or else main or
// master if the folder holds only one of them.
func (h home) defaultBranch(ctx context.Context, d Deps, p project.Project, remote string) (string, *GitFailure) {
	prefix := "refs/remotes/" + remote + "/"
	target, f := h.symbolicRef(ctx, d, p, prefix+"HEAD")
	if f != nil {
		return "", f
	}
	if target != "" {
		name, ok := strings.CutPrefix(target, prefix)
		if !ok || !validBranchName(name) {
			return "", failure(classDefaultUnknown)
		}
		return name, nil
	}
	var found []string
	for _, name := range []string{"main", "master"} {
		sha, err := h.revParseCommit(ctx, d, p.Path, "refs/heads/"+name)
		if err != nil {
			return "", failure(classUpdateFailed)
		}
		if sha != "" {
			found = append(found, name)
		}
	}
	if len(found) != 1 {
		return "", failure(classDefaultUnknown)
	}
	return found[0], nil
}

// updatePreflight says whether the folder can be updated, reading only and
// without network. The order matters: see checkFolderConfig.
func (h home) updatePreflight(ctx context.Context, d Deps, p project.Project, remote string) (UpdatePlan, *GitFailure) {
	if f := h.checkFolderConfig(ctx, d, p); f != nil {
		return UpdatePlan{}, f
	}
	head, f := h.symbolicRef(ctx, d, p, "HEAD")
	if f != nil {
		return UpdatePlan{}, f
	}
	current, onBranch := strings.CutPrefix(head, "refs/heads/")
	if !onBranch {
		return UpdatePlan{}, failure(classDetached)
	}
	def, f := h.defaultBranch(ctx, d, p, remote)
	if f != nil {
		return UpdatePlan{}, f
	}
	if current != def {
		return UpdatePlan{}, notDefaultFailure(current, def)
	}
	if sha, err := h.revParseCommit(ctx, d, p.Path, "HEAD"); err != nil || sha == "" {
		return UpdatePlan{}, failure(classUpdateFailed)
	}
	for _, ref := range []string{"MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD"} {
		sha, err := h.revParseCommit(ctx, d, p.Path, ref)
		if err != nil {
			return UpdatePlan{}, failure(classUpdateFailed)
		}
		if sha != "" {
			return UpdatePlan{}, failure(classInProgress)
		}
	}
	// --ignore-submodules=dirty: git status would go down into a submodule,
	// without the settings of workGit, and run what its own configuration names.
	// A submodule's working tree is not touched by the update.
	out, _, err := h.workGit(ctx, d, p, "status", "--porcelain=v1", "--untracked-files=no", "--ignore-submodules=dirty")
	if err != nil {
		return UpdatePlan{}, failure(classUpdateFailed)
	}
	if len(bytes.TrimSpace(out)) > 0 {
		return UpdatePlan{}, failure(classDirty)
	}
	return UpdatePlan{Current: current, Default: def}, nil
}

// UpdateCheck says whether the folder could be updated now and on which branch,
// reading only and without network. A refusal is a *GitFailure.
func UpdateCheck(ctx context.Context, d Deps, p project.Project, remote string) (UpdatePlan, error) {
	h, f := folderHome(d, p, remote)
	if f != nil {
		return UpdatePlan{}, f
	}
	plan, f := h.updatePreflight(ctx, d, p, remote)
	if f != nil {
		return UpdatePlan{}, f
	}
	return plan, nil
}

// fetchIncoming brings the principal branch of the address url into the
// folder's tracking reference, through a temporary repository: the project's
// configuration is not trusted when git holds real access (R22). It returns the
// commit. The "+" only ever concerns that tracking reference, as in git's own
// default setting: a branch is not touched.
func (h home) fetchIncoming(ctx context.Context, d Deps, p project.Project, url, proxyURL, remote, def string) (string, *GitFailure) {
	repo, cleanup, f := h.netClone(ctx, d, p)
	if f != nil {
		return "", f
	}
	defer cleanup()
	options := []string{"--quiet", "--no-tags", "--no-write-fetch-head", "--no-auto-maintenance", "--no-recurse-submodules"}
	const incoming = "refs/michel/incoming"
	args := append(append([]string{}, options...), "--", url, "refs/heads/"+def+":"+incoming)
	if _, f := h.netGit(ctx, d, repo, url, proxyURL, "fetch", args...); f != nil {
		return "", f
	}
	sha, err := h.revParseCommit(ctx, d, repo, incoming)
	if err != nil || sha == "" {
		return "", failure(classUpdateFailed)
	}
	tracking := "refs/remotes/" + remote + "/" + def
	args = append(append([]string{}, options...), repo, "+"+incoming+":"+tracking)
	if _, _, err := h.git(ctx, d, d.DataDir, p.Path, localTransport, nil, "fetch", args...); err != nil {
		return "", failure(classUpdateFailed)
	}
	if got, err := h.revParseCommit(ctx, d, p.Path, tracking); err != nil || got != sha {
		return "", failure(classUpdateFailed)
	}
	return sha, nil
}

// filterSet reads the answer of git check-attr -z filter for paths, in order: it
// says whether one of them has a filter. An answer that does not cover exactly
// these paths is an error.
func filterSet(out []byte, paths []string) (bool, error) {
	fields := strings.Split(string(out), "\x00")
	if len(fields) != len(paths)*3+1 || fields[len(fields)-1] != "" {
		return false, errors.New("git check-attr returned an unexpected answer")
	}
	set := false
	for i, path := range paths {
		if fields[i*3] != path || fields[i*3+1] != "filter" {
			return false, errors.New("git check-attr returned an unexpected answer")
		}
		if v := fields[i*3+2]; v != "unspecified" && v != "unset" {
			set = true
		}
	}
	return set, nil
}

// checkIncomingFilters refuses an update that changes a file with a filter
// attribute (Git LFS), read in the commit that arrives: a .gitattributes the
// update brings would not be seen otherwise (R34). A git too old for --source
// fails here, and nothing is written.
func (h home) checkIncomingFilters(ctx context.Context, d Deps, p project.Project, head, sha string) *GitFailure {
	out, _, err := h.git(ctx, d, d.DataDir, p.Path, nil, nil, "diff", "--name-only", "-z", "--no-ext-diff", "--no-textconv", head, sha)
	if err != nil || len(out) >= maxGitOutput {
		return failure(classUpdateFailed)
	}
	var paths []string
	for _, path := range strings.Split(string(out), "\x00") {
		if path == "" {
			continue
		}
		if !utf8.ValidString(path) { // it would not reach git unchanged on Windows
			return failure(classUpdateFailed)
		}
		paths = append(paths, path)
	}
	for start := 0; start < len(paths); start += maxAttrBatch {
		batch := paths[start:min(start+maxAttrBatch, len(paths))]
		args := append([]string{"--source=" + sha, "-z", "filter", "--"}, batch...)
		answer, _, err := h.git(ctx, d, d.DataDir, p.Path, nil, nil, "check-attr", args...)
		if err != nil {
			return failure(classUpdateFailed)
		}
		set, err := filterSet(answer, batch)
		if err != nil {
			return failure(classUpdateFailed)
		}
		if set {
			return failure(classFilter)
		}
	}
	return nil
}

// mergeFailure decides a class from what git merge wrote, which is then forgotten.
func mergeFailure(stderr, stdout []byte) *GitFailure {
	said := append(append([]byte{}, stderr...), stdout...)
	switch {
	case bytes.Contains(said, []byte("untracked working tree files")):
		return failure(classUntracked)
	case bytes.Contains(said, []byte("Not possible to fast-forward")):
		return failure(classDiverged)
	}
	return failure(classUpdateFailed)
}

// UpdateFolder brings the person's folder up to date with its principal branch
// on the address url, after a merge on the host's site: on a click, fast-forward
// only, on that branch only, with no tracked change. Hooks are off; a filter is
// refused before anything can start it. Fetching writes objects and the tracking
// reference before the check for a gap, so a refusal after it leaves HEAD, the
// index and the files as they were, not the whole .git. url comes from the
// caller, read and checked by gitremote. proxyURL is required for an https
// address and unused otherwise. Every refusal is a *GitFailure holding no output.
func UpdateFolder(ctx context.Context, d Deps, p project.Project, url, proxyURL, remote string) (UpdateResult, error) {
	h, f := folderHome(d, p, remote)
	if f != nil {
		return UpdateResult{}, f
	}
	plan, f := h.updatePreflight(ctx, d, p, remote)
	if f != nil {
		return UpdateResult{}, f
	}
	sha, f := h.fetchIncoming(ctx, d, p, url, proxyURL, remote, plan.Default)
	if f != nil {
		return UpdateResult{}, f
	}
	// The fetch takes time and the folder is the person's: what the merge relies
	// on is read again, or it could land on the branch they have just moved to.
	again, f := h.updatePreflight(ctx, d, p, remote)
	if f != nil {
		return UpdateResult{}, f
	}
	if again != plan {
		return UpdateResult{}, failure(classUpdateFailed)
	}
	head, err := h.revParseCommit(ctx, d, p.Path, "HEAD")
	if err != nil || head == "" {
		return UpdateResult{}, failure(classUpdateFailed)
	}
	if head == sha {
		return UpdateResult{Outcome: FolderUpToDate, From: head, To: head}, nil
	}
	if _, _, err := h.git(ctx, d, d.DataDir, p.Path, nil, nil, "merge-base", "--is-ancestor", head, sha); err != nil {
		if exitCode(err) == 1 {
			return UpdateResult{}, failure(classDiverged)
		}
		return UpdateResult{}, failure(classUpdateFailed)
	}
	if f := h.checkIncomingFilters(ctx, d, p, head, sha); f != nil {
		return UpdateResult{}, f
	}
	write, cancel := context.WithTimeout(context.WithoutCancel(ctx), mergeTimeout)
	defer cancel()
	stdout, stderr, err := h.workGit(write, d, p, "merge", "--ff-only", "--no-stat", "--no-autostash", "--quiet", sha)
	if err != nil {
		return UpdateResult{}, mergeFailure(stderr, stdout)
	}
	if got, err := h.revParseCommit(write, d, p.Path, "HEAD"); err != nil || got != sha {
		return UpdateResult{}, failure(classUpdateFailed)
	}
	return UpdateResult{Outcome: FolderUpdated, From: head, To: sha}, nil
}
