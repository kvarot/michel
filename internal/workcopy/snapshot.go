package workcopy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Snapshot is the agent's copy frozen at one instant: the tree id of its
// content (excluded files left out) and the change from the copy's base
// to that tree. A proposal is computed, tested and committed from one
// Snapshot, so that a write to the copy after it (the agent, a process left
// behind) changes nothing of that proposal (controller ruling 37).
type Snapshot struct {
	Tree   string
	Change Change
}

// Freeze takes the Snapshot of the copy: it stages the copy once (index
// from Root, add -A with the excluded files left out), writes the index as
// a tree, and computes the change from Root to that tree object, so that
// Tree and Change come from one immutable object whatever happens to the
// index or the working tree afterwards.
func Freeze(ctx context.Context, d Deps, c Copy) (Snapshot, error) {
	if err := checkCopy(d, c); err != nil {
		return Snapshot{}, err
	}
	if !shaShape.MatchString(c.Root) {
		return Snapshot{}, ErrInvalidCommit
	}
	h, err := ensureHome(d)
	if err != nil {
		return Snapshot{}, err
	}
	if err := h.stage(ctx, d, c); err != nil {
		return Snapshot{}, err
	}
	out, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "write-tree")
	if err != nil {
		return Snapshot{}, gitErr("write-tree", err, stderr)
	}
	tree := strings.TrimSpace(string(out))
	if !shaShape.MatchString(tree) {
		return Snapshot{}, errors.New("git write-tree returned an unexpected tree id")
	}
	ch, err := h.change(ctx, d, c, tree)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Tree: tree, Change: ch}, nil
}

// emptyTree is git's id of the tree with no entry.
const emptyTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

// scratchDir is the scratch worktree of an attempt, <data>/fix-tmp/<attempt
// id>/run, where Michel installs and tests a snapshot: never the agent's
// copy.
func scratchDir(d Deps, attemptID string) string {
	return filepath.Join(tmpPath(d, attemptID), "run")
}

// testsRunShape is the name of the folder of a run of the tests a person
// asked for (MaterializeTests).
var testsRunShape = regexp.MustCompile(`^tests-[0-9a-f]{16}$`)

// isScratch reports whether dir is a scratch worktree of an attempt: its
// run folder or one of its tests folders.
func isScratch(d Deps, dir string) bool {
	if base := filepath.Base(dir); base != "run" && !testsRunShape.MatchString(base) {
		return false
	}
	attempt := filepath.Dir(dir)
	return idShape.MatchString(filepath.Base(attempt)) && filepath.Dir(attempt) == filepath.Join(d.DataDir, "fix-tmp")
}

// Materialize writes the tree of a snapshot of c into a fresh scratch
// worktree <data>/fix-tmp/<attempt id>/run (git archive of the tree from
// the copy's object database, extracted by Michel's own reader: regular
// files only, excluded files left out, nothing outside the folder) and
// returns it as a Copy for Install and RunTests. cleanup removes it; it may
// be called more than once.
func Materialize(ctx context.Context, d Deps, c Copy, tree string) (run Copy, cleanup func(), err error) {
	return materialize(ctx, d, c, tree, "run")
}

// MaterializeTests is Materialize into a folder of its own,
// <data>/fix-tmp/<attempt id>/tests-<random>, for a run of the tests a
// person asked for: two such runs, or one and a proposal, never share a
// folder nor wipe each other's.
func MaterializeTests(ctx context.Context, d Deps, c Copy, tree string) (run Copy, cleanup func(), err error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return Copy{}, nil, err
	}
	return materialize(ctx, d, c, tree, "tests-"+hex.EncodeToString(b))
}

// materialize writes tree into <data>/fix-tmp/<attempt id>/<name>.
func materialize(ctx context.Context, d Deps, c Copy, tree, name string) (run Copy, cleanup func(), err error) {
	if err := checkCopy(d, c); err != nil {
		return Copy{}, nil, err
	}
	if !shaShape.MatchString(tree) {
		return Copy{}, nil, ErrInvalidCommit
	}
	h, err := ensureHome(d)
	if err != nil {
		return Copy{}, nil, err
	}
	attemptID := filepath.Base(c.Dir)
	dir := filepath.Join(tmpPath(d, attemptID), name)
	archive := filepath.Join(tmpPath(d, attemptID), "snapshot.tar")
	if name != "run" {
		archive = filepath.Join(tmpPath(d, attemptID), name+".tar")
	}
	cleanup = func() {
		_ = os.RemoveAll(dir)
		_ = os.Remove(archive)
		_ = os.Remove(tmpPath(d, attemptID))
	}
	cleanup()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o700); err != nil {
		return Copy{}, nil, fmt.Errorf("Michel cannot create the scratch folder: %w", noPath(err))
	}
	fail := func(err error) (Copy, func(), error) {
		cleanup()
		return Copy{}, nil, err
	}
	if tree == emptyTree {
		// Nothing to write: git archive would refuse the pathspec.
		return Copy{Dir: dir}, cleanup, nil
	}
	// Any failure (an unknown or corrupt object included) fails closed:
	// never an empty scratch folder taken for the snapshot.
	if _, stderr, err := h.git(ctx, d, tmpPath(d, attemptID), c.Dir, nil, nil, "archive",
		append([]string{"--format=tar", "-o", archive, tree, "--"}, c.pathspecs()...)...); err != nil {
		return fail(gitErr("archive", err, stderr))
	}
	if _, _, err := extract(archive, dir, c.Exclude); err != nil {
		return fail(err)
	}
	_ = os.Remove(archive)
	return Copy{Dir: dir}, cleanup, nil
}

// CommitSnapshot builds the fix commit of a snapshot in the private mirror
// (the tree of Base with the snapshot's change applied, parent Base,
// author Michel), checks that the commit holds exactly the snapshot's
// change (same paths, same blobs as the snapshot's tree: ErrInvalidCommit
// otherwise) and returns its id and its tree. Nothing is read from the
// copy's working tree.
func CommitSnapshot(ctx context.Context, d Deps, c Copy, snap Snapshot, message string) (sha, commitTree string, err error) {
	if len(snap.Change.Files) == 0 || len(snap.Change.Raw) == 0 {
		return "", "", ErrNothingToCommit
	}
	if err := checkCopy(d, c); err != nil {
		return "", "", err
	}
	if !shaShape.MatchString(c.Base) {
		return "", "", ErrInvalidCommit
	}
	h, err := ensureHome(d)
	if err != nil {
		return "", "", err
	}
	sha, err = h.commitPatch(ctx, d, c, snap.Change.Raw, message)
	if err != nil {
		return "", "", err
	}
	if ok, err := h.commitMatches(ctx, d, c, sha, snap); err != nil {
		return "", "", err
	} else if !ok {
		return "", "", fmt.Errorf("%w: the commit does not hold the snapshot's change", ErrInvalidCommit)
	}
	out, stderr, err := h.git(ctx, d, c.Mirror, c.Mirror, nil, nil, "rev-parse", sha+"^{tree}")
	if err != nil {
		return "", "", gitErr("rev-parse", err, stderr)
	}
	commitTree = strings.TrimSpace(string(out))
	if !shaShape.MatchString(commitTree) {
		return "", "", errors.New("git rev-parse returned an unexpected tree id")
	}
	return sha, commitTree, nil
}
