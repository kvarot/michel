package workcopy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// folderFixture is the project demo with a remote origin, and site, a second
// clone of that remote standing for what happens on the host's site.
type folderFixture struct {
	remoteFixture
	site string
}

func newFolderFixture(t *testing.T) folderFixture {
	t.Helper()
	return remoteFrom(t, "folder", "")
}

// advance commits files on the site's main and pushes it: a merge on the site.
func (f folderFixture) advance(t *testing.T, files map[string]string) string {
	t.Helper()
	for path, body := range files {
		writeFile(t, f.site, path, body)
	}
	gitT(t, f.env, f.site, "add", "-A")
	gitT(t, f.env, f.site, "commit", "-q", "-m", "on the site")
	gitT(t, f.env, f.site, "push", "-q", "origin", "main")
	return gitT(t, f.env, f.site, "rev-parse", "HEAD")
}

func (f folderFixture) update(t *testing.T) (UpdateResult, error) {
	t.Helper()
	return UpdateFolder(context.Background(), f.deps, f.proj, f.bare, "", "origin")
}

// record makes every subprocess of the code under test go through a recorder.
func (f *folderFixture) record() *gitRecorder {
	r := &gitRecorder{}
	f.deps.Exec = r.exec
	return r
}

// folderState is HEAD, the index and every file of the folder outside .git.
func folderState(t *testing.T, f folderFixture) string {
	t.Helper()
	root := f.proj.Path
	// --work-tree: the case core.worktree points elsewhere.
	git := []string{"--git-dir=.git", "--work-tree=."}
	head := gitT(t, f.env, root, append(git, "rev-parse", "HEAD")...)
	ref := gitT(t, f.env, root, append(git, "rev-parse", "--abbrev-ref", "HEAD")...)
	index := gitT(t, f.env, root, append(git, "ls-files", "-s")...)
	h := sha256.New()
	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.Name() == ".git" {
			return filepath.SkipDir
		}
		if e.IsDir() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		fmt.Fprintf(h, "%s\x00%x\n", filepath.ToSlash(rel), sha256.Sum256(b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join([]string{head, ref, index, hex.EncodeToString(h.Sum(nil))}, "\n")
}

// personGit runs git in the folder with the person's own configuration.
func (f folderFixture) personGit(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", f.proj.Path}, args...)...)
	cmd.Env = append(os.Environ(), "HOME="+f.home, "USERPROFILE="+f.home,
		"GIT_AUTHOR_NAME=demo", "GIT_AUTHOR_EMAIL=demo@example.test",
		"GIT_COMMITTER_NAME=demo", "GIT_COMMITTER_EMAIL=demo@example.test")
	out, err := cmd.Output()
	return string(out), err
}

// syncAttr brings a line of .gitattributes into the project and the remote.
func (f folderFixture) syncAttr(t *testing.T, line string) {
	t.Helper()
	f.advance(t, map[string]string{".gitattributes": line + "\n"})
	gitT(t, f.env, f.proj.Path, "pull", "-q", "--ff-only", "origin", "main")
}

// refusal is one case where the update must not touch the folder.
type refusal struct {
	name      string
	class     string
	preflight bool // decided before any network
	arrange   func(t *testing.T, f folderFixture)
}

func refusals() []refusal {
	config := func(args ...string) func(*testing.T, folderFixture) {
		return func(t *testing.T, f folderFixture) {
			t.Helper()
			gitT(t, f.env, f.proj.Path, append([]string{"config"}, args...)...)
		}
	}
	folderMarker := func(name string) func(*testing.T, folderFixture) {
		return func(t *testing.T, f folderFixture) {
			t.Helper()
			writeFile(t, f.proj.Path, ".git/"+name+"/todo", "demo\n")
		}
	}
	marker := func(name string) func(*testing.T, folderFixture) {
		return func(t *testing.T, f folderFixture) {
			t.Helper()
			head := gitT(t, f.env, f.proj.Path, "rev-parse", "HEAD")
			writeFile(t, f.proj.Path, ".git/"+name, head+"\n")
		}
	}
	return []refusal{
		{"detached", classDetached, true, func(t *testing.T, f folderFixture) {
			gitT(t, f.env, f.proj.Path, "checkout", "-q", "--detach")
		}},
		{"not_default", classNotDefault, true, func(t *testing.T, f folderFixture) {
			gitT(t, f.env, f.proj.Path, "checkout", "-q", "other")
		}},
		{"default_unknown, main and master", classDefaultUnknown, true, func(t *testing.T, f folderFixture) {
			gitT(t, f.env, f.proj.Path, "branch", "master")
		}},
		{"default_unknown, remote HEAD elsewhere", classDefaultUnknown, true, func(t *testing.T, f folderFixture) {
			gitT(t, f.env, f.proj.Path, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/heads/other")
		}},
		{"dirty, working tree", classDirty, true, func(t *testing.T, f folderFixture) {
			writeFile(t, f.proj.Path, "README.md", "changed by the person\n")
		}},
		{"dirty, index", classDirty, true, func(t *testing.T, f folderFixture) {
			writeFile(t, f.proj.Path, "README.md", "changed by the person\n")
			gitT(t, f.env, f.proj.Path, "add", "README.md")
		}},
		{"in_progress, merge", classInProgress, true, marker("MERGE_HEAD")},
		{"in_progress, cherry-pick", classInProgress, true, marker("CHERRY_PICK_HEAD")},
		{"in_progress, revert", classInProgress, true, marker("REVERT_HEAD")},
		{"in_progress, rebase-apply", classInProgress, true, folderMarker("rebase-apply")},
		{"in_progress, rebase-merge", classInProgress, true, folderMarker("rebase-merge")},
		{"in_progress, sequencer", classInProgress, true, folderMarker("sequencer")},
		{"filter, local key", classFilter, true, config("filter.x.clean", "demo-program")},
		{"filter, key in capitals", classFilter, true, config("FILTER.x.smudge", "demo-program")},
		{"filter, key in an included file", classFilter, true, func(t *testing.T, f folderFixture) {
			inc := filepath.ToSlash(filepath.Join(t.TempDir(), "included"))
			writeFile(t, filepath.Dir(inc), "included", "[filter \"x\"]\n\tclean = demo-program\n")
			gitT(t, f.env, f.proj.Path, "config", "include.path", inc)
		}},
		{"filter, key in config.worktree", classFilter, true, func(t *testing.T, f folderFixture) {
			gitT(t, f.env, f.proj.Path, "config", "extensions.worktreeConfig", "true")
			gitT(t, f.env, f.proj.Path, "config", "--worktree", "filter.x.clean", "demo-program")
		}},
		{"core.worktree", classFilter, true, func(t *testing.T, f folderFixture) {
			gitT(t, f.env, f.proj.Path, "config", "core.worktree", filepath.ToSlash(t.TempDir()))
		}},
		{"filter, attribute on a changed file", classFilter, false, func(t *testing.T, f folderFixture) {
			f.syncAttr(t, "changed.txt filter=x") // no program behind x: only the attribute is read
			f.advance(t, map[string]string{"changed.txt": "newer\n"})
		}},
		{"filter, attribute only the update brings", classFilter, false, func(t *testing.T, f folderFixture) {
			f.advance(t, map[string]string{".gitattributes": "*.bin filter=lfs\n", "big.bin": "pointer\n"})
		}},
		{"filter, attribute in info/attributes", classFilter, false, func(t *testing.T, f folderFixture) {
			writeFile(t, f.proj.Path, ".git/info/attributes", "changed.txt filter=x\n")
		}},
		{"filter, attribute in the person's core.attributesFile", classFilter, false, func(t *testing.T, f folderFixture) {
			writeFile(t, f.home, "attributes", "changed.txt filter=w\n")
			writeFile(t, f.home, ".gitconfig", "[core]\n\tattributesFile = "+filepath.ToSlash(filepath.Join(f.home, "attributes"))+"\n")
		}},
		{"filter, attribute in a core.attributesFile the project names", classFilter, false, func(t *testing.T, f folderFixture) {
			writeFile(t, f.home, "attributes", "changed.txt filter=w\n")
			gitT(t, f.env, f.proj.Path, "config", "core.attributesFile", filepath.ToSlash(filepath.Join(f.home, "attributes")))
		}},
		{"diverged", classDiverged, false, func(t *testing.T, f folderFixture) {
			writeFile(t, f.proj.Path, "mine.txt", "saved here only\n")
			gitT(t, f.env, f.proj.Path, "add", "mine.txt")
			gitT(t, f.env, f.proj.Path, "commit", "-q", "-m", "mine")
		}},
		{"untracked", classUntracked, false, func(t *testing.T, f folderFixture) {
			writeFile(t, f.proj.Path, "changed.txt", "the person's own file\n")
		}},
	}
}

func TestUpdateFastForwards(t *testing.T) {
	f := newFolderFixture(t)
	r := f.record()
	from := gitT(t, f.env, f.proj.Path, "rev-parse", "HEAD")
	to := f.advance(t, map[string]string{"merged.txt": "from the site\n"})

	res, err := f.update(t)
	if err != nil {
		t.Fatal(err)
	}
	if res != (UpdateResult{Outcome: FolderUpdated, From: from, To: to}) {
		t.Fatalf("result = %+v", res)
	}
	if got := gitT(t, f.env, f.proj.Path, "rev-parse", "HEAD"); got != to {
		t.Errorf("HEAD = %s, want %s", got, to)
	}
	if got := gitT(t, f.env, f.proj.Path, "rev-parse", "refs/remotes/origin/main"); got != to {
		t.Errorf("tracking reference = %s, want %s", got, to)
	}
	b, err := os.ReadFile(filepath.Join(f.proj.Path, "merged.txt"))
	if err != nil || strings.ReplaceAll(string(b), "\r\n", "\n") != "from the site\n" {
		t.Errorf("merged.txt = %q, %v", b, err)
	}
	if out, err := f.personGit(t, "status", "--porcelain"); err != nil || out != "" {
		t.Errorf("status after the update = %q, %v", out, err)
	}
	f.fixNetEmpty(t)

	merges := r.find("merge")
	if len(merges) != 1 {
		t.Fatalf("%d merges", len(merges))
	}
	m := merges[0]
	wantTail := []string{"merge", "--ff-only", "--no-overwrite-ignore", "--no-verify-signatures", "--no-squash", "--commit", "--no-stat", "--no-autostash", "--quiet", to}
	if tail := m.args[len(m.args)-len(wantTail):]; !slices.Equal(tail, wantTail) {
		t.Errorf("merge argv = %q", m.args)
	}
	hooks := filepath.Join(f.deps.DataDir, "fix-hooks")
	joined := strings.Join(m.args, " ")
	for _, want := range []string{"core.hooksPath=" + hooks, "core.fsmonitor=false", "gc.auto=0", "maintenance.auto=false", "credential.helper=",
		"commit.gpgSign=false", "core.longpaths=true", "submodule.recurse=false", "merge.verifySignatures=false", "-C " + f.proj.Path} {
		if !strings.Contains(joined, want) {
			t.Errorf("merge argv lacks %q: %q", want, m.args)
		}
	}
	if v, _ := envLookup(m.env, "HOME"); v != f.home {
		t.Errorf("merge HOME = %q, want the person's", v)
	}
	if _, set := envLookup(m.env, "GIT_CONFIG_GLOBAL"); set {
		t.Error("merge must read the person's configuration")
	}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if v, _ := envLookup(m.env, k); v != "http://127.0.0.1:9" {
			t.Errorf("merge %s = %q", k, v)
		}
	}
	if v, _ := envLookup(m.env, "GIT_NO_LAZY_FETCH"); v != "1" {
		t.Errorf("merge GIT_NO_LAZY_FETCH = %q", v)
	}
	status := r.find("status")
	if len(status) == 0 {
		t.Fatal("no status")
	}
	// The check for changes, then what the merge is compared with if it fails.
	wantStatus := []string{"status", "--porcelain=v1", "--untracked-files=no", "--ignore-submodules=dirty"}
	wantFiles := []string{"status", "--porcelain=v1", "--untracked-files=normal", "--ignore-submodules=dirty"}
	for _, s := range status {
		tail := s.args[len(s.args)-len(wantStatus):]
		if !slices.Contains(s.args, "--no-optional-locks") || !slices.Equal(tail, wantStatus) && !slices.Equal(tail, wantFiles) {
			t.Errorf("status argv = %q", s.args)
		}
	}
	fetches := r.find("fetch")
	if len(fetches) != 2 {
		t.Fatalf("%d fetches, want one from the remote and one into the project", len(fetches))
	}
	wantNet := []string{"fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--no-auto-maintenance", "--no-recurse-submodules", "--", f.bare, "refs/heads/main:refs/michel/incoming"}
	if tail := fetches[0].args[len(fetches[0].args)-len(wantNet):]; !slices.Equal(tail, wantNet) {
		t.Errorf("remote fetch = %q", fetches[0].args)
	}
	if slices.Contains(fetches[0].args, f.proj.Path) {
		t.Errorf("the remote fetch ran in the project: %q", fetches[0].args)
	}
	last := fetches[1].args[len(fetches[1].args)-1]
	if last != "+refs/michel/incoming:refs/remotes/origin/main" {
		t.Errorf("project fetch = %q", fetches[1].args)
	}
}

func TestUpdateUpToDateWritesNothing(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	r := f.record()
	head := gitT(t, f.env, f.proj.Path, "rev-parse", "HEAD")
	before := folderState(t, f)
	index, err := os.ReadFile(filepath.Join(f.proj.Path, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 { // a second click says the same
		res, err := f.update(t)
		if err != nil {
			t.Fatal(err)
		}
		if res != (UpdateResult{Outcome: FolderUpToDate, From: head, To: head}) {
			t.Fatalf("result = %+v", res)
		}
	}
	if got := folderState(t, f); got != before {
		t.Errorf("state changed:\n%s\nthen\n%s", before, got)
	}
	after, err := os.ReadFile(filepath.Join(f.proj.Path, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(index, after) {
		t.Error("the index file was written")
	}
	if len(r.find("merge")) != 0 {
		t.Error("a merge ran")
	}
	f.fixNetEmpty(t)
}

// The refusals that write in the person's home run one after the other, first;
// the others run together, in a home of their own that nothing writes in.
var refusalsInTheHome = map[string]bool{
	"filter, attribute in the person's core.attributesFile":        true,
	"filter, attribute in a core.attributesFile the project names": true,
}

func TestUpdateRefused(t *testing.T) {
	home := isolatePerson(t)
	for _, c := range refusals() {
		t.Run(c.name, func(t *testing.T) {
			var f folderFixture
			if refusalsInTheHome[c.name] {
				f = newFolderFixture(t)
			} else {
				t.Parallel()
				f = newFolderFixtureIn(t, home)
			}
			f.advance(t, map[string]string{"changed.txt": "from the site\n"})
			c.arrange(t, f)
			before := folderState(t, f)
			_, err := f.update(t)
			wantClass(t, err, c.class)
			if got := folderState(t, f); got != before {
				t.Errorf("the folder changed:\n%s\nthen\n%s", before, got)
			}
			f.fixNetEmpty(t)
		})
	}
}

func TestUpdateRefusedNamesTheBranches(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	gitT(t, f.env, f.proj.Path, "checkout", "-q", "other")
	_, err := f.update(t)
	var gf *GitFailure
	if !errors.As(err, &gf) || gf.Current != "other" || gf.Default != "main" {
		t.Fatalf("err = %#v", err)
	}
}

func TestUpdateRefusesBeforeAnyNetwork(t *testing.T) {
	home := isolatePerson(t)
	for _, c := range refusals() {
		if !c.preflight || refusalsInTheHome[c.name] {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			f := newFolderFixtureIn(t, home)
			c.arrange(t, f)
			r := f.record()
			_, err := f.update(t)
			wantClass(t, err, c.class)
			if n := len(r.find("fetch")) + len(r.find("clone")) + len(r.find("merge")); n != 0 {
				t.Errorf("%d fetch, clone or merge ran", n)
			}
			if c.class == classFilter && len(r.find("status")) != 0 {
				t.Error("a status ran before the refusal: it would run the clean program of that key")
			}
			if _, err := UpdateCheck(context.Background(), f.deps, f.proj, "origin"); err == nil {
				t.Error("UpdateCheck did not refuse")
			}
		})
	}
}

func TestUpdateUsesTheRemoteHeadWhenThereIsOne(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	gitT(t, f.env, f.proj.Path, "branch", "master") // main and master: the reference decides
	gitT(t, f.env, f.proj.Path, "update-ref", "refs/remotes/origin/main", "HEAD")
	gitT(t, f.env, f.proj.Path, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
	to := f.advance(t, map[string]string{"merged.txt": "x\n"})
	res, err := f.update(t)
	if err != nil || res.To != to {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

// A tag named like the branch makes git symbolic-ref --short say heads/main.
func TestUpdateWithATagNamedLikeTheBranch(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	gitT(t, f.env, f.proj.Path, "tag", "main")
	plan, err := UpdateCheck(context.Background(), f.deps, f.proj, "origin")
	if err != nil {
		t.Fatal(err)
	}
	if plan != (UpdatePlan{Current: "main", Default: "main"}) {
		t.Fatalf("plan = %+v", plan)
	}
	gitT(t, f.env, f.proj.Path, "checkout", "-q", "other")
	gitT(t, f.env, f.proj.Path, "tag", "other")
	_, err = f.update(t)
	var gf *GitFailure
	if !errors.As(err, &gf) || gf.Current != "other" || gf.Default != "main" {
		t.Fatalf("err = %#v", err)
	}
}

func TestUpdateRefusesABadRemoteNameOrNoRepository(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	r := f.record()
	for _, name := range []string{"", "-x", "a/b", "a b"} {
		_, err := UpdateFolder(context.Background(), f.deps, f.proj, f.bare, "", name)
		wantClass(t, err, classUpdateFailed)
	}
	if len(r.calls) != 0 {
		t.Errorf("git ran: %v", r.calls)
	}
	p := f.proj
	p.Path = t.TempDir()
	_, err := UpdateFolder(context.Background(), f.deps, p, f.bare, "", "origin")
	wantClass(t, err, classUpdateFailed)
}

func TestUpdateNeedsTheSeamForALocalRemote(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	f.advance(t, map[string]string{"merged.txt": "x\n"})
	f.deps.AllowLocalRemote = false
	before := folderState(t, f)
	_, err := f.update(t)
	wantClass(t, err, classFailed)
	if got := folderState(t, f); got != before {
		t.Error("the folder changed")
	}
	f.fixNetEmpty(t)
}

func TestUpdateKeepsAutocrlf(t *testing.T) {
	f := newFolderFixture(t)
	writeFile(t, f.home, ".gitconfig", "[core]\n\tautocrlf = true\n")
	writeFile(t, f.proj.Path, "README.md", "demo\r\n") // what Git for Windows leaves in a folder
	writeFile(t, f.proj.Path, "composer.json", `{"name":"acme/lib"}`+"\r\n")
	// Same blobs: the index only records the size of these files on the disk.
	if out, err := f.personGit(t, "add", "README.md", "composer.json"); err != nil {
		t.Fatalf("git add: %v %s", err, out)
	}
	f.advance(t, map[string]string{"composer.json": "{\"name\":\"acme/libs\"}\n"})

	if _, err := f.update(t); err != nil {
		t.Fatal(err)
	}
	if out, err := f.personGit(t, "status", "--porcelain"); err != nil || out != "" {
		t.Errorf("status after the update = %q, %v", out, err)
	}
	for _, name := range []string{"README.md", "composer.json"} {
		b, err := os.ReadFile(filepath.Join(f.proj.Path, name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "\r\n") {
			t.Errorf("%s has lost its line endings: %q", name, b)
		}
	}
}

func TestUntrackedFileIsNotDirty(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	writeFile(t, f.proj.Path, "notes.txt", "the person's notes\n")
	to := f.advance(t, map[string]string{"merged.txt": "x\n"})
	res, err := f.update(t)
	if err != nil || res.To != to {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if b, err := os.ReadFile(filepath.Join(f.proj.Path, "notes.txt")); err != nil || string(b) != "the person's notes\n" {
		t.Errorf("notes.txt = %q, %v", b, err)
	}
}

func TestUpdateRunsNoHookNorFilter(t *testing.T) {
	t.Run("hooks", func(t *testing.T) {
		f := newFolderFixture(t)
		script, mark := witness(t)
		body, err := os.ReadFile(script)
		if err != nil {
			t.Fatal(err)
		}
		other := t.TempDir()
		for _, dir := range []string{filepath.Join(f.proj.Path, ".git", "hooks"), other} {
			for _, name := range []string{"post-merge", "post-checkout", "reference-transaction"} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), body, 0o755); err != nil {
					t.Fatal(err)
				}
			}
		}
		to := f.advance(t, map[string]string{"merged.txt": "x\n"})
		res, err := f.update(t)
		if err != nil || res.To != to {
			t.Fatalf("res = %+v, err = %v", res, err)
		}
		noMark(t, mark, "a hook of .git/hooks")

		gitT(t, f.env, f.proj.Path, "config", "core.hooksPath", filepath.ToSlash(other))
		to = f.advance(t, map[string]string{"merged2.txt": "x\n"})
		res, err = f.update(t)
		if err != nil || res.To != to {
			t.Fatalf("res = %+v, err = %v", res, err)
		}
		noMark(t, mark, "a hook of the project's core.hooksPath")

		// The witness is alive: plain git runs it.
		cmd := exec.Command("git", "-C", f.proj.Path, "update-ref", "refs/heads/control", "HEAD")
		cmd.Env = f.env
		_ = cmd.Run()
		if _, err := os.Stat(mark); err != nil {
			t.Error("control: the hook did not run under plain git, so this test proves nothing")
		}
	})

	for _, c := range []struct {
		name   string
		config []string
	}{
		{"filter key", []string{"config", "filter.x.clean"}},
		{"filter key of config.worktree", []string{"config", "--worktree", "filter.x.clean"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFolderFixture(t)
			f.advance(t, map[string]string{".gitattributes": "data.txt filter=x\n", "data.txt": "aaaa\n"})
			gitT(t, f.env, f.proj.Path, "pull", "-q", "--ff-only", "origin", "main")
			f.advance(t, map[string]string{"merged.txt": "x\n"})
			script, mark := witness(t)
			if c.config[1] == "--worktree" {
				gitT(t, f.env, f.proj.Path, "config", "extensions.worktreeConfig", "true")
			}
			gitT(t, f.env, f.proj.Path, append(slices.Clone(c.config), script)...)
			// A tracked file changed with the same size: what makes status run clean.
			time.Sleep(10 * time.Millisecond)
			writeFile(t, f.proj.Path, "data.txt", "bbbb\n")
			future := time.Now().Add(2 * time.Second)
			if err := os.Chtimes(filepath.Join(f.proj.Path, "data.txt"), future, future); err != nil {
				t.Fatal(err)
			}

			before := folderState(t, f)
			_, err := f.update(t)
			wantClass(t, err, classFilter)
			noMark(t, mark, "the clean program of that key")
			if got := folderState(t, f); got != before {
				t.Error("the folder changed")
			}
			if _, err := UpdateCheck(context.Background(), f.deps, f.proj, "origin"); err == nil {
				t.Error("UpdateCheck did not refuse")
			}
			noMark(t, mark, "the clean program of that key, in UpdateCheck")

			// The witness is alive: plain git status runs it (R34).
			cmd := exec.Command("git", "-C", f.proj.Path, "status", "--porcelain")
			cmd.Env = f.env
			_ = cmd.Run()
			if _, err := os.Stat(mark); err != nil {
				t.Error("control: the filter did not run under plain git status, so this test proves nothing")
			}
		})
	}
}

// A submodule's own configuration is not the folder's: git status goes down in
// it, without the -c of the parent, and would run its programs.
func TestUpdateRunsNothingOfASubmodule(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	sub := filepath.Join(t.TempDir(), "sub")
	gitT(t, f.env, filepath.Dir(sub), "init", "-q", "-b", "main", sub)
	writeFile(t, sub, "s.txt", "aaaa\n")
	gitT(t, f.env, sub, "add", "-A")
	gitT(t, f.env, sub, "commit", "-q", "-m", "s")
	gitT(t, f.env, f.proj.Path, "-c", "protocol.file.allow=always", "submodule", "--quiet", "add", filepath.ToSlash(sub), "mod")
	gitT(t, f.env, f.proj.Path, "commit", "-q", "-m", "submodule")
	gitT(t, f.env, f.proj.Path, "push", "-q", f.bare, "main")
	gitT(t, f.env, f.site, "pull", "-q", "--ff-only", "origin", "main")

	script, mark := witness(t)
	inMod := filepath.Join(f.proj.Path, "mod")
	gitT(t, f.env, inMod, "config", "core.fsmonitor", script)
	gitT(t, f.env, inMod, "config", "filter.x.clean", script)
	writeFile(t, f.proj.Path, ".git/modules/mod/info/attributes", "s.txt filter=x\n")
	writeFile(t, inMod, "s.txt", "bbbb\n")
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(filepath.Join(inMod, "s.txt"), future, future); err != nil {
		t.Fatal(err)
	}

	to := f.advance(t, map[string]string{"merged.txt": "x\n"})
	res, err := f.update(t)
	if err != nil || res.To != to {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	noMark(t, mark, "a program of the submodule's configuration")
	if b, err := os.ReadFile(filepath.Join(inMod, "s.txt")); err != nil || string(b) != "bbbb\n" {
		t.Errorf("the submodule's file changed: %q, %v", b, err)
	}

	// The witness is alive: plain git status runs it.
	cmd := exec.Command("git", "-C", f.proj.Path, "-c", "core.fsmonitor=false", "status", "--porcelain")
	cmd.Env = f.env
	_ = cmd.Run()
	if _, err := os.Stat(mark); err != nil {
		t.Error("control: plain git status ran nothing of the submodule, so this test proves nothing")
	}
}

func TestUpdateMovesOnlyTheDefaultBranch(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	writeFile(t, f.proj.Path, "README.md", "set aside\n")
	gitT(t, f.env, f.proj.Path, "stash", "push", "-q")
	gitT(t, f.env, f.site, "tag", "v9")
	to := f.advance(t, map[string]string{"merged.txt": "x\n"})
	gitT(t, f.env, f.site, "push", "-q", "origin", "v9")

	refs := func() string {
		var keep []string
		for line := range strings.Lines(gitT(t, f.env, f.proj.Path, "for-each-ref", "--format=%(refname) %(objectname)")) {
			name, _, _ := strings.Cut(line, " ")
			if name != "refs/heads/main" && name != "refs/remotes/origin/main" {
				keep = append(keep, line)
			}
		}
		return strings.Join(keep, "")
	}
	before := refs()
	if _, err := f.update(t); err != nil {
		t.Fatal(err)
	}
	if got := refs(); got != before {
		t.Errorf("other references moved:\n%s\nthen\n%s", before, got)
	}
	if got := gitT(t, f.env, f.proj.Path, "rev-parse", "refs/heads/main"); got != to {
		t.Errorf("main = %s, want %s", got, to)
	}
	if got := gitT(t, f.env, f.proj.Path, "symbolic-ref", "HEAD"); got != "refs/heads/main" {
		t.Errorf("HEAD = %s", got)
	}
	if b, _ := os.ReadFile(filepath.Join(f.proj.Path, "README.md")); strings.Contains(string(b), "set aside") {
		t.Error("the stash came back")
	}
}

func TestUpdateCheckIsReadOnly(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	r := f.record()
	writeFile(t, f.proj.Path, "README.md", "demo\n") // stat-dirty: an optional lock would rewrite the index
	before := treeDigest(t, f.proj.Path)
	plan, err := UpdateCheck(context.Background(), f.deps, f.proj, "origin")
	if err != nil {
		t.Fatal(err)
	}
	if plan != (UpdatePlan{Current: "main", Default: "main"}) {
		t.Fatalf("plan = %+v", plan)
	}
	if got := treeDigest(t, f.proj.Path); got != before {
		t.Error("something was written in the folder")
	}
	allowed := []string{"config", "symbolic-ref", "rev-parse", "status"}
	for _, c := range r.calls {
		sub := gitSubcommand(c.args)
		if !slices.Contains(allowed, sub) {
			t.Errorf("UpdateCheck ran %s", sub)
		}
	}
	if n := len(r.find("status")); n != 1 {
		t.Errorf("%d status", n)
	}
}

// The person may change branch or edit a file during the fetch.
func TestUpdateReadsTheFolderAgainAfterTheFetch(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	f.advance(t, map[string]string{"merged.txt": "x\n"})
	r := f.record()
	r.fake = func(_ context.Context, sub string, args []string) ([]byte, []byte, error, bool) {
		if sub == "fetch" && slices.Contains(args, f.bare) {
			gitT(t, f.env, f.proj.Path, "checkout", "-q", "other")
		}
		return nil, nil, nil, false
	}
	_, err := f.update(t)
	wantClass(t, err, classNotDefault)
	if len(r.find("merge")) != 0 {
		t.Error("a merge ran")
	}
	f.fixNetEmpty(t)
}

func TestUpdateCheckAttrFailureWritesNothing(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	f.advance(t, map[string]string{"merged.txt": "x\n"})
	r := f.record()
	r.fake = func(_ context.Context, sub string, _ []string) ([]byte, []byte, error, bool) {
		if sub == "check-attr" {
			return nil, nil, errors.New("too old"), true
		}
		return nil, nil, nil, false
	}
	before := folderState(t, f)
	_, err := f.update(t)
	wantClass(t, err, classUpdateFailed)
	if len(r.find("merge")) != 0 {
		t.Error("a merge ran")
	}
	if got := folderState(t, f); got != before {
		t.Error("the folder changed")
	}
}

func TestCheckAttrAnswerMustBeComplete(t *testing.T) {
	parallel(t)
	for _, out := range []string{"", "a.txt\x00filter\x00", "a.txt\x00diff\x00unspecified\x00", "b.txt\x00filter\x00unset\x00"} {
		if _, err := filterSet([]byte(out), []string{"a.txt"}); err == nil {
			t.Errorf("answer %q accepted", out)
		}
	}
	for out, want := range map[string]bool{
		"a.txt\x00filter\x00unspecified\x00": false,
		"a.txt\x00filter\x00unset\x00":       false,
		"a.txt\x00filter\x00set\x00":         true,
		"a.txt\x00filter\x00lfs\x00":         true,
	} {
		got, err := filterSet([]byte(out), []string{"a.txt"})
		if err != nil || got != want {
			t.Errorf("answer %q = %v, %v", out, got, err)
		}
	}
}

func TestCheckAttrGoesByBatches(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	files := map[string]string{".gitattributes": "zzz.bin filter=lfs\n", "zzz.bin": "pointer\n"}
	for i := range 248 {
		files[fmt.Sprintf("many/%03d.txt", i)] = "x\n"
	}
	f.advance(t, files)
	r := f.record()
	_, err := f.update(t)
	wantClass(t, err, classFilter)
	calls := r.find("check-attr")
	if len(calls) != 3 {
		t.Fatalf("%d calls, want 3", len(calls))
	}
	sha := gitT(t, f.env, f.site, "rev-parse", "HEAD")
	for _, c := range calls {
		i := slices.Index(c.args, "--")
		if i < 0 {
			t.Fatalf("no -- in %q", c.args)
		}
		if n := len(c.args) - i - 1; n > maxAttrBatch {
			t.Errorf("%d paths", n)
		}
		want := []string{"check-attr", "--source=" + sha, "-z", "filter"}
		if !slices.Equal(c.args[i-len(want):i], want) {
			t.Errorf("argv = %q", c.args[:i])
		}
	}
}

func TestUpdateMergeSurvivesAClosedPage(t *testing.T) {
	f := newFolderFixture(t)
	to := f.advance(t, map[string]string{"merged.txt": "x\n"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := f.record()
	r.fake = func(c context.Context, sub string, _ []string) ([]byte, []byte, error, bool) {
		if sub == "merge" {
			cancel()
			if c.Err() != nil {
				t.Error("closing the page reached the merge")
			}
			dl, ok := c.Deadline()
			if !ok || time.Until(dl) > mergeTimeout {
				t.Errorf("the merge has no delay of its own: %v %v", dl, ok)
			}
		}
		return nil, nil, nil, false
	}
	res, err := UpdateFolder(ctx, f.deps, f.proj, f.bare, "", "origin")
	if err != nil || res.To != to || res.Outcome != FolderUpdated {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

func TestMergeFailureClasses(t *testing.T) {
	parallel(t)
	for out, want := range map[string]string{
		"error: The following untracked working tree files would be overwritten by merge:\n\tx\nAborting\n": classUntracked,
		"error: Updating the following directories would lose untracked files in them:\n\tx\n\nAborting\n":  classUntracked,
		"fatal: Not possible to fast-forward, aborting.\n":                                                  classDiverged,
		"error: Your local changes to the following files would be overwritten by merge:\n\t" + demoCanary:  classUpdateFailed,
		"": classUpdateFailed,
	} {
		f := mergeFailure([]byte(out), nil)
		if f.Class != want {
			t.Errorf("%q: class = %q, want %q", out, f.Class, want)
		}
		if strings.Contains(f.Error(), demoCanary) {
			t.Errorf("the failure kept git's output: %v", f)
		}
	}
}

// --- Proof (R25) ---

// fixBranch makes the commit of a fix on a branch from main, and comes back.
func fixBranch(t *testing.T, f fixture, body string) string {
	t.Helper()
	root := f.proj.Path
	gitT(t, f.env, root, "checkout", "-q", "-b", demoBranch)
	writeFile(t, root, "src/fixed.php", body)
	gitT(t, f.env, root, "add", "-A")
	gitT(t, f.env, root, "commit", "-q", "-m", "fix")
	sha := gitT(t, f.env, root, "rev-parse", "HEAD")
	gitT(t, f.env, root, "checkout", "-q", "main")
	return sha
}

// mainMoves commits something else on main, so that a replayed commit differs.
func mainMoves(t *testing.T, f fixture) {
	t.Helper()
	writeFile(t, f.proj.Path, "elsewhere.txt", "something else\n")
	gitT(t, f.env, f.proj.Path, "add", "-A")
	gitT(t, f.env, f.proj.Path, "commit", "-q", "-m", "something else")
}

func wantMerged(t *testing.T, f fixture, sha string, want bool) {
	t.Helper()
	got, err := IsMerged(context.Background(), f.deps, f.proj, sha)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("IsMerged = %v, want %v", got, want)
	}
}

func TestIsMergedAfterMergeCommit(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	sha := fixBranch(t, f, "fixed\n")
	mainMoves(t, f)
	wantMerged(t, f, sha, false)
	gitT(t, f.env, f.proj.Path, "merge", "-q", "--no-ff", "--no-edit", demoBranch)
	wantMerged(t, f, sha, true)
}

func TestIsMergedAfterFastForward(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	sha := fixBranch(t, f, "fixed\n")
	gitT(t, f.env, f.proj.Path, "merge", "-q", "--ff-only", demoBranch)
	wantMerged(t, f, sha, true)
}

func TestIsMergedAfterSquash(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	sha := fixBranch(t, f, "fixed\n")
	mainMoves(t, f)
	gitT(t, f.env, f.proj.Path, "merge", "-q", "--squash", demoBranch)
	gitT(t, f.env, f.proj.Path, "commit", "-q", "-m", "squashed on the site")
	head := gitT(t, f.env, f.proj.Path, "rev-parse", "HEAD")
	if cmd := exec.Command("git", "-C", f.proj.Path, "merge-base", "--is-ancestor", sha, head); cmd.Run() == nil {
		t.Fatal("the fix commit is an ancestor: this test proves nothing")
	}
	wantMerged(t, f, sha, true)
}

func TestIsMergedAfterRebase(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	sha := fixBranch(t, f, "fixed\n")
	mainMoves(t, f)
	gitT(t, f.env, f.proj.Path, "cherry-pick", demoBranch) // what "Rebase" does on a site
	wantMerged(t, f, sha, true)
}

func TestIsMergedFalseForAnotherChange(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	sha := fixBranch(t, f, "fixed\n")
	writeFile(t, f.proj.Path, "src/fixed.php", "fixed another way\n")
	gitT(t, f.env, f.proj.Path, "add", "-A")
	gitT(t, f.env, f.proj.Path, "commit", "-q", "-m", "another change")
	wantMerged(t, f, sha, false)
}

// A squash with other commits is not the same change: it stays inconclusive.
func TestIsMergedFalseForASquashWithOtherCommits(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	sha := fixBranch(t, f, "fixed\n")
	gitT(t, f.env, f.proj.Path, "merge", "-q", "--squash", demoBranch)
	writeFile(t, f.proj.Path, "more.txt", "more\n")
	gitT(t, f.env, f.proj.Path, "add", "-A")
	gitT(t, f.env, f.proj.Path, "commit", "-q", "-m", "fix and more")
	wantMerged(t, f, sha, false)
}

// git cherry leaves merge commits out: its answer is empty.
func TestIsMergedFalseOnEmptyCherry(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	root := f.proj.Path
	first := gitT(t, f.env, root, "rev-parse", "HEAD")
	mainMoves(t, f)
	// A merge commit whose two parents are older than it and already on main.
	sha := gitT(t, f.env, root, "commit-tree", "HEAD^{tree}", "-p", "HEAD", "-p", first, "-m", "merge")
	if out := gitT(t, f.env, root, "cherry", "HEAD", sha, sha+"^"); out != "" {
		t.Fatalf("git cherry said %q: this test proves nothing", out)
	}
	wantMerged(t, f, sha, false)
}

// A merge commit whose side holds several commits: several lines are not one fix.
func TestIsMergedFalseOnSeveralLines(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	root := f.proj.Path
	gitT(t, f.env, root, "checkout", "-q", "-b", "side")
	for _, name := range []string{"a.txt", "b.txt"} {
		writeFile(t, root, name, name+"\n")
		gitT(t, f.env, root, "add", "-A")
		gitT(t, f.env, root, "commit", "-q", "-m", name)
	}
	gitT(t, f.env, root, "checkout", "-q", "main")
	mainMoves(t, f)
	gitT(t, f.env, root, "checkout", "-q", "-b", "merged", "main")
	gitT(t, f.env, root, "merge", "-q", "--no-ff", "--no-edit", "side")
	sha := gitT(t, f.env, root, "rev-parse", "HEAD")
	gitT(t, f.env, root, "checkout", "-q", "main")
	gitT(t, f.env, root, "cherry-pick", "side~1", "side")
	out := gitT(t, f.env, root, "cherry", "HEAD", sha, sha+"^")
	if strings.Count(out, "\n") == 0 || strings.Contains(out, "+") {
		t.Fatalf("git cherry said %q: this test proves nothing", out)
	}
	wantMerged(t, f, sha, false)
}

func TestIsMergedFalseForACommitWithoutParent(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	root := f.proj.Path
	gitT(t, f.env, root, "checkout", "-q", "--orphan", "alone")
	gitT(t, f.env, root, "commit", "-q", "--allow-empty", "-m", "alone")
	sha := gitT(t, f.env, root, "rev-parse", "HEAD")
	gitT(t, f.env, root, "checkout", "-q", "-f", "main")
	wantMerged(t, f, sha, false)
}

func TestPrepareAndApplyNeverPushNorMerge(t *testing.T) {
	f := newFixture(t)
	r := &gitRecorder{}
	f.deps.Exec = r.exec
	c := prepare(t, f)
	writeFile(t, c.Dir, "fix.txt", "fix\n")
	sha, err := Commit(context.Background(), f.deps, c, "fix")
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), f.deps, f.proj, c, sha, demoBranch); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) == 0 {
		t.Fatal("no command recorded")
	}
	for _, sub := range []string{"push", "merge", "status", "cherry"} {
		if n := len(r.find(sub)); n != 0 {
			t.Errorf("%d git %s", n, sub)
		}
	}
}

// newFolderFixtureIn is newFolderFixture for a case that runs in parallel
// with others: the person's home is the one its parent made with
// isolatePerson, and the case writes nothing in it.
func newFolderFixtureIn(t *testing.T, home string) folderFixture {
	t.Helper()
	return remoteFrom(t, "folder", home)
}
