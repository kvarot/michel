package workcopy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
)

// personBytes is what a person's own file holds: line endings and bytes a rewrite
// would change, and a secret that must stay where it is.
const personBytes = "SECRET=the person\r\n\x00\xff\xfe end, no newline"

// sync brings files into the project and the remote: the state before the update.
func (f folderFixture) sync(t *testing.T, files map[string]string) {
	t.Helper()
	f.advance(t, files)
	gitT(t, f.env, f.proj.Path, "pull", "-q", "--ff-only", "origin", "main")
}

// addSubmodule puts a populated submodule at sub, on both sides.
func (f folderFixture) addSubmodule(t *testing.T, sub string) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "src")
	gitT(t, f.env, filepath.Dir(src), "init", "-q", "-b", "main", src)
	writeFile(t, src, "s.txt", "aaaa\n")
	gitT(t, f.env, src, "add", "-A")
	gitT(t, f.env, src, "commit", "-q", "-m", "s")
	gitT(t, f.env, f.proj.Path, "-c", "protocol.file.allow=always", "submodule", "--quiet", "add", filepath.ToSlash(src), sub)
	gitT(t, f.env, f.proj.Path, "commit", "-q", "-m", "submodule")
	gitT(t, f.env, f.proj.Path, "push", "-q", f.bare, "main")
	gitT(t, f.env, f.site, "pull", "-q", "--ff-only", "origin", "main")
}

// siteRemoves removes a tracked path on the site and adds files, in one commit.
func (f folderFixture) siteRemoves(t *testing.T, path string, files map[string]string) {
	t.Helper()
	gitT(t, f.env, f.site, "rm", "-q", "-r", "--cached", path)
	if err := os.RemoveAll(filepath.Join(f.site, path)); err != nil {
		t.Fatal(err)
	}
	f.advance(t, files)
}

// inTheWay is one thing of the person's where the update wants to write.
type inTheWay struct {
	name     string
	class    string
	path     string // what the refusal names
	arrange  func(t *testing.T, f folderFixture)
	incoming func(t *testing.T, f folderFixture)
	keep     []string // the person's files, each holding personBytes
	gitLoses bool     // git merge without Michel's options destroys it: the control
	home     bool     // writes in the person's home: runs alone, before the others
}

func inTheWayCases() []inTheWay {
	ignore := func(line string) func(*testing.T, folderFixture) {
		return func(t *testing.T, f folderFixture) {
			t.Helper()
			f.sync(t, map[string]string{".gitignore": line + "\n"})
		}
	}
	bring := func(path string) func(*testing.T, folderFixture) {
		return func(t *testing.T, f folderFixture) {
			t.Helper()
			f.advanceForced(t, path)
		}
	}
	return []inTheWay{
		{name: "ignored file, the update tracks it", class: classIgnored, path: "local.cfg",
			arrange: ignore("local.cfg"), incoming: bring("local.cfg"),
			keep: []string{"local.cfg"}, gitLoses: true},
		{name: "ignored file, a settings file", class: classIgnored, path: "prod.env",
			arrange: ignore("prod.env"), incoming: bring("prod.env"),
			keep: []string{"prod.env"}, gitLoses: true},
		{name: "ignored file, inside an ignored folder", class: classIgnored, path: "build/local.txt",
			arrange: ignore("build/"), incoming: bring("build/local.txt"),
			keep: []string{"build/local.txt"}, gitLoses: true},
		{name: "ignored folder, the update makes it a file", class: classIgnored, path: "build",
			arrange: ignore("build/"), incoming: bring("build"),
			keep: []string{"build/local.txt", "build/deep/other.txt"}, gitLoses: true},
		{name: "ignored file, the update makes it a folder", class: classIgnored, path: "local.cfg",
			arrange: ignore("local.cfg"), incoming: bring("local.cfg/inside.txt"),
			keep: []string{"local.cfg"}, gitLoses: true},
		{name: "ignored file, in a folder the update makes a file", class: classIgnored, path: "d",
			arrange: func(t *testing.T, f folderFixture) {
				t.Helper()
				f.sync(t, map[string]string{".gitignore": "*.log\n", "d/tracked.txt": "x\n"})
			},
			incoming: func(t *testing.T, f folderFixture) {
				t.Helper()
				f.siteRemoves(t, "d", map[string]string{"d": "now a file\n"})
			},
			keep: []string{"d/mine.log"}, gitLoses: true},
		{name: "ignored by .git/info/exclude", class: classIgnored, path: "local.cfg",
			arrange: func(t *testing.T, f folderFixture) {
				t.Helper()
				writeFile(t, f.proj.Path, ".git/info/exclude", "local.cfg\n")
			},
			incoming: bring("local.cfg"),
			keep:     []string{"local.cfg"}, gitLoses: true},
		{name: "ignored by the person's own excludes file", class: classIgnored, path: "local.cfg", home: true,
			arrange: func(t *testing.T, f folderFixture) {
				t.Helper()
				writeFile(t, f.home, "excludes", "local.cfg\n")
				writeFile(t, f.home, ".gitconfig", "[core]\n\texcludesFile = "+filepath.ToSlash(filepath.Join(f.home, "excludes"))+"\n")
			},
			incoming: bring("local.cfg"),
			keep:     []string{"local.cfg"}, gitLoses: true},
		{name: "untracked file", class: classUntracked, path: "changed.txt",
			incoming: bring("changed.txt"),
			keep:     []string{"changed.txt"}},
		{name: "untracked folder, the update makes it a file", class: classUntracked, path: "changed.txt",
			incoming: bring("changed.txt"),
			keep:     []string{"changed.txt/mine.txt"}},
		{name: "untracked file, the update makes it a folder", class: classUntracked, path: "changed.txt",
			incoming: bring("changed.txt/inside.txt"),
			keep:     []string{"changed.txt"}},
		{name: "submodule edited, the update makes it a file", class: classSubmodule, path: "sub",
			arrange: func(t *testing.T, f folderFixture) {
				t.Helper()
				f.addSubmodule(t, "sub")
			},
			incoming: func(t *testing.T, f folderFixture) {
				t.Helper()
				f.siteRemoves(t, "sub", map[string]string{"sub": "now a file\n"})
			},
			keep: []string{"sub/s.txt"}, gitLoses: true},
		{name: "submodule with a file of the person's, the update makes it a file", class: classSubmodule, path: "sub",
			arrange: func(t *testing.T, f folderFixture) {
				t.Helper()
				f.addSubmodule(t, "sub")
			},
			incoming: func(t *testing.T, f folderFixture) {
				t.Helper()
				f.siteRemoves(t, "sub", map[string]string{"sub": "now a file\n"})
			},
			keep: []string{"sub/mine.txt"}, gitLoses: true},
		{name: "submodule, the update puts a folder there", class: classSubmodule, path: "sub",
			arrange: func(t *testing.T, f folderFixture) {
				t.Helper()
				f.addSubmodule(t, "sub")
			},
			incoming: func(t *testing.T, f folderFixture) {
				t.Helper()
				f.siteRemoves(t, "sub", map[string]string{"sub/x.txt": "a folder now\n"})
			},
			keep: []string{"sub/s.txt"}},
	}
}

// Losing a person's file is the worst this feature can do. Whatever stands where
// the update wants to write, the update refuses, says what stands there, and the
// file is byte for byte what it was, with the same date.
func TestUpdateLeavesWhatIsInTheWay(t *testing.T) {
	home := isolatePerson(t)
	for _, c := range inTheWayCases() {
		t.Run(c.name, func(t *testing.T) {
			var f folderFixture
			if c.home {
				f = newFolderFixture(t)
			} else {
				t.Parallel()
				f = newFolderFixtureIn(t, home)
			}
			if c.arrange != nil {
				c.arrange(t, f)
			}
			c.incoming(t, f)
			to := gitT(t, f.env, f.site, "rev-parse", "HEAD")
			past := time.Now().Add(-time.Hour).Truncate(time.Second)
			for _, rel := range c.keep {
				writeFile(t, f.proj.Path, rel, personBytes)
				if err := os.Chtimes(filepath.Join(f.proj.Path, rel), past, past); err != nil {
					t.Fatal(err)
				}
			}
			head := gitT(t, f.env, f.proj.Path, "rev-parse", "HEAD")
			before := folderState(t, f)

			res, err := f.update(t)

			if err == nil {
				t.Errorf("no refusal: %+v", res)
			} else {
				wantClass(t, err, c.class)
				var gf *GitFailure
				if errors.As(err, &gf) && gf.Path != c.path {
					t.Errorf("Path = %q, want %q", gf.Path, c.path)
				}
			}
			for _, rel := range c.keep {
				full := filepath.Join(f.proj.Path, rel)
				b, err := os.ReadFile(full)
				if err != nil {
					t.Fatalf("%s is gone: %v", rel, err)
				}
				if string(b) != personBytes {
					t.Errorf("%s changed: %q", rel, b)
				}
				info, err := os.Stat(full)
				if err != nil {
					t.Fatal(err)
				}
				if !info.ModTime().Equal(past) {
					t.Errorf("%s was written again: %v, want %v", rel, info.ModTime(), past)
				}
			}
			if got := folderState(t, f); got != before {
				t.Errorf("the folder changed:\n%s\nthen\n%s", before, got)
			}
			if got := gitT(t, f.env, f.proj.Path, "rev-parse", "HEAD"); got != head {
				t.Errorf("HEAD moved to %s", got)
			}
			f.fixNetEmpty(t)

			if !c.gitLoses {
				return
			}
			// The control: plain git really destroys it, so the refusal means something.
			_, _ = f.personGit(t, "merge", "--ff-only", "--quiet", to)
			lost := false
			for _, rel := range c.keep {
				b, err := os.ReadFile(filepath.Join(f.proj.Path, rel))
				lost = lost || err != nil || string(b) != personBytes
			}
			if !lost {
				t.Error("control: plain git merge lost nothing, so this case proves nothing")
			}
		})
	}
}

// A file named in another case on a disk that does not tell them apart.
func TestUpdateLeavesAnIgnoredFileInAnotherCase(t *testing.T) {
	parallel(t)
	if runtime.GOOS != "windows" {
		t.Skip("needs a disk that does not tell the case of a name")
	}
	f := newFolderFixture(t)
	f.sync(t, map[string]string{".gitignore": "prod.env\n"})
	f.advanceForced(t, "prod.env")
	writeFile(t, f.proj.Path, "PROD.ENV", personBytes)
	_, err := f.update(t)
	wantClass(t, err, classIgnored)
	if b, err := os.ReadFile(filepath.Join(f.proj.Path, "PROD.ENV")); err != nil || string(b) != personBytes {
		t.Errorf("PROD.ENV = %q, %v", b, err)
	}
}

// A file that merely sits next to what arrives is no reason to refuse.
// The advice of api.git.submodule_hint: a clean submodule is refused because Michel
// does not look inside it, and the update runs once its folder is empty.
func TestUpdateRunsOnceTheSubmoduleFolderIsEmpty(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	f.addSubmodule(t, "sub")
	f.siteRemoves(t, "sub", map[string]string{"sub": "now a file\n"})
	to := gitT(t, f.env, f.site, "rev-parse", "HEAD")
	var gf *GitFailure
	if _, err := f.update(t); !errors.As(err, &gf) || gf.Class != classSubmodule || gf.Path != "sub" {
		t.Fatalf("clean submodule: %v, %+v", err, gf)
	}
	entries, err := os.ReadDir(filepath.Join(f.proj.Path, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(f.proj.Path, "sub", e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	res, err := f.update(t)
	if err != nil || res.To != to {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if b, err := os.ReadFile(filepath.Join(f.proj.Path, "sub")); err != nil || strings.TrimSpace(string(b)) != "now a file" {
		t.Errorf("sub = %q, %v", b, err)
	}
}

func TestUpdateIgnoresWhatIsNotInTheWay(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	f.sync(t, map[string]string{".gitignore": "*.log\nlocal.cfg\n"})
	writeFile(t, f.proj.Path, "local.cfg", personBytes)
	writeFile(t, f.proj.Path, "d/mine.log", personBytes)
	writeFile(t, f.proj.Path, "untracked.txt", personBytes)
	to := f.advance(t, map[string]string{"d/new.txt": "x\n"})
	res, err := f.update(t)
	if err != nil || res.To != to {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	for _, rel := range []string{"local.cfg", "d/mine.log", "untracked.txt"} {
		if b, err := os.ReadFile(filepath.Join(f.proj.Path, rel)); err != nil || string(b) != personBytes {
			t.Errorf("%s = %q, %v", rel, b, err)
		}
	}
}

// signedOnSite rewrites the site's last commit with a signature, as a merge on a
// host's site carries one, and pushes it. Nothing checks the signature's value:
// a program is started to read it, which is the point.
func (f folderFixture) signedOnSite(t *testing.T) string {
	t.Helper()
	raw := gitT(t, f.env, f.site, "cat-file", "commit", "HEAD")
	header, body, ok := strings.Cut(raw, "\n\n")
	if !ok {
		t.Fatalf("commit = %q", raw)
	}
	signed := header + "\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n demo\n -----END PGP SIGNATURE-----\n\n" + body + "\n"
	file := filepath.Join(t.TempDir(), "commit")
	if err := os.WriteFile(file, []byte(signed), 0o644); err != nil {
		t.Fatal(err)
	}
	sha := gitT(t, f.env, f.site, "hash-object", "-t", "commit", "-w", filepath.ToSlash(file))
	gitT(t, f.env, f.site, "update-ref", "refs/heads/main", sha)
	gitT(t, f.env, f.site, "reset", "-q", "--hard", sha)
	gitT(t, f.env, f.site, "push", "-q", "-f", "origin", "main")
	return sha
}

// branch.<name>.mergeOptions is read before the command line. Each value here must
// change nothing: no program, a real fast-forward, nothing left in the index.
func TestUpdateIsDeafToMergeOptions(t *testing.T) {
	home := isolatePerson(t)
	for _, options := range []string{
		"--verify-signatures", "--squash", "--no-commit", "--no-ff", "-s ours", "--strategy=demo-none",
		"--overwrite-ignore", "--autostash", "--verify-signatures --squash --no-ff",
	} {
		t.Run(options, func(t *testing.T) {
			t.Parallel()
			f := newFolderFixtureIn(t, home)
			script, mark := witness(t)
			f.advance(t, map[string]string{"merged.txt": "x\n"})
			to := f.signedOnSite(t)
			gitT(t, f.env, f.proj.Path, "config", "gpg.program", script)
			gitT(t, f.env, f.proj.Path, "config", "branch.main.mergeOptions", options)

			res, err := f.update(t)
			if err != nil || res.Outcome != FolderUpdated || res.To != to {
				t.Fatalf("res = %+v, err = %v", res, err)
			}
			noMark(t, mark, "the program of gpg.program")
			if got := gitT(t, f.env, f.proj.Path, "rev-parse", "HEAD"); got != to {
				t.Errorf("HEAD = %s, want %s", got, to)
			}
			if out, err := f.personGit(t, "status", "--porcelain"); err != nil || out != "" {
				t.Errorf("status = %q, %v", out, err)
			}
			if options == "--verify-signatures" {
				// The control: git does start that program on this commit.
				cmd := exec.Command("git", "-C", f.proj.Path, "verify-commit", to)
				cmd.Env = f.env
				_ = cmd.Run()
				if _, err := os.Stat(mark); err != nil {
					t.Error("control: the signature started no program, so this test proves nothing")
				}
			}
		})
	}
}

// A key behind an include that depends on the person's home is seen as git status
// sees it (R34).
func TestConfigCheckReadsWhatStatusReads(t *testing.T) {
	f := newFolderFixture(t)
	home := filepath.Dir(f.proj.Path)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	f.home = home
	f.sync(t, map[string]string{".gitattributes": "data.txt filter=x\n", "data.txt": "aaaa\n"})
	script, mark := witness(t)
	writeFile(t, f.proj.Path, ".git/evil.cfg", "[filter \"x\"]\n\tclean = "+script+"\n")
	gitT(t, f.env, f.proj.Path, "config", "includeIf.gitdir:~/**.path", "evil.cfg")
	writeFile(t, f.proj.Path, "data.txt", "bbbb\n")
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(filepath.Join(f.proj.Path, "data.txt"), future, future); err != nil {
		t.Fatal(err)
	}

	_, err := UpdateCheck(context.Background(), f.deps, f.proj, "origin")
	wantClass(t, err, classFilter)
	noMark(t, mark, "the clean program, in UpdateCheck")
	_, err = f.update(t)
	wantClass(t, err, classFilter)
	noMark(t, mark, "the clean program, in the update")

	// The runner sees it too, for a command that does not go through the check.
	h, err := ensureHome(f.deps)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.workGit(context.Background(), f.deps, f.proj, "status", "--porcelain=v1"); !errors.Is(err, errProjectConfig) {
		t.Errorf("status under that key: %v", err)
	}
	noMark(t, mark, "the clean program, in the runner")

	// The control: plain git status, with the person's home, runs it.
	if out, err := f.personGit(t, "status", "--porcelain"); err != nil {
		t.Fatalf("status: %v %s", err, out)
	}
	if _, err := os.Stat(mark); err != nil {
		t.Error("control: plain git status ran nothing, so this test proves nothing")
	}
}

// The attributes of core.attributesFile count for the refusal as they do for merge.
func TestUpdateSeesTheFilterOfAnAttributesFile(t *testing.T) {
	parallel(t)
	for _, where := range []string{"global", "local"} {
		t.Run(where, func(t *testing.T) {
			f := newFolderFixture(t)
			to := f.advance(t, map[string]string{"changed.txt": "from the site\n"})
			script, mark := witness(t)
			attrs := filepath.ToSlash(filepath.Join(t.TempDir(), "attributes"))
			writeFile(t, filepath.Dir(attrs), "attributes", "changed.txt filter=w\n")
			person := "[filter \"w\"]\n\tsmudge = " + script + "\n"
			if where == "global" {
				person += "[core]\n\tattributesFile = " + attrs + "\n"
			} else {
				gitT(t, f.env, f.proj.Path, "config", "core.attributesFile", attrs)
			}
			writeFile(t, f.home, ".gitconfig", person)

			before := folderState(t, f)
			_, err := f.update(t)
			wantClass(t, err, classFilter)
			noMark(t, mark, "the smudge program")
			if got := folderState(t, f); got != before {
				t.Error("the folder changed")
			}

			// The control: plain git merge runs it.
			if out, err := f.personGit(t, "merge", "--ff-only", "--quiet", to); err != nil {
				t.Logf("plain merge: %v %s", err, out)
			}
			if _, err := os.Stat(mark); err != nil {
				t.Error("control: plain git merge ran nothing, so this test proves nothing")
			}
		})
	}
}

// The fetch of the temporary repository into the project reads the project's
// configuration: whatever it says, nothing runs and nothing else is reached.
func TestFetchIntoProjectRunsNothing(t *testing.T) {
	parallel(t)
	apply := func(t *testing.T, h hostile) error {
		t.Helper()
		c := prepare(t, h.fixture)
		writeFile(t, c.Dir, "fix2.txt", "fix\n")
		sha, err := Commit(context.Background(), h.deps, c, "fix")
		if err != nil {
			t.Fatal(err)
		}
		return Apply(context.Background(), h.deps, h.proj, c, sha, "michel/fix-01jdemo01")
	}
	t.Run("an address rewritten from the drive letter", func(t *testing.T) {
		h := newHostile(t)
		prefix := filepath.VolumeName(h.deps.DataDir)
		if prefix == "" {
			prefix = "/"
		}
		h.set(t, "core.sshCommand", h.run("core.sshCommand"))
		h.set(t, "url.ssh://example.test/x.insteadOf", prefix)
		if err := apply(t, h); err == nil {
			t.Error("the rewritten fetch reached something")
		}
		h.wantNothingRan(t, "Apply")
		h.advance(t, map[string]string{"merged.txt": "x\n"})
		if _, err := h.update(t); err == nil {
			t.Error("the rewritten fetch reached something")
		}
		h.wantNothingRan(t, "UpdateFolder")
	})
	t.Run("alternates and core.alternateRefsCommand", func(t *testing.T) {
		h := newHostile(t)
		writeFile(t, h.proj.Path, ".git/objects/info/alternates", filepath.ToSlash(filepath.Join(h.site, ".git", "objects"))+"\n")
		h.set(t, "core.alternateRefsCommand", h.run("core.alternateRefsCommand"))
		if err := apply(t, h); err != nil {
			t.Fatal(err)
		}
		h.wantNothingRan(t, "Apply")
		to := h.advance(t, map[string]string{"merged.txt": "x\n"})
		res, err := h.update(t)
		if err != nil || res.To != to {
			t.Fatalf("res = %+v, err = %v", res, err)
		}
		h.wantNothingRan(t, "UpdateFolder")
	})
}

// A merge that fails after writing says so; one that wrote nothing says that.
func TestUpdateFailureSaysWhetherFilesChanged(t *testing.T) {
	parallel(t)
	failing := func(t *testing.T, f *folderFixture, write func()) {
		t.Helper()
		r := f.record()
		r.fake = func(_ context.Context, sub string, _ []string) ([]byte, []byte, error, bool) {
			if sub == "merge" {
				write()
				return nil, []byte("error: Unable to write, " + demoCanary + "\n"), errors.New("exit status 1"), true
			}
			return nil, nil, nil, false
		}
	}
	t.Run("files changed", func(t *testing.T) {
		f := newFolderFixture(t)
		f.advance(t, map[string]string{"README.md": "from the site\n"})
		failing(t, &f, func() { writeFile(t, f.proj.Path, "README.md", "half of the update\n") })
		_, err := f.update(t)
		wantClass(t, err, classUpdatePartial)
		if strings.Contains(err.Error(), demoCanary) {
			t.Errorf("the failure kept git's output: %v", err)
		}
	})
	t.Run("nothing changed", func(t *testing.T) {
		f := newFolderFixture(t)
		f.advance(t, map[string]string{"README.md": "from the site\n"})
		failing(t, &f, func() {})
		before := folderState(t, f)
		_, err := f.update(t)
		wantClass(t, err, classUpdateFailed)
		if got := folderState(t, f); got != before {
			t.Error("the folder changed")
		}
	})
	t.Run("the state cannot be read after the failure", func(t *testing.T) {
		f := newFolderFixture(t)
		f.advance(t, map[string]string{"README.md": "from the site\n"})
		r := f.record()
		merged := false
		r.fake = func(_ context.Context, sub string, _ []string) ([]byte, []byte, error, bool) {
			switch {
			case sub == "merge":
				merged = true
				return nil, nil, errors.New("exit status 1"), true
			case sub == "status" && merged:
				return nil, nil, errors.New("exit status 128"), true
			}
			return nil, nil, nil, false
		}
		_, err := f.update(t)
		wantClass(t, err, classUpdatePartial)
	})
}

// The real thing: another program holds a file open, git stops halfway.
func TestUpdateLockedFileSaysPartial(t *testing.T) {
	parallel(t)
	if runtime.GOOS != "windows" {
		t.Skip("only Windows refuses to replace a file another program holds")
	}
	f := newFolderFixture(t)
	f.sync(t, map[string]string{"a.txt": "old a\n", "z.txt": "old z\n"})
	f.advance(t, map[string]string{"a.txt": "new a\n", "z.txt": "new z\n"})
	held, err := os.Open(filepath.Join(f.proj.Path, "z.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	head := gitT(t, f.env, f.proj.Path, "rev-parse", "HEAD")

	_, err = f.update(t)
	wantClass(t, err, classUpdatePartial)
	if got := gitT(t, f.env, f.proj.Path, "rev-parse", "HEAD"); got != head {
		t.Errorf("HEAD moved to %s", got)
	}
	if b, err := os.ReadFile(filepath.Join(f.proj.Path, "z.txt")); err != nil || string(b) != "old z\n" {
		t.Errorf("z.txt = %q, %v", b, err)
	}
}

func TestPartialAndIgnoredHaveTheirSentences(t *testing.T) {
	parallel(t)
	for _, class := range []string{classUpdatePartial, classIgnored} {
		for _, key := range []string{"api.git." + class, "api.git." + class + "_hint"} {
			if !i18n.Has(key) {
				t.Errorf("%s is not in the catalogs", key)
			}
			if i18n.T(i18n.FR, key) == i18n.T(i18n.EN, key) {
				t.Errorf("%s is not translated", key)
			}
		}
	}
}

// A stopped git am keeps HEAD on the branch and the tree clean.
func TestUpdateRefusesAStoppedAm(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	f.advance(t, map[string]string{"merged.txt": "x\n"})
	patch := filepath.Join(t.TempDir(), "demo.patch")
	body := "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\n" +
		"From: demo <demo@example.test>\nDate: Mon, 1 Jan 2024 00:00:00 +0000\nSubject: [PATCH] demo\n\n---\n" +
		"diff --git a/nothing-here.txt b/nothing-here.txt\n--- a/nothing-here.txt\n+++ b/nothing-here.txt\n@@ -1 +1 @@\n-old\n+new\n-- \n2.46.2\n"
	if err := os.WriteFile(patch, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.personGit(t, "am", filepath.ToSlash(patch)); err == nil {
		t.Fatal("git am did not stop: this test proves nothing")
	}
	if _, err := os.Stat(filepath.Join(f.proj.Path, ".git", "rebase-apply")); err != nil {
		t.Fatalf("git am left no marker: %v", err)
	}
	before := folderState(t, f)
	_, err := f.update(t)
	wantClass(t, err, classInProgress)
	if got := folderState(t, f); got != before {
		t.Error("the folder changed")
	}
}

// --- Proof (R25, R56) ---

// An empty commit has no change: another empty commit on main is not its proof.
func TestIsMergedFalseForAnEmptyFix(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	root := f.proj.Path
	gitT(t, f.env, root, "checkout", "-q", "-b", "side")
	gitT(t, f.env, root, "commit", "-q", "--allow-empty", "-m", "empty fix")
	sha := gitT(t, f.env, root, "rev-parse", "HEAD")
	gitT(t, f.env, root, "checkout", "-q", "main")
	mainMoves(t, f)
	gitT(t, f.env, root, "commit", "-q", "--allow-empty", "-m", "another empty commit")
	if out := gitT(t, f.env, root, "cherry", "HEAD", sha, sha+"^"); !strings.HasPrefix(out, "- ") {
		t.Fatalf("git cherry said %q: this test proves nothing", out)
	}
	wantMerged(t, f, sha, false)
}

// git cherry may name a commit of the side of a merge: its patch is not the
// merge's change.
func TestIsMergedFalseWhenCherryNamesAnotherCommit(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	root := f.proj.Path
	gitT(t, f.env, root, "checkout", "-q", "-b", "side")
	writeFile(t, root, "a.txt", "a\n")
	gitT(t, f.env, root, "add", "-A")
	gitT(t, f.env, root, "commit", "-q", "-m", "a")
	gitT(t, f.env, root, "checkout", "-q", "main")
	mainMoves(t, f)
	gitT(t, f.env, root, "checkout", "-q", "-b", "merged", "main")
	gitT(t, f.env, root, "merge", "-q", "--no-ff", "--no-edit", "side")
	sha := gitT(t, f.env, root, "rev-parse", "HEAD")
	gitT(t, f.env, root, "checkout", "-q", "main")
	gitT(t, f.env, root, "cherry-pick", "side")
	side := gitT(t, f.env, root, "rev-parse", "side")
	if out := gitT(t, f.env, root, "cherry", "HEAD", sha, sha+"^"); out != "- "+side {
		t.Fatalf("git cherry said %q: this test proves nothing", out)
	}
	wantMerged(t, f, sha, false)
}

// R56: the test is a patch id, and a patch id ignores whitespace and where the
// lines are. A squash needs it. These two are false "merged" answers it gives,
// accepted: Prove also needs the tool to stop seeing the flaw.
func TestIsMergedPatchIDIgnoresWhitespaceAndPosition(t *testing.T) {
	parallel(t)
	t.Run("whitespace", func(t *testing.T) {
		f := newFixture(t)
		root := f.proj.Path
		writeFile(t, root, "src/w.py", "if ready:\n    start()\nend()\n")
		gitT(t, f.env, root, "add", "-A")
		gitT(t, f.env, root, "commit", "-q", "-m", "base")
		gitT(t, f.env, root, "checkout", "-q", "-b", "side")
		writeFile(t, root, "src/w.py", "if ready:\n    start()\n    check()\nend()\n")
		gitT(t, f.env, root, "commit", "-q", "-am", "inside the if")
		sha := gitT(t, f.env, root, "rev-parse", "HEAD")
		gitT(t, f.env, root, "checkout", "-q", "main")
		writeFile(t, root, "src/w.py", "if ready:\n    start()\ncheck()\nend()\n")
		gitT(t, f.env, root, "commit", "-q", "-am", "outside the if")
		wantMerged(t, f, sha, true)
	})
	t.Run("position", func(t *testing.T) {
		f := newFixture(t)
		root := f.proj.Path
		block := "start\nctx1\nctx2\nctx3\nold\nctx4\nctx5\nctx6\nend\n"
		writeFile(t, root, "src/p.txt", block+"-\n-\n-\n-\n-\n-\n-\n"+block)
		gitT(t, f.env, root, "add", "-A")
		gitT(t, f.env, root, "commit", "-q", "-m", "base")
		first := strings.Replace(block, "old", "new", 1)
		gitT(t, f.env, root, "checkout", "-q", "-b", "side")
		writeFile(t, root, "src/p.txt", first+"-\n-\n-\n-\n-\n-\n-\n"+block)
		gitT(t, f.env, root, "commit", "-q", "-am", "the first block")
		sha := gitT(t, f.env, root, "rev-parse", "HEAD")
		gitT(t, f.env, root, "checkout", "-q", "main")
		writeFile(t, root, "src/p.txt", block+"-\n-\n-\n-\n-\n-\n-\n"+first)
		gitT(t, f.env, root, "commit", "-q", "-am", "the second block")
		wantMerged(t, f, sha, true)
	})
}

func TestUpdateArgvIsDeafToTheBranchOptions(t *testing.T) {
	parallel(t)
	f := newFolderFixture(t)
	to := f.advance(t, map[string]string{"merged.txt": "x\n"})
	r := f.record()
	if _, err := f.update(t); err != nil {
		t.Fatal(err)
	}
	merges := r.find("merge")
	if len(merges) != 1 {
		t.Fatalf("%d merges", len(merges))
	}
	if !slices.Contains(merges[0].args, "branch.main.mergeOptions=") {
		t.Errorf("merge argv = %q", merges[0].args)
	}
	if merges[0].args[len(merges[0].args)-1] != to {
		t.Errorf("merge argv = %q", merges[0].args)
	}
}

// advanceForced tracks a file on the site, even one its .gitignore names: a person
// keeps it ignored, the site's commit adds it anyway.
func (f folderFixture) advanceForced(t *testing.T, path string) {
	t.Helper()
	writeFile(t, f.site, path, "SECRET=template\n")
	gitT(t, f.env, f.site, "add", "-f", path)
	gitT(t, f.env, f.site, "commit", "-q", "-m", "on the site")
	gitT(t, f.env, f.site, "push", "-q", "origin", "main")
}
