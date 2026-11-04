package workcopy

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
)

// hostile is a project whose .git/config names a program for every key that
// can name one. The program writes the key's name in a single mark file.
type hostile struct {
	folderFixture
	script, mark string
}

// run is the value that makes git start the witness and say which key did it.
func (h hostile) run(key string) string { return "sh '" + h.script + "' " + key }

func (h hostile) set(t *testing.T, key, value string) {
	t.Helper()
	gitT(t, h.env, h.proj.Path, "config", "--local", "--add", key, value)
}

// fired says which keys ran something.
func (h hostile) fired() string {
	b, err := os.ReadFile(h.mark)
	if err != nil {
		return ""
	}
	return strings.Join(strings.Fields(string(b)), " ")
}

func (h hostile) wantNothingRan(t *testing.T, what string) {
	t.Helper()
	if got := h.fired(); got != "" {
		t.Errorf("%s: a project's key ran a program: %s", what, got)
	}
}

func newHostile(t *testing.T) hostile {
	t.Helper()
	f := newFolderFixture(t)
	dir := t.TempDir()
	h := hostile{folderFixture: f, script: filepath.ToSlash(filepath.Join(dir, "witness.sh")), mark: filepath.Join(dir, "ran")}
	body := "#!/bin/sh\necho \"$1\" >> '" + filepath.ToSlash(h.mark) + "'\nexit 1\n"
	if err := os.WriteFile(h.script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return h
}

// executingKeys are the keys that hold a program, set in a project.
var executingKeys = []string{
	"core.sshCommand", "core.gitProxy", "core.pager", "core.editor", "core.askPass",
	"core.alternateRefsCommand", "diff.external", "diff.evil.textconv", "diff.evil.command",
	"merge.evil.driver", "credential.helper", "credential.https://example.test.helper",
	"gpg.program", "gpg.ssh.program", "gpg.x509.program", "sequence.editor", "pager.status", "pager.diff",
	"alias.rev-parse", "alias.status", "alias.merge", "alias.fetch",
	"remote.origin.uploadpack", "remote.origin.receivepack",
	"submodule.mod.update",
}

// directKeys name a program that git starts without a shell: no argument.
var directKeys = []string{"core.gitProxy", "core.askPass", "gpg.program", "gpg.ssh.program", "gpg.x509.program"}

// filterKeys are the keys of a filter: a folder that holds them is refused.
var filterKeys = []string{"filter.evil.clean", "filter.evil.smudge", "filter.evil.process"}

// plainKeys turn on what would start one of the programs above.
var plainKeys = [][2]string{
	{"commit.gpgSign", "true"}, {"tag.gpgSign", "true"}, {"merge.verifySignatures", "true"},
	{"status.submoduleSummary", "true"}, {"fetch.recurseSubmodules", "true"}, {"submodule.recurse", "true"},
	{"submodule.active", "*"}, {"safe.directory", "*"}, {"protocol.allow", "always"}, {"protocol.ext.allow", "always"},
	{"gc.auto", "1"}, {"maintenance.auto", "true"}, {"fetch.bundleURI", "ssh://example.test/bundle"},
}

// arm writes the whole hostile configuration, a hooks folder, included files
// and an alternate, so that the programs have what starts them.
func (h hostile) arm(t *testing.T, withFilter bool) {
	t.Helper()
	keys := slices.Clone(executingKeys)
	if withFilter {
		keys = append(keys, filterKeys...)
	}
	for _, k := range keys {
		value := h.run(k)
		if slices.Contains(directKeys, k) {
			value = h.script
		}
		if strings.HasPrefix(k, "alias.") || strings.HasSuffix(k, ".helper") || k == "submodule.mod.update" {
			value = "!" + value
		}
		h.set(t, k, value)
	}
	for _, kv := range plainKeys {
		h.set(t, kv[0], kv[1])
	}
	h.set(t, "core.fsmonitor", h.script)

	hooks := t.TempDir()
	for _, dir := range []string{hooks, filepath.Join(h.proj.Path, ".git", "hooks")} {
		for _, name := range []string{"post-merge", "post-checkout", "post-rewrite", "reference-transaction", "pre-merge-commit", "pre-push", "pre-commit", "fsmonitor-watchman"} {
			writeFile(t, dir, name, "#!/bin/sh\nexec sh '"+h.script+"' hook."+name+"\n")
		}
	}
	h.set(t, "core.hooksPath", filepath.ToSlash(hooks))

	inc := t.TempDir()
	body := "[core]\n\tsshCommand = " + h.run("include.core.sshCommand") + "\n\tfsmonitor = " + h.script + "\n" +
		"\talternateRefsCommand = " + h.run("include.core.alternateRefsCommand") + "\n"
	writeFile(t, inc, "plain", body)
	writeFile(t, inc, "cond", strings.ReplaceAll(body, "include.", "includeIf."))
	h.set(t, "include.path", filepath.ToSlash(filepath.Join(inc, "plain")))
	h.set(t, "includeIf.gitdir:**.path", filepath.ToSlash(filepath.Join(inc, "cond")))

	attrs := "* diff=evil merge=evil\n"
	if withFilter {
		attrs = "* diff=evil merge=evil filter=evil\n"
	}
	writeFile(t, h.proj.Path, ".git/info/attributes", attrs)

	// An alternate is what starts core.alternateRefsCommand during a fetch.
	alt := filepath.Join(t.TempDir(), "alt.git")
	gitT(t, h.env, filepath.Dir(alt), "clone", "-q", "--bare", filepath.ToSlash(h.bare), filepath.ToSlash(alt))
	writeFile(t, h.proj.Path, ".git/objects/info/alternates", filepath.ToSlash(filepath.Join(alt, "objects"))+"\n")
}

// runEverything calls every operation of the package that reaches a project.
func (h hostile) runEverything(t *testing.T, d Deps) {
	t.Helper()
	ctx := context.Background()
	if _, err := RepoState(ctx, d, h.proj); err != nil {
		t.Errorf("RepoState: %v", err)
	}
	if _, _, _, err := ReadRemotes(ctx, d, h.proj); err != nil {
		t.Errorf("ReadRemotes: %v", err)
	}
	if _, err := Head(ctx, d, h.proj); err != nil {
		t.Errorf("Head: %v", err)
	}
	if _, err := IsMerged(ctx, d, h.proj, h.sha); err != nil {
		t.Errorf("IsMerged: %v", err)
	}
	f := h.fixture
	f.deps = d
	c := prepare(t, f)
	writeFile(t, c.Dir, "fix2.txt", "fix\n")
	sha, err := Commit(ctx, d, c, "fix")
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := Apply(ctx, d, h.proj, c, sha, "michel/fix-01jdemo01"); err != nil {
		t.Errorf("Apply: %v", err)
	}
	if res, err := Push(ctx, d, h.proj, h.bare, "", demoBranch, h.sha); err != nil || res.Outcome != PushPushed {
		t.Errorf("Push: %+v, %v", res, err)
	}
}

// reached fails a test whose scenario stopped before a command.
func reached(t *testing.T, rec *gitRecorder, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if len(rec.find(sub)) == 0 {
			t.Errorf("the scenario never ran git %s, so it proves nothing about it", sub)
		}
	}
}

// Every command Michel runs on a project, the project's configuration hostile.
// All of them keep working, because none of these keys is a reason to refuse.
func TestHostileConfigRunsNoProgram(t *testing.T) {
	parallel(t)
	t.Run("reads, copy, branch, push", func(t *testing.T) {
		h := newHostile(t)
		h.arm(t, true)
		rec := &gitRecorder{}
		d := h.deps
		d.Exec = rec.exec
		h.runEverything(t, d)
		reached(t, rec, "rev-parse", "config", "merge-base", "cherry", "clone", "fetch", "ls-tree", "archive", "init", "add", "commit", "diff", "push")
		h.wantNothingRan(t, "reads, copy, branch, push")
	})
	t.Run("update of the folder", func(t *testing.T) {
		h := newHostile(t)
		h.arm(t, false)
		to := h.advance(t, map[string]string{"merged.txt": "x\n"})
		rec := h.record()
		if _, err := UpdateCheck(context.Background(), h.deps, h.proj, "origin"); err != nil {
			t.Fatalf("UpdateCheck: %v", err)
		}
		res, err := h.update(t)
		if err != nil || res.To != to {
			t.Fatalf("res = %+v, err = %v", res, err)
		}
		reached(t, rec, "config", "symbolic-ref", "rev-parse", "status", "clone", "fetch", "merge-base", "diff", "check-attr", "merge")
		h.wantNothingRan(t, "update of the folder")
	})
	t.Run("a filter refuses the update and starts nothing", func(t *testing.T) {
		h := newHostile(t)
		h.arm(t, true)
		h.advance(t, map[string]string{"merged.txt": "x\n"})
		writeFile(t, h.proj.Path, "README.md", "demo\n") // same size, new date: status would call clean
		future := time.Now().Add(2 * time.Second)
		if err := os.Chtimes(filepath.Join(h.proj.Path, "README.md"), future, future); err != nil {
			t.Fatal(err)
		}
		_, err := h.update(t)
		wantClass(t, err, classFilter)
		h.wantNothingRan(t, "filter refusal")
	})
}

// core.sshCommand through a submodule: its own configuration holds a remote over
// SSH and a program, the project asks for recursion, the update brings a commit
// of the submodule that the folder does not have.
func TestHostileSubmoduleRunsNoProgram(t *testing.T) {
	parallel(t)
	h := newHostile(t)
	sub := filepath.Join(t.TempDir(), "sub")
	gitT(t, h.env, filepath.Dir(sub), "init", "-q", "-b", "main", sub)
	writeFile(t, sub, "s.txt", "one\n")
	gitT(t, h.env, sub, "add", "-A")
	gitT(t, h.env, sub, "commit", "-q", "-m", "one")
	gitT(t, h.env, h.proj.Path, "-c", "protocol.file.allow=always", "submodule", "--quiet", "add", filepath.ToSlash(sub), "mod")
	gitT(t, h.env, h.proj.Path, "commit", "-q", "-m", "submodule")
	gitT(t, h.env, h.proj.Path, "push", "-q", h.bare, "main")
	gitT(t, h.env, h.site, "pull", "-q", "--ff-only", "origin", "main")

	writeFile(t, sub, "s.txt", "two\n")
	gitT(t, h.env, sub, "add", "-A")
	gitT(t, h.env, sub, "commit", "-q", "-m", "two")
	newer := gitT(t, h.env, sub, "rev-parse", "HEAD")
	gitT(t, h.env, h.site, "update-index", "--cacheinfo", "160000,"+newer+",mod")
	to := h.advance(t, map[string]string{"merged.txt": "x\n"})

	inMod := filepath.Join(h.proj.Path, "mod")
	gitT(t, h.env, inMod, "config", "core.sshCommand", h.run("submodule.core.sshCommand"))
	gitT(t, h.env, inMod, "config", "core.fsmonitor", h.script)
	gitT(t, h.env, inMod, "config", "remote.origin.url", "ssh://example.test/mod.git")
	h.set(t, "submodule.mod.url", "ssh://example.test/mod.git")
	h.set(t, "core.sshCommand", h.run("core.sshCommand"))
	h.set(t, "submodule.recurse", "true")
	h.set(t, "fetch.recurseSubmodules", "true")
	h.set(t, "submodule.active", "*")

	res, err := h.update(t)
	if err != nil || res.To != to {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if _, err := IsMerged(context.Background(), h.deps, h.proj, h.sha); err != nil {
		t.Errorf("IsMerged: %v", err)
	}
	f := h.fixture
	prepare(t, f)
	h.wantNothingRan(t, "a submodule")

	// The witness is alive: plain git in the folder reaches the submodule's program.
	cmd := exec.Command("git", "-C", h.proj.Path, "fetch", "-q", "--recurse-submodules=yes", filepath.ToSlash(h.bare), "main")
	cmd.Env = h.env
	_ = cmd.Run()
	if h.fired() == "" {
		t.Error("control: plain git ran nothing of the submodule, so this test proves nothing")
	}
}

// Git will not take a fetch address from the project: every command but a local
// copy has no transport at all, and that one has only the file transport.
func TestHostileRewriteOfTheLocalFetchRunsNoProgram(t *testing.T) {
	parallel(t)
	for _, target := range []string{"ssh://example.test/", "ext::sh -c 'sh WITNESS url'#"} {
		t.Run(strings.Fields(target)[0], func(t *testing.T) {
			h := newHostile(t)
			h.set(t, "protocol.allow", "always")
			h.set(t, "protocol.ext.allow", "always")
			h.set(t, "core.sshCommand", h.run("core.sshCommand"))
			base := "url." + strings.ReplaceAll(target, "WITNESS", h.script) + ".insteadOf"
			h.set(t, base, filepath.ToSlash(h.deps.DataDir))
			h.set(t, base, h.deps.DataDir)
			c := prepare(t, h.fixture)
			writeFile(t, c.Dir, "fix2.txt", "fix\n")
			sha, err := Commit(context.Background(), h.deps, c, "fix")
			if err != nil {
				t.Fatal(err)
			}
			if err := Apply(context.Background(), h.deps, h.proj, c, sha, "michel/fix-01jdemo01"); err == nil {
				t.Error("the rewritten fetch reached something")
			}
			h.wantNothingRan(t, "Apply")
			h.advance(t, map[string]string{"merged.txt": "x\n"})
			if _, err := h.update(t); err == nil {
				t.Error("the rewritten fetch reached something")
			}
			h.wantNothingRan(t, "UpdateFolder")
		})
	}
}

// A setting for a remote named by the fetch's own address names the program of
// the local transport (uploadpack) or a helper (vcs).
func TestHostileRemoteNamedLikeTheFetchAddressIsRefused(t *testing.T) {
	parallel(t)
	for _, key := range []string{"uploadpack", "vcs"} {
		t.Run(key, func(t *testing.T) {
			h := newHostile(t)
			c := prepare(t, h.fixture)
			writeFile(t, c.Dir, "fix2.txt", "fix\n")
			sha, err := Commit(context.Background(), h.deps, c, "fix")
			if err != nil {
				t.Fatal(err)
			}
			value := h.run("remote." + key)
			if key == "vcs" {
				value = "ext"
			}
			h.set(t, "protocol.ext.allow", "always")
			h.set(t, "remote."+c.Mirror+"."+key, value)
			if err := Apply(context.Background(), h.deps, h.proj, c, sha, "michel/fix-01jdemo01"); err == nil {
				t.Error("Apply went on")
			}
			h.wantNothingRan(t, "Apply")
		})
	}
}

// lazyProject is the review's scenario: HEAD and the branches point to an id
// that has no object, and the project declares a promisor remote.
func lazyProject(t *testing.T) hostile {
	t.Helper()
	h := newHostile(t)
	h.setPromisor(t)
	missing := strings.Repeat("d", 40)
	writeFile(t, h.proj.Path, ".git/refs/heads/main", missing+"\n")
	writeFile(t, h.proj.Path, ".git/refs/heads/"+demoBranch, missing+"\n")
	return h
}

func (h hostile) setPromisor(t *testing.T) {
	t.Helper()
	gitT(t, h.env, h.proj.Path, "config", "--local", "core.repositoryformatversion", "1")
	h.set(t, "extensions.partialClone", "evil")
	h.set(t, "remote.evil.promisor", "true")
	h.set(t, "remote.evil.url", "ssh://example.test/demo.git")
	h.set(t, "core.sshCommand", h.run("core.sshCommand"))
}

func TestLazyFetchRunsNoProgram(t *testing.T) {
	parallel(t)
	ctx := context.Background()
	t.Run("control: plain git fetches and runs the witness", func(t *testing.T) {
		h := lazyProject(t)
		cmd := exec.Command("git", "-C", h.proj.Path, "rev-parse", "--verify", "--quiet", "--end-of-options", "HEAD^{commit}")
		cmd.Env = h.env
		_ = cmd.Run()
		if h.fired() == "" {
			t.Fatal("control: plain git ran nothing, so this test proves nothing")
		}
	})
	t.Run("RepoState", func(t *testing.T) {
		h := lazyProject(t)
		_, err := RepoState(ctx, h.deps, h.proj)
		wantClass(t, err, classPartial)
		h.wantNothingRan(t, "RepoState")
	})
	t.Run("Push", func(t *testing.T) {
		h := lazyProject(t)
		_, err := Push(ctx, h.deps, h.proj, h.bare, "", demoBranch, h.sha)
		wantClass(t, err, classFailed)
		h.wantNothingRan(t, "Push")
	})
	t.Run("UpdateCheck and UpdateFolder", func(t *testing.T) {
		h := lazyProject(t)
		_, err := UpdateCheck(ctx, h.deps, h.proj, "origin")
		wantClass(t, err, classUpdateFailed)
		_, err = h.update(t)
		wantClass(t, err, classUpdateFailed)
		h.wantNothingRan(t, "update")
	})
	t.Run("Head, Prepare, IsMerged", func(t *testing.T) {
		h := lazyProject(t)
		if got, err := Head(ctx, h.deps, h.proj); err != nil || got != "" {
			t.Errorf("Head = %q, %v", got, err)
		}
		if _, err := Prepare(ctx, h.deps, h.proj, "01JATTEMPT0000000000000000"); !errors.Is(err, ErrNoCommit) {
			t.Errorf("Prepare: %v", err)
		}
		// HEAD has no object: an error, or not merged, and nothing fetched.
		if got, _ := IsMerged(ctx, h.deps, h.proj, h.sha); got {
			t.Error("IsMerged says merged")
		}
		h.wantNothingRan(t, "Head, Prepare, IsMerged")
	})
	t.Run("a missing blob in git cherry", func(t *testing.T) {
		h := newHostile(t)
		h.setPromisor(t)
		// A commit on main that changes the same path: git cherry must read the blobs.
		writeFile(t, h.proj.Path, "fix.txt", "another fix\n")
		gitT(t, h.env, h.proj.Path, "add", "fix.txt")
		gitT(t, h.env, h.proj.Path, "commit", "-q", "-m", "same path")
		blob := gitT(t, h.env, h.proj.Path, "rev-parse", h.sha+":fix.txt")
		if err := os.Remove(filepath.Join(h.proj.Path, ".git", "objects", blob[:2], blob[2:])); err != nil {
			t.Fatal(err)
		}
		_, _ = IsMerged(ctx, h.deps, h.proj, h.sha)
		h.wantNothingRan(t, "IsMerged")
		cmd := exec.Command("git", "-C", h.proj.Path, "cherry", "HEAD", h.sha, h.sha+"^")
		cmd.Env = h.env
		_ = cmd.Run()
		if h.fired() == "" {
			t.Error("control: plain git cherry ran nothing, so this test proves nothing")
		}
	})
	t.Run("keys in an included file", func(t *testing.T) {
		h := newHostile(t)
		dir := t.TempDir()
		writeFile(t, dir, "inc", "[remote \"evil\"]\n\tpromisor = true\n\turl = ssh://example.test/demo.git\n")
		h.set(t, "include.path", filepath.ToSlash(filepath.Join(dir, "inc")))
		_, err := RepoState(ctx, h.deps, h.proj)
		wantClass(t, err, classPartial)
	})
}

// A git that ignores GIT_NO_LAZY_FETCH must not reach a command that may read an
// object: the keys are read first, on every command on a project.
func TestOldGitRefusesAPromisorBeforeAnyCommand(t *testing.T) {
	parallel(t)
	ctx := context.Background()
	h := lazyProject(t)
	rec := h.record()
	h.deps.assumeOldGit = true
	if _, err := Head(ctx, h.deps, h.proj); err == nil {
		t.Error("Head went on")
	}
	if _, err := IsMerged(ctx, h.deps, h.proj, h.sha); err == nil {
		t.Error("IsMerged went on")
	}
	if _, err := Prepare(ctx, h.deps, h.proj, "01JATTEMPT0000000000000000"); err == nil {
		t.Error("Prepare went on")
	}
	if n := len(rec.find("rev-parse")); n != 0 {
		t.Errorf("%d git rev-parse ran", n)
	}
	h.wantNothingRan(t, "old git")

	normal := newHostile(t)
	normal.deps.assumeOldGit = true

	if got, err := Head(ctx, normal.deps, normal.proj); err != nil || got == "" {
		t.Errorf("a normal project, old git: Head = %q, %v", got, err)
	}
}

func TestGitVersionIsRead(t *testing.T) {
	parallel(t)
	for out, old := range map[string]bool{
		"git version 2.46.2.windows.1\n": false,
		"git version 2.45.0\n":           false,
		"git version 3.0.0\n":            false,
		"git version 2.44.3\n":           true,
		"git version 1.99.0\n":           true,
		"something else\n":               true,
		"":                               true,
	} {
		if got := versionIsOld(out); got != old {
			t.Errorf("versionIsOld(%q) = %v", out, got)
		}
	}
}

// The witnesses are alive: plain git, without the runner, starts each of them.
func TestHostileKeysAreAlive(t *testing.T) {
	parallel(t)
	plain := func(t *testing.T, h hostile, stdin string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", h.proj.Path}, args...)...)
		cmd.Env = h.env
		cmd.Stdin = strings.NewReader(stdin)
		_ = cmd.Run()
	}
	touch := func(t *testing.T, h hostile) {
		t.Helper()
		writeFile(t, h.proj.Path, "README.md", "same\n")
		future := time.Now().Add(2 * time.Second)
		if err := os.Chtimes(filepath.Join(h.proj.Path, "README.md"), future, future); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		key   string
		value func(hostile) string
		setup func(*testing.T, hostile)
	}{
		{"core.fsmonitor", func(h hostile) string { return h.script }, func(t *testing.T, h hostile) { plain(t, h, "", "status", "--porcelain") }},
		{"core.gitProxy", func(h hostile) string { return h.script }, func(t *testing.T, h hostile) {
			plain(t, h, "", "ls-remote", "git://example.test/demo.git")
		}},
		{"core.sshCommand", func(h hostile) string { return h.run("core.sshCommand") }, func(t *testing.T, h hostile) {
			plain(t, h, "", "ls-remote", "ssh://example.test/demo.git")
		}},
		{"diff.external", func(h hostile) string { return h.run("diff.external") }, func(t *testing.T, h hostile) {
			touch(t, h)
			plain(t, h, "", "diff")
		}},
		{"diff.evil.textconv", func(h hostile) string { return h.run("diff.evil.textconv") }, func(t *testing.T, h hostile) {
			writeFile(t, h.proj.Path, ".git/info/attributes", "* diff=evil\n")
			touch(t, h)
			plain(t, h, "", "diff")
		}},
		{"filter.evil.clean", func(h hostile) string { return h.run("filter.evil.clean") }, func(t *testing.T, h hostile) {
			writeFile(t, h.proj.Path, ".git/info/attributes", "* filter=evil\n")
			touch(t, h)
			plain(t, h, "", "add", "README.md")
		}},
		{"credential.helper", func(h hostile) string { return "!" + h.run("credential.helper") }, func(t *testing.T, h hostile) {
			plain(t, h, "protocol=https\nhost=example.test\n\n", "credential", "fill")
		}},
		{"gpg.program", func(h hostile) string { return h.script }, func(t *testing.T, h hostile) {
			plain(t, h, "", "-c", "commit.gpgSign=true", "commit", "-q", "--allow-empty", "-m", "signed")
		}},
		{"core.alternateRefsCommand", func(h hostile) string { return h.run("core.alternateRefsCommand") }, func(t *testing.T, h hostile) {
			alt := filepath.Join(t.TempDir(), "alt.git")
			gitT(t, h.env, filepath.Dir(alt), "clone", "-q", "--bare", filepath.ToSlash(h.bare), filepath.ToSlash(alt))
			writeFile(t, h.proj.Path, ".git/objects/info/alternates", filepath.ToSlash(filepath.Join(alt, "objects"))+"\n")
			h.advance(t, map[string]string{"merged.txt": "x\n"})
			plain(t, h, "", "fetch", "-q", filepath.ToSlash(h.bare), "main")
		}},
	} {
		t.Run(c.key, func(t *testing.T) {
			h := newHostile(t)
			h.set(t, c.key, c.value(h))
			c.setup(t, h)
			if h.fired() == "" {
				t.Error("plain git started nothing, so this key proves nothing")
			}
		})
	}
}

// --- The findings of the review of Task 14c ---

// sleeper makes the person's core.sshCommand a script that sleeps, then leaves a mark.
func sleeper(t *testing.T, home string, seconds int) (mark string) {
	t.Helper()
	dir := t.TempDir()
	mark = filepath.Join(dir, "late")
	script := filepath.ToSlash(filepath.Join(dir, "sleeper.sh"))
	body := "#!/bin/sh\nsleep " + strconv.Itoa(seconds) + "\necho late >> '" + filepath.ToSlash(mark) + "'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, home, ".gitconfig", "[core]\n\tsshCommand = sh '"+script+"'\n")
	return mark
}

// The real runner kills the whole tree: nothing goes on after the deadline, and
// the temporary repository can be removed.
func TestPushDeadlineKillsTheWholeTree(t *testing.T) {
	f := newRemoteFixture(t)
	const sleep = 10
	mark := sleeper(t, f.home, sleep)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	_, err := Push(ctx, f.deps, f.proj, demoSSH, "", demoBranch, f.sha)
	wantClass(t, err, classTimeout)
	if took := time.Since(start); took > 8*time.Second {
		t.Errorf("Push came back after %s", took)
	}
	f.fixNetEmpty(t)
	time.Sleep(time.Until(start.Add((sleep + 3) * time.Second)))
	noMark(t, mark, "the script, after the deadline")
}

func TestRevParseCutByTheDeadlineIsNotAnEmptyRepository(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	rec := &gitRecorder{fake: func(ctx context.Context, sub string, _ []string) ([]byte, []byte, error, bool) {
		if sub != "rev-parse" {
			return nil, nil, nil, false
		}
		<-ctx.Done()
		// A process killed on Windows ends with code 1, as "no such commit" does.
		cmd := exec.Command("git", "rev-parse", "--verify", "--quiet", strings.Repeat("d", 40)+"^{commit}")
		cmd.Dir = f.proj.Path
		cmd.Env = f.env
		return nil, nil, cmd.Run(), true
	}}
	f.deps.Exec = rec.exec
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	h, err := ensureHome(f.deps)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := h.revParseCommit(ctx, f.deps, f.proj.Path, "HEAD"); err == nil {
		t.Errorf("revParseCommit = %q, without an error", got)
	}
}

func TestPersonsAskPassIsNotCalled(t *testing.T) {
	f := newRemoteFixture(t)
	script, mark := witness(t)
	writeFile(t, f.home, ".gitconfig", "[core]\n\taskPass = "+script+"\n")
	rec := &gitRecorder{fake: fakePush(newBranchLine(), nil)}
	f.deps.Exec = rec.exec
	if _, err := Push(context.Background(), f.deps, f.proj, demoSSH, "", demoBranch, f.sha); err != nil {
		t.Fatal(err)
	}
	call := rec.find("push")[0]
	if !slices.Contains(call.args, "core.askPass=") {
		t.Errorf("argv %v", call.args)
	}
	if _, ok := envLookup(call.env, "GIT_ASKPASS"); ok {
		t.Error("GIT_ASKPASS is set")
	}
	fill := func(args ...string) {
		cmd := exec.Command("git", append(args, "credential", "fill")...)
		cmd.Env = call.env
		cmd.Dir = f.deps.DataDir
		cmd.Stdin = strings.NewReader("protocol=https\nhost=example.test\n\n")
		_ = cmd.Run()
	}
	fill("-c", "core.askPass=")
	noMark(t, mark, "the person's core.askPass")
	fill()
	if _, err := os.Stat(mark); err != nil {
		t.Error("control: without the argument nothing ran, so this test proves nothing")
	}
}

func TestSafeBareRepositoryExplicitDoesNotStopAPush(t *testing.T) {
	f := newRemoteFixture(t)
	writeFile(t, f.home, ".gitconfig", "[safe]\n\tbareRepository = explicit\n")
	got, err := f.push(t)
	if err != nil || got.Outcome != PushPushed {
		t.Fatalf("Push = %+v, %v", got, err)
	}
}

func TestSSHCommandInAnIncludedFileIsKept(t *testing.T) {
	f := newRemoteFixture(t)
	writeFile(t, f.home, "extra", "[core]\n\tsshCommand = ssh -i demo\n")
	writeFile(t, f.home, ".gitconfig", "[include]\n\tpath = extra\n")
	rec := &gitRecorder{fake: fakePush(newBranchLine(), nil)}
	f.deps.Exec = rec.exec
	if _, err := Push(context.Background(), f.deps, f.proj, demoSSH, "", demoBranch, f.sha); err != nil {
		t.Fatal(err)
	}
	if v, ok := envLookup(rec.find("push")[0].env, "GIT_SSH_COMMAND"); ok {
		t.Errorf("GIT_SSH_COMMAND = %q would override the person's setting", v)
	}
}

func TestOldTemporaryRepositoriesAreRemoved(t *testing.T) {
	parallel(t)
	f := newRemoteFixture(t)
	dir := netDir(f.deps)
	old := ulid.MustNew(ulid.Timestamp(time.Now().Add(-2*time.Hour)), ulid.DefaultEntropy()).String() + ".git"
	fresh := ulid.MustNew(ulid.Timestamp(time.Now().Add(-10*time.Minute)), ulid.DefaultEntropy()).String() + ".git"
	for _, name := range []string{old, fresh, "not-a-ulid.git"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.push(t); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, old)); err == nil {
		t.Error("the old one stayed")
	}
	for _, name := range []string{fresh, "not-a-ulid.git"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was removed", name)
		}
	}
}

// --- No other way to start git ---

// startSites is every function that may start a program in the packages that
// handle a project. Git goes through the first one only.
var startSites = map[string]bool{
	"internal/workcopy/gitrun.go:execGit":        true, // the runner
	"internal/workcopy/gitrun.go:gitVersion":     true, // git version, outside any repository
	"internal/workcopy/exec_windows.go:killTree": true, // taskkill
	"internal/workcopy/git.go:defaultExec":       true, // what an ExecFunc ends in
	"internal/workcopy/install.go:run":           true, // composer and npm, in the copy
	"internal/workcopy/run.go:RunTests":          true, // the project's tests, in the copy
	"internal/cli/serve.go:openBrowser":          true,
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		if dir == filepath.Dir(dir) {
			t.Fatal("no go.mod")
		}
	}
}

// startsAProgram says whether a call can start a program: exec.Command,
// exec.CommandContext, os.StartProcess, or an ExecFunc: d.exec()(...), d.Exec(...)
// with its five arguments, defaultExec(...).
func startsAProgram(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		switch fn.Sel.Name {
		case "Command", "CommandContext":
			if x, ok := fn.X.(*ast.Ident); ok && x.Name == "exec" {
				return true
			}
		case "StartProcess":
			return true
		case "Exec":
			return len(call.Args) == 5
		}
	case *ast.CallExpr:
		if sel, ok := fn.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "exec" {
			return true
		}
	case *ast.Ident:
		return fn.Name == "defaultExec" || fn.Name == "DefaultExec"
	}
	return false
}

// Nothing in the whole program names git as the program to start but the runner.
func TestGitIsNamedOnlyByTheRunner(t *testing.T) {
	parallel(t)
	root := repoRoot(t)
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, e os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.IsDir() && e.Name() == "testdata" {
				return filepath.SkipDir
			}
			if e.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			for _, decl := range file.Decls {
				name := declName(decl)
				ast.Inspect(decl, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok || !startsAProgram(call) {
						return true
					}
					for _, arg := range call.Args {
						if lit, ok := arg.(*ast.BasicLit); ok && lit.Value == `"git"` && name != "execGit" && name != "gitVersion" {
							t.Errorf("%s: %s starts git outside the runner", fset.Position(call.Pos()), name)
						}
					}
					return true
				})
			}
			return nil
		})
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
}

// declName is the name of a function, or of a variable holding one.
func declName(decl ast.Decl) string {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		return d.Name.Name
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			if v, ok := spec.(*ast.ValueSpec); ok && len(v.Names) > 0 {
				return v.Names[0].Name
			}
		}
	}
	return ""
}

// No code of these packages starts git, or any program, outside the sites above.
func TestNoOtherWayToStartGit(t *testing.T) {
	parallel(t)
	root := repoRoot(t)
	found := map[string]bool{}
	for _, pkg := range []string{"workcopy", "fix", "scan", "project", "cli", "api", "collect"} {
		dir := filepath.Join(root, "internal", pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			rel := "internal/" + pkg + "/" + e.Name()
			for _, decl := range file.Decls {
				name := declName(decl)
				ast.Inspect(decl, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok || !startsAProgram(call) {
						return true
					}
					site := rel + ":" + name
					found[site] = true
					if !startSites[site] {
						t.Errorf("%s: %s starts a program outside the runner", fset.Position(call.Pos()), site)
					}
					return true
				})
			}
		}
	}
	for site := range startSites {
		if !found[site] {
			t.Errorf("%s no longer starts a program: remove it from the list", site)
		}
	}
}
