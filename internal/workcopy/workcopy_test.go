package workcopy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/project"
)

func fakeAWS() string { return "AKIA" + "ABCDEFGHIJKLMNOP" }

// needGit skips the test when git is not installed, like internal/hygiene.
func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
}

// testGitEnv is the environment of the git commands the tests run
// themselves: no system or global configuration, a fixed identity.
func testGitEnv(t *testing.T) []string {
	t.Helper()
	gc := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(gc, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+gc,
		"GIT_AUTHOR_NAME=demo", "GIT_AUTHOR_EMAIL=demo@example.test",
		"GIT_COMMITTER_NAME=demo", "GIT_COMMITTER_EMAIL=demo@example.test")
}

// gitT runs git in dir for the test and returns its trimmed stdout.
func gitT(t *testing.T, env []string, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "core.autocrlf=false"}, args...)...)
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		var stderr []byte
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			stderr = ee.Stderr
		}
		t.Fatalf("git %v: %v %s", args, err, stderr)
	}
	return strings.TrimSpace(string(out))
}

func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

type fixture struct {
	env  []string
	proj project.Project
	deps Deps
}

// newFixture makes a git project "demo" with one commit: tracked files,
// among them a .env, a key, a folder the project excludes and a source file
// holding a hard-coded key.
func newFixture(t *testing.T) fixture {
	t.Helper()
	needGit(t)
	env := testGitEnv(t)
	root := t.TempDir()
	gitT(t, env, root, "init", "-q", "-b", "main")
	writeFile(t, root, "README.md", "demo\n")
	writeFile(t, root, "composer.json", `{"name":"acme/lib"}`+"\n")
	writeFile(t, root, "composer.lock", `{"packages":[]}`+"\n")
	writeFile(t, root, ".env", "DB_PASSWORD=s3cr3tvalue\n")
	writeFile(t, root, "config/server.key", "key\n")
	writeFile(t, root, "config/.env.local", "A=1\n")
	writeFile(t, root, "private/notes.txt", "private\n")
	writeFile(t, root, "src/app.php", "<?php\n\n$k = '"+fakeAWS()+"';\n")
	gitT(t, env, root, "add", "-A")
	gitT(t, env, root, "commit", "-q", "-m", "init")
	p := project.Project{ID: "01JDEMO0000000000000000000", Name: "demo", Path: root, Exclude: []string{"private"}}
	return fixture{env: env, proj: p, deps: Deps{DataDir: t.TempDir(), ProxyAddr: "127.0.0.1:1", Now: func() time.Time { return time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC) }}}
}

// treeDigest is the SHA-256 of every path, size, modification time and
// mode under root, .git included: equal digests mean nothing was created,
// removed or written there.
func treeDigest(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		fmt.Fprintf(h, "%s\x00%d\x00%d\x00%v\n", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano(), info.Mode())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func prepare(t *testing.T, f fixture) Copy {
	t.Helper()
	c, err := Prepare(context.Background(), f.deps, f.proj, "01JATTEMPT0000000000000000")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(func() { _ = Remove(c) })
	return c
}

func TestIsGitRepoFalseForPlainFolder(t *testing.T) {
	if IsGitRepo(t.TempDir()) {
		t.Error("a plain folder is reported as a git repository")
	}
	if IsGitRepo(filepath.Join(t.TempDir(), "missing")) {
		t.Error("a missing folder is reported as a git repository")
	}
	f := newFixture(t)
	if !IsGitRepo(f.proj.Path) {
		t.Error("a git repository is not reported as one")
	}
	if IsGitRepo(filepath.Join(f.proj.Path, "src")) {
		t.Error("a subfolder of a repository is reported as a repository")
	}
	_, err := Prepare(context.Background(), f.deps, project.Project{ID: "01JDEMO0000000000000000000", Path: t.TempDir()}, "01JATTEMPT0000000000000000")
	if !errors.Is(err, ErrNotGitRepo) {
		t.Errorf("Prepare on a plain folder: %v, want ErrNotGitRepo", err)
	}
}

func TestPrepareNeverWritesInProject(t *testing.T) {
	f := newFixture(t)
	// A dirty working tree and an untracked file: still nothing written.
	writeFile(t, f.proj.Path, "README.md", "changed\n")
	writeFile(t, f.proj.Path, "untracked.txt", "u\n")
	before := treeDigest(t, f.proj.Path)
	c := prepare(t, f)
	writeFile(t, c.Dir, "README.md", "fixed\n")
	if _, _, err := Diff(context.Background(), f.deps, c); err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if _, err := Commit(context.Background(), f.deps, c, "fix"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if after := treeDigest(t, f.proj.Path); after != before {
		t.Error("the project folder (or its .git) changed during the preparation")
	}
	rel, err := filepath.Rel(f.deps.DataDir, c.Dir)
	if err != nil || filepath.ToSlash(rel) != "worktrees/"+f.proj.ID+"/01JATTEMPT0000000000000000" {
		t.Errorf("copy at %s, want under worktrees/<project>/<attempt> of the data folder", rel)
	}
	if want := gitT(t, f.env, f.proj.Path, "rev-parse", "HEAD"); c.Base != want {
		t.Errorf("Base %s, want %s", c.Base, want)
	}
	if _, err := Prepare(context.Background(), f.deps, f.proj, "01JATTEMPT0000000000000000"); err == nil {
		t.Error("a second Prepare of the same attempt overwrote the copy")
	}
	for _, bad := range []string{"", "../x", "a/b", strings.Repeat("A", 80)} {
		if _, err := Prepare(context.Background(), f.deps, f.proj, bad); !errors.Is(err, ErrInvalidID) {
			t.Errorf("attempt id %q: %v, want ErrInvalidID", bad, err)
		}
	}
}

func TestPrepareSkipsExcludedFiles(t *testing.T) {
	f := newFixture(t)
	writeFile(t, f.proj.Path, "id_rsa", "untracked key\n")
	c := prepare(t, f)
	for _, rel := range []string{".env", "config/server.key", "config/.env.local", "private/notes.txt", "id_rsa"} {
		if _, err := os.Lstat(filepath.Join(c.Dir, filepath.FromSlash(rel))); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was copied (%v)", rel, err)
		}
	}
	for _, rel := range []string{"README.md", "src/app.php", "composer.lock"} {
		if _, err := os.Stat(filepath.Join(c.Dir, filepath.FromSlash(rel))); err != nil {
			t.Errorf("%s missing from the copy: %v", rel, err)
		}
	}
	want := []string{".env", "config/.env.local", "config/server.key", "private/notes.txt"}
	if !slices.Equal(c.Excluded, want) {
		t.Errorf("Excluded %v, want %v", c.Excluded, want)
	}
	// Writing an excluded file in the copy does not make it part of the
	// change, and the commit keeps the excluded tracked files.
	writeFile(t, c.Dir, ".env", "DB_PASSWORD=other\n")
	writeFile(t, c.Dir, "new.pem", "x\n")
	writeFile(t, c.Dir, "src/app.php", "<?php\n")
	_, files, err := Diff(context.Background(), f.deps, c)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !slices.Equal(files, []string{"src/app.php"}) {
		t.Errorf("files %v, want only src/app.php", files)
	}
	sha, err := Commit(context.Background(), f.deps, c, "fix")
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	tree := gitT(t, f.env, c.Dir, "ls-tree", "-r", "--name-only", sha)
	for _, rel := range want {
		if !strings.Contains(tree, rel) {
			t.Errorf("the commit drops the excluded tracked file %s", rel)
		}
	}
	if strings.Contains(tree, "new.pem") {
		t.Error("the commit holds a new excluded file")
	}
}

func TestPrepareReportsSecretHits(t *testing.T) {
	f := newFixture(t)
	c := prepare(t, f)
	want := []mask.Hit{{File: "src/app.php", Line: 3, Kind: mask.KindAWSKey}}
	if !slices.Equal(c.SecretHits, want) {
		t.Errorf("SecretHits %+v, want %+v", c.SecretHits, want)
	}
}

func TestDiffRejectsOutsideCopy(t *testing.T) {
	for _, e := range []rawEntry{
		{path: "../x", mode: "100644"},
		{path: "a/../../x", mode: "100644"},
		{path: "/etc/x", mode: "100644"},
		{path: "C:/x", mode: "100644"},
		{path: `a\b`, mode: "100644"},
		{path: ".git/config", mode: "100644"},
		{path: "sub/.GIT/hooks/pre-commit", mode: "100644"},
		{path: "link", mode: "120000"},
		{path: "mod", mode: "160000"},
	} {
		if err := checkEntry(e); !errors.Is(err, ErrOutsideCopy) {
			t.Errorf("%+v: %v, want ErrOutsideCopy", e, err)
		}
	}
	if err := checkEntry(rawEntry{path: "src/app.php", mode: "100644"}); err != nil {
		t.Errorf("a plain file is refused: %v", err)
	}
	if err := checkEntry(rawEntry{path: "src/gone.php", mode: "000000"}); err != nil {
		t.Errorf("a deleted file is refused: %v", err)
	}

	// End to end: a symbolic link added in the copy invalidates the diff.
	f := newFixture(t)
	c := prepare(t, f)
	writeFile(t, c.Dir, "README.md", "fixed\n")
	if err := os.Symlink(f.proj.Path, filepath.Join(c.Dir, "link")); err != nil {
		// No symlink privilege (Windows): record one in the index the way git
		// does on a file system without links.
		writeFile(t, c.Dir, "link", f.proj.Path)
		blob := gitT(t, f.env, c.Dir, "hash-object", "-w", "link")
		gitT(t, f.env, c.Dir, "-c", "core.symlinks=false", "update-index", "--add", "--cacheinfo", "120000,"+blob+",link")
	}
	if _, _, err := Diff(context.Background(), f.deps, c); !errors.Is(err, ErrOutsideCopy) {
		t.Errorf("Diff with a symbolic link: %v, want ErrOutsideCopy", err)
	}
	if _, err := Commit(context.Background(), f.deps, c, "fix"); !errors.Is(err, ErrOutsideCopy) {
		t.Errorf("Commit with a symbolic link: %v, want ErrOutsideCopy", err)
	}
}

func TestRunTestsNotRunWithoutCommand(t *testing.T) {
	c := Copy{Dir: t.TempDir()}
	d := Deps{DataDir: t.TempDir(), Exec: func(context.Context, string, []string, []string, string) ([]byte, []byte, error) {
		t.Error("a command ran without a test command")
		return nil, nil, nil
	}}
	status, out, err := RunTests(context.Background(), d, c, nil)
	if status != TestsNotRun || out != "" || err != nil {
		t.Errorf("got %q %q %v, want not_run", status, out, err)
	}

	var gotName, gotDir string
	var gotArgs []string
	d.Exec = func(_ context.Context, name string, args, _ []string, dir string) ([]byte, []byte, error) {
		gotName, gotArgs, gotDir = name, args, dir
		return []byte("ok\x1b[31m\n"), []byte(strings.Repeat("e", 70<<10)), nil
	}
	status, out, err = RunTests(context.Background(), d, c, []string{"vendor/bin/phpunit", "--testdox"})
	if status != TestsPassed || err != nil {
		t.Fatalf("got %q %v, want passed", status, err)
	}
	if gotName != "vendor/bin/phpunit" || !slices.Equal(gotArgs, []string{"--testdox"}) || gotDir != c.Dir {
		t.Errorf("ran %s %v in %s", gotName, gotArgs, gotDir)
	}
	if strings.Contains(out, "\x1b") || len(out) > 2*maxStream+64 {
		t.Errorf("output not sanitized or not capped (%d bytes)", len(out))
	}
	d.Exec = func(context.Context, string, []string, []string, string) ([]byte, []byte, error) {
		return nil, []byte("1 failure"), &exec.ExitError{}
	}
	if status, out, err = RunTests(context.Background(), d, c, []string{"phpunit"}); status != TestsFailed || err != nil || !strings.Contains(out, "1 failure") {
		t.Errorf("failing tests: %q %q %v", status, out, err)
	}
	d.Exec = func(context.Context, string, []string, []string, string) ([]byte, []byte, error) {
		return nil, nil, exec.ErrNotFound
	}
	if status, _, err = RunTests(context.Background(), d, c, []string{"phpunit"}); status != TestsNotRun || err == nil {
		t.Errorf("missing test program: %q %v, want not_run and an error", status, err)
	}
}

func TestSplitCommand(t *testing.T) {
	for in, want := range map[string][]string{
		"":                                nil,
		"   ":                             nil,
		"vendor/bin/phpunit":              {"vendor/bin/phpunit"},
		"npm  test -- --ci":               {"npm", "test", "--", "--ci"},
		`php artisan test --filter "A B"`: {"php", "artisan", "test", "--filter", "A B"},
		`echo 'a "b"' c\ d`:               {"echo", `a "b"`, "c d"},
	} {
		got, err := SplitCommand(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("SplitCommand(%q) = %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{`a "b`, `a 'b`, `a \`, "a | b", "a && b", "a; b", "a > f", "$(x)", "`x`"} {
		if _, err := SplitCommand(bad); err == nil {
			t.Errorf("SplitCommand(%q) accepted a shell construct", bad)
		}
	}
}

type recorded struct {
	name string
	args []string
	env  []string
	dir  string
}

type recorder struct {
	mu   sync.Mutex
	runs []recorded
	next func(ctx context.Context, name string, args, env []string, dir string) ([]byte, []byte, error)
}

func (r *recorder) exec(ctx context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
	r.mu.Lock()
	r.runs = append(r.runs, recorded{name, append([]string{}, args...), append([]string{}, env...), dir})
	r.mu.Unlock()
	if r.next == nil {
		return nil, nil, nil
	}
	return r.next(ctx, name, args, env, dir)
}

func TestExecEnvIsAllowlisted(t *testing.T) {
	t.Setenv("MICHEL_CANARY_SECRET", "leak")
	f := newFixture(t)
	rec := &recorder{next: defaultExec}
	f.deps.Exec = rec.exec
	c := prepare(t, f)
	writeFile(t, c.Dir, "README.md", "fixed\n")
	if _, err := Commit(context.Background(), f.deps, c, "fix"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	rec.next = nil
	if err := Install(context.Background(), f.deps, c, "Packagist", "composer.lock"); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, _, err := RunTests(context.Background(), f.deps, c, []string{"phpunit"}); err != nil {
		t.Fatalf("RunTests: %v", err)
	}
	home := filepath.Join(f.deps.DataDir, "fix-home")
	if len(rec.runs) < 4 {
		t.Fatalf("only %d commands recorded", len(rec.runs))
	}
	for _, r := range rec.runs {
		joined := strings.Join(r.env, "\n")
		if strings.Contains(joined, "MICHEL_CANARY_SECRET") || strings.Contains(joined, "leak") {
			t.Errorf("%s %v: the canary variable reached the command", r.name, r.args)
		}
		for _, want := range []string{"HOME=" + home, "USERPROFILE=" + home, "COMPOSER_HOME=" + filepath.Join(home, "composer"),
			"npm_config_cache=" + filepath.Join(home, "npm"), "HTTPS_PROXY=http://127.0.0.1:1", "HTTP_PROXY=http://127.0.0.1:1",
			"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + filepath.Join(home, "gitconfig"), "GIT_TERMINAL_PROMPT=0"} {
			if !slices.Contains(r.env, want) {
				t.Errorf("%s %v: %s missing from the environment", r.name, r.args, want)
			}
		}
		rel, err := filepath.Rel(f.deps.DataDir, r.dir)
		if err != nil || !filepath.IsLocal(rel) && rel != "." {
			t.Errorf("%s %v ran from %s, outside the data folder", r.name, r.args, r.dir)
		}
		if r.name == "git" {
			if !slices.Contains(r.args, "core.hooksPath="+filepath.Join(home, "no-hooks")) || !slices.Contains(r.args, "core.fsmonitor=false") {
				t.Errorf("git %v: hooks or fsmonitor not disabled", r.args)
			}
			if !slices.Contains(allowedGit, gitSubcommand(r.args)) {
				t.Errorf("git %v: subcommand outside the closed list", r.args)
			}
		}
	}
	last := rec.runs[len(rec.runs)-2]
	if last.name != "composer" || !slices.Equal(last.args, []string{"install", "--no-scripts", "--no-interaction", "--no-plugins"}) || last.dir != c.Dir {
		t.Errorf("install ran %s %v in %s", last.name, last.args, last.dir)
	}
}

func TestInstallArgvByLockfile(t *testing.T) {
	c := Copy{Dir: t.TempDir()}
	writeFile(t, c.Dir, "composer.lock", "{}")
	writeFile(t, c.Dir, "web/package-lock.json", "{}")
	writeFile(t, c.Dir, "pn/pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
	writeFile(t, c.Dir, "y1/yarn.lock", "# yarn lockfile v1\n")
	writeFile(t, c.Dir, "y2/yarn.lock", "__metadata:\n  version: 8\n")
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	for _, tc := range []struct {
		eco, rel, name string
		args           []string
		dir            string
	}{
		{"Packagist", "composer.lock", "composer", []string{"install", "--no-scripts", "--no-interaction", "--no-plugins"}, ""},
		{"npm", "web/package-lock.json", "npm", []string{"ci", "--ignore-scripts", "--no-audit", "--no-fund"}, "web"},
		{"npm", "pn/pnpm-lock.yaml", "pnpm", []string{"install", "--frozen-lockfile", "--ignore-scripts"}, "pn"},
		{"npm", "y1/yarn.lock", "yarn", []string{"install", "--frozen-lockfile", "--ignore-scripts", "--non-interactive"}, "y1"},
		{"npm", "y2/yarn.lock", "yarn", []string{"install", "--immutable", "--mode=skip-build"}, "y2"},
	} {
		rec.runs = nil
		if err := Install(context.Background(), d, c, tc.eco, tc.rel); err != nil {
			t.Errorf("%s: %v", tc.rel, err)
			continue
		}
		r := rec.runs[0]
		if r.name != tc.name || !slices.Equal(r.args, tc.args) || r.dir != filepath.Join(c.Dir, filepath.FromSlash(tc.dir)) {
			t.Errorf("%s: ran %s %v in %s", tc.rel, r.name, r.args, r.dir)
		}
	}
	rec.runs = nil
	for _, tc := range []struct{ eco, rel string }{{"npm", "composer.lock"}, {"Packagist", "missing/composer.lock"}, {"Packagist", "../composer.lock"}, {"Packagist", "README.md"}, {"PyPI", "composer.lock"}} {
		if err := Install(context.Background(), d, c, tc.eco, tc.rel); err == nil {
			t.Errorf("Install(%s, %s) accepted", tc.eco, tc.rel)
		}
	}
	if len(rec.runs) != 0 {
		t.Errorf("a refused install ran %v", rec.runs)
	}
	d.Exec = func(context.Context, string, []string, []string, string) ([]byte, []byte, error) {
		return nil, []byte("Your requirements could not be resolved"), &exec.ExitError{}
	}
	err := Install(context.Background(), d, c, "Packagist", "composer.lock")
	var ce *CmdError
	if !errors.As(err, &ce) || !strings.Contains(ce.Output, "could not be resolved") {
		t.Errorf("failed install: %v", err)
	}
}

// committedFix prepares a copy of a project that is dirty and on another
// branch than its default one, then commits a change in the copy.
func committedFix(t *testing.T) (fixture, Copy, string) {
	t.Helper()
	f := newFixture(t)
	gitT(t, f.env, f.proj.Path, "checkout", "-q", "-b", "feature")
	writeFile(t, f.proj.Path, "README.md", "work in progress\n")
	writeFile(t, f.proj.Path, "staged.txt", "staged\n")
	gitT(t, f.env, f.proj.Path, "add", "staged.txt")
	writeFile(t, f.proj.Path, "untracked.txt", "u\n")
	c := prepare(t, f)
	writeFile(t, c.Dir, "composer.lock", `{"packages":[{"name":"acme/lib"}]}`+"\n")
	sha, err := Commit(context.Background(), f.deps, c, "fix(deps): upgrade acme/lib")
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return f, c, sha
}

func fileSHA(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestApplyLeavesWorkingTreeUntouched(t *testing.T) {
	f, c, sha := committedFix(t)
	statusBefore := gitT(t, f.env, f.proj.Path, "status", "--porcelain")
	gitDir := filepath.Join(f.proj.Path, ".git")
	indexBefore, headBefore := fileSHA(t, filepath.Join(gitDir, "index")), fileSHA(t, filepath.Join(gitDir, "HEAD"))
	stagedBefore := gitT(t, f.env, f.proj.Path, "ls-files", "-s")
	// The working tree (outside .git) must not change at all.
	work := func() string {
		h := sha256.New()
		_ = filepath.Walk(f.proj.Path, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() && info.Name() == ".git" {
				return filepath.SkipDir
			}
			rel, _ := filepath.Rel(f.proj.Path, p)
			fmt.Fprintf(h, "%s\x00%d\x00%d\n", rel, info.Size(), info.ModTime().UnixNano())
			return nil
		})
		return hex.EncodeToString(h.Sum(nil))
	}
	workBefore := work()
	branch := "michel/fix-01jattempt00"
	if err := Apply(context.Background(), f.deps, f.proj, c, sha, branch); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if fileSHA(t, filepath.Join(gitDir, "index")) != indexBefore {
		t.Error("the index of the project changed")
	}
	if fileSHA(t, filepath.Join(gitDir, "HEAD")) != headBefore {
		t.Error("HEAD of the project changed")
	}
	if work() != workBefore {
		t.Error("the working tree of the project changed")
	}
	if got := gitT(t, f.env, f.proj.Path, "status", "--porcelain"); got != statusBefore {
		t.Errorf("status changed:\n%s\nwant:\n%s", got, statusBefore)
	}
	if got := gitT(t, f.env, f.proj.Path, "ls-files", "-s"); got != stagedBefore {
		t.Error("the staged files changed")
	}
	if got := gitT(t, f.env, f.proj.Path, "rev-parse", "refs/heads/"+branch); got != sha {
		t.Errorf("branch points to %s, want %s", got, sha)
	}
	if got := gitT(t, f.env, f.proj.Path, "branch", "--show-current"); got != "feature" {
		t.Errorf("current branch %s, want feature", got)
	}
	if _, err := os.Stat(filepath.Join(gitDir, "FETCH_HEAD")); err == nil {
		t.Error("FETCH_HEAD was written")
	}
}

func TestApplyRefusesExistingBranch(t *testing.T) {
	f, c, sha := committedFix(t)
	branch := "michel/fix-01jattempt00"
	if err := Apply(context.Background(), f.deps, f.proj, c, sha, branch); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := Apply(context.Background(), f.deps, f.proj, c, sha, branch); !errors.Is(err, ErrBranchExists) {
		t.Errorf("second Apply: %v, want ErrBranchExists", err)
	}
	gitT(t, f.env, f.proj.Path, "branch", "michel/fix-taken0000")
	if err := Apply(context.Background(), f.deps, f.proj, c, sha, "michel/fix-taken0000"); !errors.Is(err, ErrBranchExists) {
		t.Errorf("Apply on a branch of the user: %v, want ErrBranchExists", err)
	}
	for _, bad := range []string{"main", "feature", "michel/fix-", "michel/fix-short", "michel/fix-ABCDEFGH", "michel/fix-abcdefgh/x", "refs/heads/michel/fix-abcdefgh", "michel/fix-abcdefgh:main", "michel/fix-abcdefgh..x", "-michel/fix-abcdefgh"} {
		if err := Apply(context.Background(), f.deps, f.proj, c, sha, bad); !errors.Is(err, ErrInvalidBranch) {
			t.Errorf("branch %q: %v, want ErrInvalidBranch", bad, err)
		}
	}
	for _, bad := range []string{"", "HEAD", "main", "--all", c.Base[:7], strings.Repeat("g", 40)} {
		if err := Apply(context.Background(), f.deps, f.proj, c, bad, "michel/fix-abcdefgh"); err == nil {
			t.Errorf("sha %q accepted", bad)
		}
	}
	// A commit that does not descend from the base of the copy is refused.
	if err := Apply(context.Background(), f.deps, f.proj, c, c.Base, "michel/fix-abcdefgh"); err == nil {
		t.Error("the base commit itself was applied as a fix")
	}
}

func TestIsMerged(t *testing.T) {
	f, c, sha := committedFix(t)
	if ok, err := IsMerged(context.Background(), f.deps, f.proj, sha); ok || err != nil {
		t.Errorf("before apply: %v %v, want false", ok, err)
	}
	branch := "michel/fix-01jattempt00"
	if err := Apply(context.Background(), f.deps, f.proj, c, sha, branch); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if ok, err := IsMerged(context.Background(), f.deps, f.proj, sha); ok || err != nil {
		t.Errorf("applied, not merged: %v %v, want false", ok, err)
	}
	gitT(t, f.env, f.proj.Path, "stash", "-q", "-u")
	gitT(t, f.env, f.proj.Path, "merge", "-q", "--no-edit", branch)
	if ok, err := IsMerged(context.Background(), f.deps, f.proj, sha); !ok || err != nil {
		t.Errorf("merged: %v %v, want true", ok, err)
	}
	if ok, err := IsMerged(context.Background(), f.deps, f.proj, strings.Repeat("ab", 20)); ok || err != nil {
		t.Errorf("unknown commit: %v %v, want false", ok, err)
	}
	if _, err := IsMerged(context.Background(), f.deps, f.proj, "HEAD"); err == nil {
		t.Error("a ref name was accepted as a commit id")
	}
}

func TestRemoveDeletesOnlyACopy(t *testing.T) {
	f := newFixture(t)
	c := prepare(t, f)
	if err := Remove(Copy{Dir: f.proj.Path}); err == nil {
		t.Error("Remove accepted a folder that is not a copy")
	}
	if _, err := os.Stat(f.proj.Path); err != nil {
		t.Fatal(err)
	}
	if err := Remove(c); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(c.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the copy is still there: %v", err)
	}
}

func TestDiffRefusesTamperedCopyConfig(t *testing.T) {
	f, c, sha := committedFix(t)
	if c.ConfigSHA == "" {
		t.Fatal("Prepare recorded no configuration digest")
	}
	cfg := filepath.Join(c.Dir, ".git", "config")
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, append(b, "[filter \"x\"]\n\tclean = run-me\n"...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Diff(context.Background(), f.deps, c); !errors.Is(err, ErrCopyTampered) {
		t.Errorf("Diff: %v, want ErrCopyTampered", err)
	}
	if _, err := Commit(context.Background(), f.deps, c, "fix"); !errors.Is(err, ErrCopyTampered) {
		t.Errorf("Commit: %v, want ErrCopyTampered", err)
	}
	if err := Apply(context.Background(), f.deps, f.proj, c, sha, "michel/fix-01jattempt00"); !errors.Is(err, ErrCopyTampered) {
		t.Errorf("Apply: %v, want ErrCopyTampered", err)
	}
	if err := os.WriteFile(cfg, b, 0o644); err != nil {
		t.Fatal(err)
	}
	c.ConfigSHA = ""
	if _, _, err := Diff(context.Background(), f.deps, c); !errors.Is(err, ErrCopyTampered) {
		t.Errorf("Diff without a digest: %v, want ErrCopyTampered", err)
	}
}
