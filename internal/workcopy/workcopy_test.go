package workcopy

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/project"
)

func fakeAWS() string { return "AKIA" + "ABCDEFGHIJKLMNOP" }

// minLock is the smallest package-lock.json Michel installs from: version
// 3 with a root entry.
const minLock = `{"lockfileVersion":3,"packages":{"":{}}}`

// junction makes link point at target: a junction on Windows (mklink /J,
// which needs no privilege), a symbolic link elsewhere. It reports whether
// the link exists.
func junction(t *testing.T, link, target string) bool {
	t.Helper()
	if runtime.GOOS != "windows" {
		return os.Symlink(target, link) == nil
	}
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Logf("mklink /J: %v %s", err, out)
	}
	return err == nil
}

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
	return newFixtureFrom(t, filepath.Join(template(t, "project").dir, "proj"), nil)
}

// newFixtureFrom copies the project of a template into a folder of the test.
func newFixtureFrom(t *testing.T, src string, repl []string) fixture {
	t.Helper()
	needGit(t)
	env := testGitEnv(t)
	root := t.TempDir()
	copyTree(t, src, root, repl)
	p := project.Project{ID: "01JDEMO0000000000000000000", Name: "demo", Path: root, Exclude: []string{"private"}}
	return fixture{env: env, proj: p, deps: Deps{DataDir: t.TempDir(), ProxyAddr: "127.0.0.1:1", Now: func() time.Time { return time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC) }}}
}

// buildProject builds, with git, the repository every fixture starts from.
func buildProject(t *testing.T, env []string, root string) {
	t.Helper()
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
	t.Cleanup(func() { _ = Remove(f.deps, c) })
	return c
}

func TestIsGitRepoFalseForPlainFolder(t *testing.T) {
	parallel(t)
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
	parallel(t)
	f := newFixture(t)
	// A dirty working tree and an untracked file: still nothing written.
	writeFile(t, f.proj.Path, "README.md", "changed\n")
	writeFile(t, f.proj.Path, "untracked.txt", "u\n")
	before := treeDigest(t, f.proj.Path)
	c := prepare(t, f)
	writeFile(t, c.Dir, "README.md", "fixed\n")
	if _, err := Diff(context.Background(), f.deps, c); err != nil {
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
	parallel(t)
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
	ch, err := Diff(context.Background(), f.deps, c)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !slices.Equal(ch.Files, []string{"src/app.php"}) {
		t.Errorf("files %v, want only src/app.php", ch.Files)
	}
	sha, err := Commit(context.Background(), f.deps, c, "fix")
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	tree := gitT(t, f.env, c.Mirror, "ls-tree", "-r", "--name-only", sha)
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
	parallel(t)
	f := newFixture(t)
	c := prepare(t, f)
	want := []mask.Hit{{File: "src/app.php", Line: 3, Kind: mask.KindAWSKey, Strong: true}}
	if !slices.Equal(c.SecretHits, want) {
		t.Errorf("SecretHits %+v, want %+v", c.SecretHits, want)
	}
}

func TestDiffRejectsOutsideCopy(t *testing.T) {
	parallel(t)
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
		// No symlink privilege (Windows): no link can exist in the copy, and
		// an entry staged by hand is dropped (Diff restarts the index from
		// Root), so there is nothing to refuse end to end.
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := Diff(context.Background(), f.deps, c); !errors.Is(err, ErrOutsideCopy) {
		t.Errorf("Diff with a symbolic link: %v, want ErrOutsideCopy", err)
	}
	if _, err := Commit(context.Background(), f.deps, c, "fix"); !errors.Is(err, ErrOutsideCopy) {
		t.Errorf("Commit with a symbolic link: %v, want ErrOutsideCopy", err)
	}
}

// fakeCopy makes an empty folder shaped like a fix copy in d.DataDir.
func fakeCopy(t *testing.T, d Deps) Copy {
	t.Helper()
	dir := filepath.Join(d.DataDir, "worktrees", "01JDEMO0000000000000000000", "01JFAKE0000000000000000000")
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	return Copy{Dir: dir}
}

func TestRunTestsNotRunWithoutCommand(t *testing.T) {
	parallel(t)
	d := Deps{DataDir: t.TempDir()}
	c := fakeCopy(t, d)
	d.Exec = func(context.Context, string, []string, []string, string) ([]byte, []byte, error) {
		t.Error("a command ran without a test command")
		return nil, nil, nil
	}
	status, out, err := RunTests(context.Background(), d, c, nil)
	if status != TestsNotRun || out != "" || err != nil {
		t.Errorf("got %q %q %v, want not_run", status, out, err)
	}
	if status, _, err := RunTests(context.Background(), d, Copy{Dir: t.TempDir()}, []string{"phpunit"}); status != TestsNotRun || !errors.Is(err, ErrNotACopy) {
		t.Errorf("tests outside a copy: %q %v, want ErrNotACopy", status, err)
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
	parallel(t)
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
			"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + filepath.Join(home, "gitconfig"), "GIT_TERMINAL_PROMPT=0",
			"COREPACK_ENABLE_DOWNLOAD_PROMPT=0", "COREPACK_ENABLE_AUTO_PIN=0", "COREPACK_ENABLE_NETWORK=0",
			"npm_config_git=" + filepath.Join(home, "no-git"), "GIT_NO_REPLACE_OBJECTS=1",
			"npm_config_proxy=http://127.0.0.1:1", "npm_config_https_proxy=http://127.0.0.1:1", "npm_config_noproxy=",
			"npm_config_strict_ssl=true", "COMPOSER_NO_INTERACTION=1", "COMPOSER_VENDOR_DIR=vendor", "COMPOSER_BIN_DIR=vendor/bin"} {
			if !slices.Contains(r.env, want) {
				t.Errorf("%s %v: %s missing from the environment", r.name, r.args, want)
			}
		}
		rel, err := filepath.Rel(f.deps.DataDir, r.dir)
		if err != nil || !filepath.IsLocal(rel) && rel != "." {
			t.Errorf("%s %v ran from %s, outside the data folder", r.name, r.args, r.dir)
		}
		if r.name == "git" {
			if !slices.Contains(r.args, "core.hooksPath="+filepath.Join(f.deps.DataDir, "fix-hooks")) || !slices.Contains(r.args, "core.fsmonitor=false") {
				t.Errorf("git %v: hooks or fsmonitor not disabled", r.args)
			}
			// Long paths: a data folder deep in the profile must not make
			// a clone fail on Windows ("Filename too long").
			if !slices.Contains(r.args, "core.longpaths=true") {
				t.Errorf("git %v: core.longpaths=true missing", r.args)
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
	parallel(t)
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
	parallel(t)
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
	parallel(t)
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
	parallel(t)
	f := newFixture(t)
	c := prepare(t, f)
	if err := Remove(f.deps, Copy{Dir: f.proj.Path}); err == nil {
		t.Error("Remove accepted a folder that is not a copy")
	}
	// Shaped like a copy, but outside the data folder.
	other := fakeCopy(t, Deps{DataDir: t.TempDir()})
	if err := Remove(f.deps, other); !errors.Is(err, ErrNotACopy) {
		t.Errorf("Remove outside the data folder: %v, want ErrNotACopy", err)
	}
	if _, err := os.Stat(other.Dir); err != nil {
		t.Error("Remove deleted a folder outside the data folder")
	}
	if _, err := os.Stat(f.proj.Path); err != nil {
		t.Fatal(err)
	}
	if err := Remove(f.deps, c); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	for _, p := range []string{c.Dir, c.Mirror} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is still there: %v", filepath.Base(p), err)
		}
	}
}

func TestDiffRefusesTamperedCopyConfig(t *testing.T) {
	parallel(t)
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
	if _, err := Diff(context.Background(), f.deps, c); !errors.Is(err, ErrCopyTampered) {
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
	if _, err := Diff(context.Background(), f.deps, c); !errors.Is(err, ErrCopyTampered) {
		t.Errorf("Diff without a digest: %v, want ErrCopyTampered", err)
	}
}

func TestCopyHasNoExcludedBlobs(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	c := prepare(t, f)
	objects := gitT(t, f.env, c.Dir, "cat-file", "--batch-all-objects", "--batch")
	if strings.Contains(objects, "s3cr3tvalue") {
		t.Error("an object of the copy holds the excluded .env")
	}
	if strings.Contains(objects, "private") {
		t.Error("an object of the copy holds a file of an excluded folder")
	}
	if n := gitT(t, f.env, c.Dir, "rev-list", "--count", "--all"); n != "1" {
		t.Errorf("the copy has %s commits, want 1", n)
	}
	if log := gitT(t, f.env, c.Dir, "log", "--format=%an %s"); log != "Michel michel: base" {
		t.Errorf("copy log %q", log)
	}
	if remotes := gitT(t, f.env, c.Dir, "remote"); remotes != "" {
		t.Errorf("the copy has remotes: %s", remotes)
	}
}

func TestCopyHasNoAbsolutePath(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	c := prepare(t, f)
	needles := []string{f.proj.Path, filepath.ToSlash(f.proj.Path), f.deps.DataDir, filepath.ToSlash(f.deps.DataDir)}
	err := filepath.Walk(c.Dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, n := range needles {
			if strings.Contains(strings.ToLower(string(b)), strings.ToLower(n)) {
				rel, _ := filepath.Rel(c.Dir, p)
				t.Errorf("%s holds an absolute path", rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCopyKeepsFilesAsCommitted(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	// export-ignore would drop tests/ from git archive; eol=crlf would
	// rewrite line ends; both are turned off for the copy.
	writeFile(t, f.proj.Path, ".gitattributes", "tests export-ignore\n*.txt text eol=crlf\n")
	writeFile(t, f.proj.Path, "tests/AppTest.php", "<?php\n")
	writeFile(t, f.proj.Path, "notes.txt", "a\nb\n")
	gitT(t, f.env, f.proj.Path, "add", "-A")
	gitT(t, f.env, f.proj.Path, "commit", "-q", "-m", "attributes")
	c := prepare(t, f)
	if _, err := os.Stat(filepath.Join(c.Dir, "tests", "AppTest.php")); err != nil {
		t.Errorf("an export-ignore file is missing from the copy: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(c.Dir, "notes.txt")); string(b) != "a\nb\n" {
		t.Errorf("notes.txt %q, want the committed bytes", b)
	}
	writeFile(t, c.Dir, "notes.txt", "a\nc\n")
	sha, err := Commit(context.Background(), f.deps, c, "fix")
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got := gitT(t, f.env, c.Mirror, "diff", "--name-only", c.Base, sha); got != "notes.txt" {
		t.Errorf("fix commit changes %q, want notes.txt", got)
	}
}

func TestDiffRawIsTheAppliedPatch(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	c := prepare(t, f)
	writeFile(t, c.Dir, "README.md", "fixed\x1b[31m\r\n")
	writeFile(t, c.Dir, "bin.dat", "\x00\x01\x02")
	ch, err := Diff(context.Background(), f.deps, c)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !strings.Contains(string(ch.Raw), "\x1b[31m\r") || !strings.Contains(string(ch.Raw), "GIT binary patch") {
		t.Error("Raw is not the exact binary patch")
	}
	if strings.Contains(ch.Display, "\x1b") || strings.Contains(ch.Display, "GIT binary patch") {
		t.Error("Display is not the sanitized text diff")
	}
	if !slices.Equal(ch.Files, []string{"README.md", "bin.dat"}) {
		t.Errorf("files %v", ch.Files)
	}
	sha, err := Commit(context.Background(), f.deps, c, "fix")
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got := gitT(t, f.env, c.Mirror, "cat-file", "blob", sha+":bin.dat"); got != "\x00\x01\x02" {
		t.Errorf("binary file %q in the fix commit", got)
	}
}

func TestApplyIgnoresAgentCommits(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	c := prepare(t, f)
	// The agent commits in its copy: a file added then removed, a hook.
	writeFile(t, c.Dir, "evil.txt", "evil payload\n")
	gitT(t, f.env, c.Dir, "add", "evil.txt")
	gitT(t, f.env, c.Dir, "commit", "-q", "-m", "add")
	evil := gitT(t, f.env, c.Dir, "rev-parse", "HEAD:evil.txt")
	gitT(t, f.env, c.Dir, "rm", "-q", "evil.txt")
	gitT(t, f.env, c.Dir, "commit", "-q", "-m", "remove")
	writeFile(t, c.Dir, ".git/hooks/x", "#!/bin/sh\n")
	writeFile(t, c.Dir, "composer.lock", `{"packages":[{"name":"acme/lib"}]}`+"\n")
	sha, err := Commit(context.Background(), f.deps, c, "fix(deps): upgrade acme/lib")
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	branch := "michel/fix-01jattempt00"
	if err := Apply(context.Background(), f.deps, f.proj, c, sha, branch); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if n := gitT(t, f.env, f.proj.Path, "rev-list", "--count", c.Base+".."+branch); n != "1" {
		t.Errorf("the branch adds %s commits, want 1", n)
	}
	if parents := gitT(t, f.env, f.proj.Path, "rev-parse", branch+"^@"); parents != c.Base {
		t.Errorf("parents %q, want Base", parents)
	}
	if who := gitT(t, f.env, f.proj.Path, "log", "-1", "--format=%an <%ae> %cn", branch); who != "Michel <michel@localhost> Michel" {
		t.Errorf("author %q", who)
	}
	if files := gitT(t, f.env, f.proj.Path, "diff", "--name-only", c.Base, branch); files != "composer.lock" {
		t.Errorf("the branch changes %q", files)
	}
	cmd := exec.Command("git", "-C", f.proj.Path, "cat-file", "-e", evil)
	cmd.Env = f.env
	if cmd.Run() == nil {
		t.Error("an object of the agent's commits reached the project")
	}
	// A commit of the copy is not a fix commit.
	agentHead := gitT(t, f.env, c.Dir, "rev-parse", "HEAD")
	if err := Apply(context.Background(), f.deps, f.proj, c, agentHead, "michel/fix-otherbranch"); err == nil {
		t.Error("a commit of the agent's copy was applied")
	}
}

func TestPlantedHooksDoNotRun(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	c := prepare(t, f)
	marker := filepath.Join(t.TempDir(), "ran")
	hook := "#!/bin/sh\necho ran > '" + filepath.ToSlash(marker) + "'\n"
	for _, dir := range []string{filepath.Join(f.deps.DataDir, "fix-hooks"), filepath.Join(c.Dir, ".git", "hooks"), filepath.Join(c.Mirror, "hooks"), filepath.Join(f.deps.DataDir, "fix-home")} {
		for _, name := range []string{"pre-commit", "post-commit", "commit-msg", "reference-transaction", "post-index-change"} {
			writeFile(t, dir, name, hook)
			_ = os.Chmod(filepath.Join(dir, name), 0o755)
		}
	}
	writeFile(t, c.Dir, "README.md", "fixed\n")
	sha, err := Commit(context.Background(), f.deps, c, "fix")
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := Apply(context.Background(), f.deps, f.proj, c, sha, "michel/fix-01jattempt00"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("a planted hook ran")
	}
	if entries, _ := os.ReadDir(filepath.Join(f.deps.DataDir, "fix-hooks")); len(entries) != 0 {
		t.Error("the hooks folder was not emptied")
	}
}

func TestInstallRefusesSymlinkedManifestDir(t *testing.T) {
	parallel(t)
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	outside := t.TempDir()
	writeFile(t, outside, "composer.lock", "{}")
	if err := os.Symlink(outside, filepath.Join(c.Dir, "vendored")); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if err := Install(context.Background(), d, c, "Packagist", "vendored/composer.lock"); !errors.Is(err, ErrOutsideCopy) {
		t.Errorf("install through a linked folder: %v, want ErrOutsideCopy", err)
	}
	if len(rec.runs) != 0 {
		t.Errorf("the install ran %v", rec.runs)
	}
}

func TestMirrorIsOutsideCopyTree(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	c := prepare(t, f)
	tree := filepath.Dir(c.Dir)
	under := func(p string) bool {
		rel, err := filepath.Rel(tree, p)
		return err == nil && (rel == "." || filepath.IsLocal(rel))
	}
	want := filepath.Join(f.deps.DataDir, "fix-mirrors", f.proj.ID, "01JATTEMPT0000000000000000.git")
	if c.Mirror != want || under(c.Mirror) {
		t.Errorf("mirror at %s, want %s outside the copies", c.Mirror, want)
	}
	// Temporary files appear only in <data>/fix-tmp while Michel works,
	// and are gone afterwards.
	var seen []string
	f.deps.Exec = func(ctx context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
		for _, a := range append(append([]string{dir}, args...), env...) {
			if _, v, ok := strings.Cut(a, "="); ok && filepath.IsAbs(v) {
				a = v
			}
			if filepath.IsAbs(a) {
				seen = append(seen, a)
			}
		}
		return defaultExec(ctx, name, args, env, dir)
	}
	writeFile(t, c.Dir, "README.md", "fixed\n")
	if _, err := Commit(context.Background(), f.deps, c, "fix"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	for _, p := range seen {
		if strings.Contains(p, "fix.index") || strings.Contains(p, "fix.patch") || strings.HasSuffix(p, ".git") && p != filepath.Join(c.Dir, ".git") {
			if under(p) {
				t.Errorf("%s is under the copies' folder", p)
			}
		}
	}
	entries, err := os.ReadDir(tree)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(c.Dir) {
			t.Errorf("%s sits next to the copy", e.Name())
		}
	}
	if entries, _ := os.ReadDir(filepath.Join(f.deps.DataDir, "fix-tmp")); len(entries) != 0 {
		t.Errorf("temporary files left: %d", len(entries))
	}
	if err := Remove(f.deps, c); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	for _, p := range []string{c.Dir, c.Mirror, filepath.Join(f.deps.DataDir, "fix-tmp", filepath.Base(c.Dir))} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left after Remove", p)
		}
	}
}

func TestSafeSegmentNormalizesLikeNTFS(t *testing.T) {
	parallel(t)
	for _, p := range []string{".git./hooks/x", ".GIT /x", "git~1/x", "GIT~2/config", "a:b", "nul.txt", "sub/CON", "lpt1.log", "com9", "aux .txt",
		"a/<b", "a/b|c", "x\x01y", "a/../b", "./a", "a/./b", ". ./x", ".git"} {
		if err := checkEntry(rawEntry{path: p, mode: "100644"}); !errors.Is(err, ErrOutsideCopy) {
			t.Errorf("%q: %v, want ErrOutsideCopy", p, err)
		}
	}
	for _, p := range []string{"src/app.php", ".gitignore", ".github/workflows/ci.yml", "git~x/a", "console.txt", "nullable.php", "com10.txt", "a.git/x", ".env.example"} {
		if err := checkEntry(rawEntry{path: p, mode: "100644"}); err != nil {
			t.Errorf("%q refused: %v", p, err)
		}
	}
}

func TestExtractSkipsUnsafeTarEntries(t *testing.T) {
	parallel(t)
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "a.tar")
	out, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(out)
	add := func(name string, typ byte, body string) {
		hdr := &tar.Header{Name: name, Typeflag: typ, Mode: 0o644, Size: int64(len(body))}
		if typ == tar.TypeSymlink {
			hdr.Linkname, hdr.Size = "../../outside", 0
			body = ""
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	add("ok.txt", tar.TypeReg, "ok")
	for _, bad := range []string{".git./hooks/x", ".GIT /x", "git~1/x", "a:b", "nul.txt", "../escape.txt"} {
		add(bad, tar.TypeReg, "bad")
	}
	add("link", tar.TypeSymlink, "")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	out.Close()
	dir := filepath.Join(tmp, "copy")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	kept, _, err := extract(archive, dir, nil)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !slices.Equal(kept, []string{"ok.txt"}) {
		t.Errorf("kept %v, want only ok.txt", kept)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the copy holds %v", names)
	}
	if _, err := os.Lstat(filepath.Join(tmp, "escape.txt")); err == nil {
		t.Error("an entry was written outside the copy")
	}
}

func TestExcludedPathsNeverReachTheCommit(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	c := prepare(t, f)
	writeFile(t, c.Dir, ".ENV", "DB_PASSWORD=other\n")
	writeFile(t, c.Dir, "config/SERVER.KEY", "key\n")
	writeFile(t, c.Dir, "new.pem", "pem\n")
	writeFile(t, c.Dir, "private/planted.php", "<?php\n")
	writeFile(t, c.Dir, "PRIVATE/planted.php", "<?php\n")
	gitT(t, f.env, c.Dir, "add", "-f", "new.pem", "private/planted.php")
	writeFile(t, c.Dir, "README.md", "fixed\n")
	ch, err := Diff(context.Background(), f.deps, c)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !slices.Equal(ch.Files, []string{"README.md"}) {
		t.Errorf("files %v, want only README.md", ch.Files)
	}
	sha, err := Commit(context.Background(), f.deps, c, "fix")
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got := gitT(t, f.env, c.Mirror, "diff", "--name-only", c.Base, sha); got != "README.md" {
		t.Errorf("the fix commit changes %q", got)
	}
}

func TestCheckExcludedIsCaseInsensitive(t *testing.T) {
	parallel(t)
	c := Copy{Excluded: []string{"config/.env.local"}, Exclude: []string{"private"}}
	for _, p := range []string{".ENV", ".Env.production", "config/SERVER.KEY", "a/Cert.PEM", "ID_RSA", "PRIVATE/x.php", "src/Private/x", "CONFIG/.ENV.LOCAL"} {
		if err := checkExcluded(c, []string{"src/ok.php", p}); !errors.Is(err, ErrExcludedPath) {
			t.Errorf("%q: %v, want ErrExcludedPath", p, err)
		}
	}
	if err := checkExcluded(c, []string{"src/ok.php", "privateer/x.php", "keys.php", "environment.php"}); err != nil {
		t.Errorf("plain files refused: %v", err)
	}
}

func TestPrepareExcludesCaseVariants(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	writeFile(t, f.proj.Path, "certs/Server.PEM", "pem\n")
	f.proj.Exclude = []string{"private", "secret-docs"}
	writeFile(t, f.proj.Path, "Secret-Docs/notes.txt", "p\n")
	gitT(t, f.env, f.proj.Path, "add", "-A")
	gitT(t, f.env, f.proj.Path, "commit", "-q", "-m", "case")
	c := prepare(t, f)
	for _, rel := range []string{"certs/Server.PEM", "Secret-Docs"} {
		if _, err := os.Lstat(filepath.Join(c.Dir, filepath.FromSlash(rel))); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was copied", rel)
		}
	}
	if !slices.Contains(c.Excluded, "certs/Server.PEM") || !slices.Contains(c.Excluded, "Secret-Docs/notes.txt") {
		t.Errorf("Excluded %v", c.Excluded)
	}
}

func TestDisplayIgnoresDiffAttributes(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	c := prepare(t, f)
	writeFile(t, c.Dir, ".gitattributes", "* -diff\n")
	writeFile(t, c.Dir, "README.md", "fixed line\n")
	ch, err := Diff(context.Background(), f.deps, c)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !strings.Contains(ch.Display, "+fixed line") || strings.Contains(ch.Display, "Binary files") {
		t.Errorf("Display hides the change:\n%s", ch.Display)
	}
	if !strings.Contains(string(ch.Raw), "+fixed line") || strings.Contains(string(ch.Raw), "GIT binary patch") {
		t.Errorf("Raw is not a text patch:\n%s", ch.Raw)
	}
}

func TestCheckBinaryRefusesTextContent(t *testing.T) {
	parallel(t)
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "plain text\n")
	writeFile(t, dir, "b.bin", "\x00\x01\x02")
	if err := checkBinary(dir, []string{"a.txt"}, nil); !errors.Is(err, ErrBinaryChange) {
		t.Errorf("text shown as binary: %v, want ErrBinaryChange", err)
	}
	if err := checkBinary(dir, []string{"b.bin", "deleted.txt"}, map[string]bool{"deleted.txt": true}); err != nil {
		t.Errorf("a real binary or a deletion refused: %v", err)
	}
}

func TestPrepareBoundsTheArchive(t *testing.T) {
	f := newFixture(t)
	old := maxCopyFiles
	maxCopyFiles = 3
	defer func() { maxCopyFiles = old }()
	if _, err := Prepare(context.Background(), f.deps, f.proj, "01JATTEMPT0000000000000000"); !errors.Is(err, ErrCopyTooLarge) {
		t.Errorf("Prepare of a too large project: %v, want ErrCopyTooLarge", err)
	}
	for _, p := range []string{filepath.Join(f.deps.DataDir, "fix-tmp", "01JATTEMPT0000000000000000"), filepath.Join(f.deps.DataDir, "worktrees", f.proj.ID, "01JATTEMPT0000000000000000")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s left after a refused Prepare", p)
		}
	}
}

func TestExtractCreatesNoExcludedFolder(t *testing.T) {
	parallel(t)
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "a.tar")
	out, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(out)
	for _, e := range []struct {
		name string
		typ  byte
	}{{"private/", tar.TypeDir}, {"private/sub/", tar.TypeDir}, {"private/sub/x.txt", tar.TypeReg}, {"src/", tar.TypeDir}, {"src/a.txt", tar.TypeReg}} {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o755}
		if e.typ == tar.TypeReg {
			hdr.Size = 1
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			tw.Write([]byte("x"))
		}
	}
	tw.Close()
	out.Close()
	dir := filepath.Join(tmp, "copy")
	os.Mkdir(dir, 0o755)
	if _, _, err := extract(archive, dir, []string{"private"}); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "private")); !errors.Is(err, os.ErrNotExist) {
		t.Error("the excluded folder was created")
	}
}

func TestInstallArgvByLockfile(t *testing.T) {
	parallel(t)
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	writeFile(t, c.Dir, "composer.lock", "{}")
	writeFile(t, c.Dir, "web/package-lock.json", minLock)
	writeFile(t, c.Dir, "pn/pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
	writeFile(t, c.Dir, "y1/yarn.lock", "# yarn lockfile v1\n")
	npmrc := filepath.Join(d.DataDir, "fix-home", "npmrc")
	for _, tc := range []struct {
		eco, rel, name string
		args           []string
		dir            string
	}{
		{"Packagist", "composer.lock", "composer", []string{"install", "--no-scripts", "--no-interaction", "--no-plugins"}, ""},
		{"npm", "web/package-lock.json", "npm", []string{"ci", "--ignore-scripts", "--no-audit", "--no-fund", "--userconfig", npmrc}, "web"},
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
	for _, rel := range []string{"pn/pnpm-lock.yaml", "y1/yarn.lock"} {
		if err := Install(context.Background(), d, c, "npm", rel); !errors.Is(err, ErrInstallUnsupported) {
			t.Errorf("%s: %v, want ErrInstallUnsupported", rel, err)
		}
	}
	for _, tc := range []struct{ eco, rel string }{{"npm", "composer.lock"}, {"Packagist", "missing/composer.lock"}, {"Packagist", "../composer.lock"}, {"Packagist", "README.md"}, {"PyPI", "composer.lock"}} {
		if err := Install(context.Background(), d, c, tc.eco, tc.rel); err == nil {
			t.Errorf("Install(%s, %s) accepted", tc.eco, tc.rel)
		}
	}
	if err := Install(context.Background(), d, Copy{Dir: t.TempDir()}, "Packagist", "composer.lock"); !errors.Is(err, ErrNotACopy) {
		t.Errorf("install outside a copy: %v, want ErrNotACopy", err)
	}
	if len(rec.runs) != 0 {
		t.Errorf("a refused install ran %d commands", len(rec.runs))
	}
	if b, err := os.ReadFile(npmrc); err != nil || len(b) != 0 {
		t.Errorf("Michel's npmrc is not an empty file: %v", err)
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

// installCase writes files in a fresh folder of the copy and installs its
// lockfile; it returns the error.
func installCase(t *testing.T, d Deps, c Copy, dir string, files map[string]string) error {
	t.Helper()
	lock, eco := "", ""
	for name, body := range files {
		writeFile(t, c.Dir, dir+"/"+name, body)
		switch filepath.Base(name) {
		case "composer.lock":
			lock, eco = name, "Packagist"
		case "package-lock.json":
			lock, eco = name, "npm"
		}
	}
	return Install(context.Background(), d, c, eco, dir+"/"+lock)
}

func TestNpmrcIsAllowlisted(t *testing.T) {
	parallel(t)
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	for i, body := range []string{
		"\"git\"=./evil\n", "${X}=y\n", "proxy=http://evil.example\n", "store-dir=../x\n", "strict-ssl=false\n",
		"[section]\nregistry=https://r.example\n", "registry\\x=y\n", "ignore-scripts\n", "script-shell=/tmp/x.sh\n",
		"  node-options = --require ./evil.js\n", "git=./evil\n", "userconfig=../x\n", "prefix=../x\n",
		"registry=https://r.example/\rvirtual-store-dir=../../../outside\rstore-dir=C:/x\n",
	} {
		if err := installCase(t, d, c, fmt.Sprintf("r%d", i), map[string]string{"package-lock.json": minLock, ".npmrc": body}); !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf(".npmrc %q: %v, want ErrUnsafeInstall", body, err)
		}
	}
	// A setting in a parent folder of the lockfile counts too.
	if err := installCase(t, d, c, "up", map[string]string{".npmrc": "script-shell=./evil.sh\n", "web/package-lock.json": minLock}); !errors.Is(err, ErrUnsafeInstall) {
		t.Errorf(".npmrc in a parent folder: %v, want ErrUnsafeInstall", err)
	}
	if len(rec.runs) != 0 {
		t.Errorf("a refused install ran %d commands", len(rec.runs))
	}
	if err := installCase(t, d, c, "ok", map[string]string{"package-lock.json": minLock, ".npmrc": "# c\r\n; c\r\nregistry=https://r.example/\r\n@acme:registry=https://npm.example/\n" +
		"//npm.example/:_authToken=${NPM_TOKEN}\n//npm.example/path/:_auth=abc\n//npm.example/:username=u\n//npm.example/:_password=p\nalways-auth=true\n"}); err != nil {
		t.Errorf("registry and auth settings refused: %v", err)
	}
}

func TestPackageJSONIsChecked(t *testing.T) {
	parallel(t)
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	refused := []string{
		`{"packageManager":"yarn@1.22.22"}`,
		`{"packageManager":"pnpm@9.0.0"}`,
		`{"packageManager":"npm@https://evil.example/x.tgz"}`,
		`{"packageManager":"npm@file:../x"}`,
		`{"packageManager":"npm@latest"}`,
		`{"packageManager":"npm"}`,
		`{"packageManager":{"name":"npm"}}`,
		`{"packageManager":"npm@10.8.2","PackageManager":"yarn@1.0.0"}`,
		`{"dependencies":{"a":"file:../../outside"}}`,
		`{"devDependencies":{"a":"link:../x"}}`,
		`{"optionalDependencies":{"a":"../x"}}`,
		`{"peerDependencies":{"a":"/abs/x"}}`,
		`{"dependencies":{"a":"C:\\x"}}`,
		`{"overrides":{"a":{"b":"file:./x"}}}`,
		`{"workspaces":["../outside/*"]}`,
		`{"workspaces":{"packages":["/abs"]}}`,
		`{"dependencies":{"a":"^1.0.0"},"dependencies":{"a":"file:../x"}}`,
	}
	for i, pkg := range refused {
		if err := installCase(t, d, c, fmt.Sprintf("r%d", i), map[string]string{"package-lock.json": minLock, "package.json": pkg}); !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf("package.json %s: %v, want ErrUnsafeInstall", pkg, err)
		}
	}
	// The nearest package.json is clean, a parent one is hostile.
	if err := installCase(t, d, c, "top", map[string]string{"package.json": `{"packageManager":"yarn@https://evil.example/x.tgz"}`,
		"app/package.json": `{"name":"acme-lib"}`, "app/package-lock.json": minLock}); !errors.Is(err, ErrUnsafeInstall) {
		t.Errorf("hostile packageManager in a parent folder: %v, want ErrUnsafeInstall", err)
	}
	for i, lock := range []string{
		`{"lockfileVersion":3,"packages":{"node_modules/a":{"resolved":"../../outside","link":true}}}`,
		`{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0","integrity":"sha512-x","resolved":"file:../x.tgz"}}}`,
		`{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0","integrity":"sha512-x","resolved":"git+ssh://git@evil.example/x.git"}}}`,
	} {
		if err := installCase(t, d, c, fmt.Sprintf("l%d", i), map[string]string{"package-lock.json": lock}); !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf("package-lock.json %s: %v, want ErrUnsafeInstall", lock, err)
		}
	}
	if len(rec.runs) != 0 {
		t.Errorf("a refused install ran %d commands", len(rec.runs))
	}
	for i, pm := range []string{"npm@10.8.2", "npm@11.0.0-pre.1+sha512.0123abcdef"} {
		rec.runs = nil
		pkg := `{"packageManager":` + strconv.Quote(pm) + `,"dependencies":{"a":"^1.2.3","b":"npm:c@1"},"workspaces":["packages/*"]}`
		lock := `{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.2.3","resolved":"https://registry.npmjs.org/a/-/a-1.2.3.tgz","integrity":"sha512-abc"},"node_modules/w":{"resolved":"packages/w","link":true}}}`
		if err := installCase(t, d, c, fmt.Sprintf("ok%d", i), map[string]string{"package-lock.json": lock, "package.json": pkg}); err != nil {
			t.Errorf("packageManager %q refused: %v", pm, err)
			continue
		}
		if len(rec.runs) != 1 || !slices.Contains(rec.runs[0].env, "COREPACK_ENABLE_NETWORK=0") {
			t.Errorf("packageManager %q: corepack may download", pm)
		}
	}
}

func TestComposerSettingsAreAllowlisted(t *testing.T) {
	parallel(t)
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	refused := []string{
		`{"config":{"vendor-dir":"../../x"},"Config":null}`,
		`{"Config":{"vendor-dir":"../../x"}}`,
		`{"config":{"sort-packages":true},"config":{"vendor-dir":"../x"}}`,
		`{"config":"vendor"}`,
		`{"config":{"vendor-dir":"../x"}}`,
		`{"config":{"bin-dir":"../x"}}`,
		`{"config":{"cache-dir":"../x"}}`,
		`{"config":{"data-dir":"../x"}}`,
		`{"config":{"home":"../x"}}`,
		`{"config":{"disable-tls":true}}`,
		`{"config":{"secure-http":false}}`,
		`{"config":{"process-timeout":0}}`,
		`{"repositories":[{"type":"path","url":"../outside"}]}`,
		`{"repositories":[{"type":"artifact","url":"./zips"}]}`,
		`{"repositories":[{"type":"vcs","url":"https://evil.example/x.git"}]}`,
		`{"repositories":[{"type":"git","url":"https://evil.example/x.git"}]}`,
		`{"repositories":[{"type":"package","package":{"name":"a/b","version":"1.0","dist":{"url":"file:///x","type":"zip"}}}]}`,
		`{"repositories":[{"type":"composer","url":"http://insecure.example"}]}`,
		`{"repositories":{"x":{"type":"composer","url":"https://r.example","options":{"ssl":{"verify_peer":false}}}}}`,
		`not json`,
	}
	for i, cj := range refused {
		if err := installCase(t, d, c, fmt.Sprintf("r%d", i), map[string]string{"composer.lock": "{}", "composer.json": cj}); !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf("composer.json %s: %v, want ErrUnsafeInstall", cj, err)
		}
	}
	for i, lock := range []string{
		`{"packages":[{"name":"a/b","dist":{"type":"path","url":"../outside"}}]}`,
		`{"packages-dev":[{"name":"a/b","dist":{"type":"zip","url":"file:///x.zip"}}]}`,
		`{"packages":[{"name":"a/b","source":{"type":"path","url":"../x"}}]}`,
		`{"packages":[{"name":"a/b","source":{"type":"git","url":"../x"}}]}`,
	} {
		if err := installCase(t, d, c, fmt.Sprintf("l%d", i), map[string]string{"composer.lock": lock}); !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf("composer.lock %s: %v, want ErrUnsafeInstall", lock, err)
		}
	}
	if len(rec.runs) != 0 {
		t.Errorf("a refused install ran %d commands", len(rec.runs))
	}
	ok := `{"name":"acme/lib","config":{"sort-packages":true,"platform":{"php":"8.2"},"allow-plugins":{"a/b":true},"optimize-autoloader":true,"preferred-install":"dist","platform-check":false,"audit":{"abandoned":"ignore"}},` +
		`"repositories":[{"type":"composer","url":"https://repo.example"},{"packagist.org":false}]}`
	lock := `{"packages":[{"name":"acme/lib","dist":{"type":"zip","url":"https://api.github.com/repos/acme/lib/zipball/x"},"source":{"type":"git","url":"https://github.com/acme/lib.git"}}]}`
	if err := installCase(t, d, c, "ok", map[string]string{"composer.lock": lock, "composer.json": ok}); err != nil {
		t.Errorf("a plain composer project refused: %v", err)
	}
}

func TestInstallStartsFromFreshFolders(t *testing.T) {
	parallel(t)
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	outside := t.TempDir()
	writeFile(t, outside, "keep.txt", "keep\n")
	writeFile(t, c.Dir, "a/composer.lock", "{}")
	writeFile(t, c.Dir, "a/vendor/autoload.php", "<?php\n")
	if err := os.Link(filepath.Join(outside, "keep.txt"), filepath.Join(c.Dir, "a", "vendor", "hard.txt")); err != nil {
		t.Logf("hard links unavailable: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(c.Dir, "a", "vendor", "inner")); err != nil {
		t.Logf("symbolic links unavailable: %v", err)
	}
	if err := Install(context.Background(), d, c, "Packagist", "a/composer.lock"); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(c.Dir, "a", "vendor")); !errors.Is(err, os.ErrNotExist) {
		t.Error("vendor was not deleted before the install")
	}
	// node_modules itself a link (junction on Windows): the link goes, the
	// target stays.
	writeFile(t, c.Dir, "b/package-lock.json", minLock)
	if junction(t, filepath.Join(c.Dir, "b", "node_modules"), outside) {
		if err := Install(context.Background(), d, c, "npm", "b/package-lock.json"); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(c.Dir, "b", "node_modules")); !errors.Is(err, os.ErrNotExist) {
			t.Error("the node_modules link was not removed")
		}
	}
	// A junction inside node_modules: removed with it, never followed.
	writeFile(t, c.Dir, "e/package-lock.json", minLock)
	writeFile(t, c.Dir, "e/node_modules/x/index.js", "x\n")
	if junction(t, filepath.Join(c.Dir, "e", "node_modules", "inner"), outside) {
		if err := Install(context.Background(), d, c, "npm", "e/package-lock.json"); err != nil {
			t.Fatalf("Install: %v", err)
		}
	}
	if b, err := os.ReadFile(filepath.Join(outside, "keep.txt")); err != nil || string(b) != "keep\n" {
		t.Errorf("a file outside the copy was touched: %v", err)
	}
	// bin stays checked: a link there is refused.
	writeFile(t, c.Dir, "f/package-lock.json", minLock)
	if junction(t, filepath.Join(c.Dir, "f", "bin"), outside) {
		if err := Install(context.Background(), d, c, "npm", "f/package-lock.json"); !errors.Is(err, ErrOutsideCopy) {
			t.Errorf("linked bin: %v, want ErrOutsideCopy", err)
		}
	}
}

func TestCheckExcludedReadsNamesLikeWindows(t *testing.T) {
	parallel(t)
	c := Copy{Exclude: []string{"private"}}
	for _, p := range []string{".ENV.", ".env ", "CONFIG~1/server.key", "PRIVAT~1/x.php", "SERVER~1.KEY", "src/A~12.TXT"} {
		if err := checkExcluded(c, []string{p}); !errors.Is(err, ErrExcludedPath) {
			t.Errorf("%q: %v, want ErrExcludedPath", p, err)
		}
	}
	if err := checkExcluded(c, []string{"src/tilde~x.php", "a~/b.php"}); err != nil {
		t.Errorf("plain names refused: %v", err)
	}
}

func TestTreeSizeIgnoresExcludedFiles(t *testing.T) {
	f := newFixture(t)
	old := maxCopyFiles
	// The fixture holds 8 files, 4 of them excluded.
	maxCopyFiles = 5
	defer func() { maxCopyFiles = old }()
	if _, err := Prepare(context.Background(), f.deps, f.proj, "01JATTEMPT0000000000000000"); err != nil {
		t.Errorf("excluded files were counted: %v", err)
	}
}

func TestEnvAcceptsProxyURL(t *testing.T) {
	parallel(t)
	d := Deps{DataDir: t.TempDir(), ProxyAddr: "http://michel:0123abcd@127.0.0.1:4567"}
	env, home, err := Env(d)
	if err != nil {
		t.Fatal(err)
	}
	if home != filepath.Join(d.DataDir, "fix-home") {
		t.Errorf("home = %s", home)
	}
	if !slices.Contains(env, "HTTPS_PROXY=http://michel:0123abcd@127.0.0.1:4567") {
		t.Errorf("HTTPS_PROXY missing or doubled scheme: %v", env)
	}
	d.ProxyAddr = "127.0.0.1:4567"
	env, _, _ = Env(d)
	if !slices.Contains(env, "https_proxy=http://127.0.0.1:4567") {
		t.Errorf("host:port form: %v", env)
	}
}
