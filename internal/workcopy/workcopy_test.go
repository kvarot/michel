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
	t.Cleanup(func() { _ = Remove(f.deps, c) })
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
			"npm_config_git=" + filepath.Join(home, "no-git")} {
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
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	writeFile(t, c.Dir, "composer.lock", "{}")
	writeFile(t, c.Dir, "web/package-lock.json", "{}")
	writeFile(t, c.Dir, "pn/pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
	writeFile(t, c.Dir, "y1/yarn.lock", "# yarn lockfile v1\n")
	writeFile(t, c.Dir, "y2/yarn.lock", "__metadata:\n  version: 8\n")
	writeFile(t, c.Dir, "y2/package.json", `{"packageManager":"yarn@4.5.0"}`)
	npmrc := filepath.Join(d.DataDir, "fix-home", "npmrc")
	for _, tc := range []struct {
		eco, rel, name string
		args           []string
		dir            string
	}{
		{"Packagist", "composer.lock", "composer", []string{"install", "--no-scripts", "--no-interaction", "--no-plugins"}, ""},
		{"npm", "web/package-lock.json", "npm", []string{"ci", "--ignore-scripts", "--no-audit", "--no-fund", "--userconfig", npmrc}, "web"},
		{"npm", "pn/pnpm-lock.yaml", "pnpm", []string{"install", "--frozen-lockfile", "--ignore-scripts", "--ignore-pnpmfile"}, "pn"},
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
	if err := Install(context.Background(), d, Copy{Dir: t.TempDir()}, "Packagist", "composer.lock"); !errors.Is(err, ErrNotACopy) {
		t.Errorf("install outside a copy: %v, want ErrNotACopy", err)
	}
	if len(rec.runs) != 0 {
		t.Errorf("a refused install ran %v", rec.runs)
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

func TestInstallRefusesUnsafeProjectSettings(t *testing.T) {
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	writeFile(t, c.Dir, "a/yarn.lock", "# yarn lockfile v1\n")
	writeFile(t, c.Dir, "a/.yarnrc.yml", "yarnPath: .yarn/releases/yarn.cjs\n")
	writeFile(t, c.Dir, "b/yarn.lock", "__metadata:\n  version: 8\n")
	writeFile(t, c.Dir, "b/.yarnrc.yml", "plugins:\n  - path: .yarn/plugins/x.cjs\n")
	writeFile(t, c.Dir, "c/sub/yarn.lock", "# yarn lockfile v1\n")
	writeFile(t, c.Dir, "c/.yarnrc", "yarn-path \".yarn/releases/yarn-1.js\"\n")
	writeFile(t, c.Dir, "d/package-lock.json", "{}")
	writeFile(t, c.Dir, "d/package.json", `{"packageManager":"pnpm@9.0.0"}`)
	writeFile(t, c.Dir, "e/pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
	writeFile(t, c.Dir, "e/package.json", `{"packageManager":"yarn@1.22.0+sha256.abc"}`)
	for _, rel := range []string{"a/yarn.lock", "b/yarn.lock", "c/sub/yarn.lock", "d/package-lock.json", "e/pnpm-lock.yaml"} {
		if err := Install(context.Background(), d, c, "npm", rel); !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf("%s: %v, want ErrUnsafeInstall", rel, err)
		}
	}
	if len(rec.runs) != 0 {
		t.Errorf("an unsafe install ran %v", rec.runs)
	}
	writeFile(t, c.Dir, "f/yarn.lock", "# yarn lockfile v1\n")
	writeFile(t, c.Dir, "f/.yarnrc.yml", "nodeLinker: node-modules\n")
	writeFile(t, c.Dir, "f/package.json", `{"packageManager":"yarn@4.5.0"}`)
	if err := Install(context.Background(), d, c, "npm", "f/yarn.lock"); err != nil {
		t.Errorf("a plain yarn project is refused: %v", err)
	}
}

func TestInstallRefusesSymlinkedManifestDir(t *testing.T) {
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

func TestInstallRefusesPackageManagerURL(t *testing.T) {
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	writeFile(t, c.Dir, "y/yarn.lock", "# yarn lockfile v1\n")
	writeFile(t, c.Dir, "p/pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
	for _, tc := range []struct{ rel, pm string }{
		{"y/yarn.lock", "yarn@https://evil.example/x.tgz"},
		{"p/pnpm-lock.yaml", "pnpm@file:../x"},
		{"y/yarn.lock", "yarn@git+ssh://git@evil.example/x.git"},
		{"y/yarn.lock", "yarn@latest"},
		{"y/yarn.lock", "yarn"},
		{"y/yarn.lock", "yarn@1.22.0 extra"},
		{"y/yarn.lock", "yarn@1.22.0+sha256.abc/../x"},
		{"p/pnpm-lock.yaml", "pnpm@9.0.0:x"},
	} {
		writeFile(t, c.Dir, filepath.Dir(tc.rel)+"/package.json", `{"packageManager":`+strconv.Quote(tc.pm)+`}`)
		if err := Install(context.Background(), d, c, "npm", tc.rel); !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf("packageManager %q: %v, want ErrUnsafeInstall", tc.pm, err)
		}
	}
	writeFile(t, c.Dir, "y/package.json", `{"packageManager":{"name":"yarn"}}`)
	if err := Install(context.Background(), d, c, "npm", "y/yarn.lock"); !errors.Is(err, ErrUnsafeInstall) {
		t.Errorf("packageManager object: %v, want ErrUnsafeInstall", err)
	}
	if len(rec.runs) != 0 {
		t.Errorf("an unsafe install ran %d commands", len(rec.runs))
	}
	// The nearest package.json is clean, a parent one is hostile.
	writeFile(t, c.Dir, "top/package.json", `{"packageManager":"yarn@https://evil.example/x.tgz"}`)
	writeFile(t, c.Dir, "top/app/package.json", `{"name":"acme-lib"}`)
	writeFile(t, c.Dir, "top/app/yarn.lock", "# yarn lockfile v1\n")
	if err := Install(context.Background(), d, c, "npm", "top/app/yarn.lock"); !errors.Is(err, ErrUnsafeInstall) {
		t.Errorf("hostile packageManager in a parent folder: %v, want ErrUnsafeInstall", err)
	}
}

func TestInstallAcceptsPinnedPackageManager(t *testing.T) {
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	writeFile(t, c.Dir, "y/yarn.lock", "# yarn lockfile v1\n")
	writeFile(t, c.Dir, "p/pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
	writeFile(t, c.Dir, "n/package-lock.json", "{}")
	for _, tc := range []struct{ rel, pm string }{
		{"y/yarn.lock", "yarn@1.22.22"},
		{"y/yarn.lock", "yarn@4.5.0-rc.1+sha512.0123abcdef"},
		{"p/pnpm-lock.yaml", "pnpm@9.12.3+sha256.deadbeef"},
		{"n/package-lock.json", "npm@10.8.2"},
	} {
		writeFile(t, c.Dir, filepath.Dir(tc.rel)+"/package.json", `{"packageManager":`+strconv.Quote(tc.pm)+`}`)
		rec.runs = nil
		if err := Install(context.Background(), d, c, "npm", tc.rel); err != nil {
			t.Errorf("packageManager %q refused: %v", tc.pm, err)
			continue
		}
		if len(rec.runs) != 1 || !slices.Contains(rec.runs[0].env, "COREPACK_ENABLE_NETWORK=0") {
			t.Errorf("packageManager %q: corepack may download", tc.pm)
		}
	}
	writeFile(t, c.Dir, "p/package.json", `{"packageManager":"yarn@1.22.22"}`)
	if err := Install(context.Background(), d, c, "npm", "p/pnpm-lock.yaml"); !errors.Is(err, ErrUnsafeInstall) {
		t.Errorf("another manager than the lockfile's: %v, want ErrUnsafeInstall", err)
	}
}

func TestInstallRefusesExecutingNpmSettings(t *testing.T) {
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	cases := map[string][2]string{
		"a": {".npmrc", "registry=https://registry.example\nscript-shell=/tmp/x.sh\n"},
		"b": {".npmrc", "  node-options = --require ./evil.js\n"},
		"c": {".npmrc", "git=./evil\n"},
		"d": {".npmrc", "userconfig=../x\n"},
		"e": {".npmrc", "globalconfig=../x\n"},
		"f": {".npmrc", "prefix=../x\n"},
		"g": {".npmrc", "cache=../x\n"},
		"h": {".npmrc", "shell=./evil\n"},
		"i": {"pnpm-workspace.yaml", "scriptShell: ./evil.sh\n"},
		"j": {".pnpmrc", "global-pnpmfile=./evil.cjs\n"},
	}
	for dir, f := range cases {
		writeFile(t, c.Dir, dir+"/package-lock.json", "{}")
		writeFile(t, c.Dir, dir+"/"+f[0], f[1])
		if err := Install(context.Background(), d, c, "npm", dir+"/package-lock.json"); !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf("%s with %q: %v, want ErrUnsafeInstall", f[0], f[1], err)
		}
	}
	// A setting in a parent folder of the lockfile counts too.
	writeFile(t, c.Dir, "up/.npmrc", "script-shell=./evil.sh\n")
	writeFile(t, c.Dir, "up/web/package-lock.json", "{}")
	if err := Install(context.Background(), d, c, "npm", "up/web/package-lock.json"); !errors.Is(err, ErrUnsafeInstall) {
		t.Errorf(".npmrc in a parent folder: %v, want ErrUnsafeInstall", err)
	}
	if len(rec.runs) != 0 {
		t.Errorf("an unsafe install ran %d commands", len(rec.runs))
	}
	// Registry and scoped auth settings are allowed.
	writeFile(t, c.Dir, "ok/package-lock.json", "{}")
	writeFile(t, c.Dir, "ok/.npmrc", "# comment\nregistry=https://registry.example/\n@acme:registry=https://npm.example/\n//npm.example/:_authToken=${NPM_TOKEN}\n")
	if err := Install(context.Background(), d, c, "npm", "ok/package-lock.json"); err != nil {
		t.Errorf("registry settings refused: %v", err)
	}
}

func TestSafeSegmentNormalizesLikeNTFS(t *testing.T) {
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
