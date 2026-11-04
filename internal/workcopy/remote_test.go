package workcopy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/project"
)

const (
	demoBranch = "michel/fix-01jdemo00"
	demoSSH    = "ssh://git@example.test/demo/app.git"
	demoHTTPS  = "https://example.test/demo/app.git"
	demoCanary = "canari-git-7391"
)

// unsetEnv removes a variable for the test, restoring it afterwards.
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
}

// isolatePerson gives the test a person's home of its own, empty, and removes
// what the machine running the tests may have set. It returns that home.
func isolatePerson(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
	for _, k := range []string{"GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		unsetEnv(t, k)
	}
	return home
}

type remoteFixture struct {
	fixture
	home  string
	bare  string // the remote, as an address git takes
	sha   string // the fix commit, on demoBranch
	other string // a commit on another local branch
	main  string // the principal branch, on both sides
}

// newRemoteFixture is the project demo with a fix branch, another branch and a
// tag, and a bare repository holding only its main branch, reachable through
// the test seam.
func newRemoteFixture(t *testing.T) remoteFixture {
	t.Helper()
	home := isolatePerson(t)
	f := newFixture(t)
	f.deps.AllowLocalRemote = true
	root := f.proj.Path
	main := gitT(t, f.env, root, "rev-parse", "HEAD")
	gitT(t, f.env, root, "tag", "v1")
	gitT(t, f.env, root, "checkout", "-q", "-b", "other")
	writeFile(t, root, "other.txt", "other\n")
	gitT(t, f.env, root, "add", "other.txt")
	gitT(t, f.env, root, "commit", "-q", "-m", "other")
	other := gitT(t, f.env, root, "rev-parse", "HEAD")
	gitT(t, f.env, root, "checkout", "-q", "main")
	gitT(t, f.env, root, "checkout", "-q", "-b", demoBranch)
	writeFile(t, root, "fix.txt", "fix\n")
	gitT(t, f.env, root, "add", "fix.txt")
	gitT(t, f.env, root, "commit", "-q", "-m", "fix")
	sha := gitT(t, f.env, root, "rev-parse", "HEAD")
	gitT(t, f.env, root, "checkout", "-q", "main")
	bare := filepath.ToSlash(filepath.Join(t.TempDir(), "remote.git"))
	gitT(t, f.env, filepath.Dir(bare), "init", "-q", "--bare", "-b", "main", bare)
	gitT(t, f.env, root, "push", "-q", bare, "main")
	return remoteFixture{fixture: f, home: home, bare: bare, sha: sha, other: other, main: main}
}

func (f remoteFixture) push(t *testing.T) (PushResult, error) {
	t.Helper()
	return Push(context.Background(), f.deps, f.proj, f.bare, "", demoBranch, f.sha)
}

func (f remoteFixture) refs(t *testing.T) string {
	t.Helper()
	return gitT(t, f.env, f.bare, "for-each-ref", "--format=%(refname) %(objectname)")
}

func (f remoteFixture) fixNetEmpty(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(f.deps.DataDir, "fix-net"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the temporary repository stayed: %v", entries)
	}
}

func wantClass(t *testing.T, err error, class string) {
	t.Helper()
	var gf *GitFailure
	if !errors.As(err, &gf) {
		t.Fatalf("error %v is not a GitFailure", err)
	}
	if gf.Class != class {
		t.Fatalf("class = %q, want %q", gf.Class, class)
	}
}

// gitCall is one subprocess the code under test asked for.
type gitCall struct {
	args, env []string
	dir       string
}

// gitRecorder runs git for real, except for the subcommands answered by fake.
type gitRecorder struct {
	mu    sync.Mutex
	calls []gitCall
	fake  func(ctx context.Context, sub string, args []string) (stdout, stderr []byte, err error, handled bool)
}

func (r *gitRecorder) exec(ctx context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
	r.mu.Lock()
	r.calls = append(r.calls, gitCall{args: slices.Clone(args), env: slices.Clone(env), dir: dir})
	r.mu.Unlock()
	if r.fake != nil {
		if o, e, err, ok := r.fake(ctx, gitSubcommand(args), args); ok {
			return o, e, err
		}
	}
	return defaultExec(ctx, name, args, env, dir)
}

func (r *gitRecorder) find(sub string) []gitCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []gitCall
	for _, c := range r.calls {
		if gitSubcommand(c.args) == sub {
			out = append(out, c)
		}
	}
	return out
}

// fakePush answers every push with the output a real one would give.
func fakePush(stdout string, err error) func(context.Context, string, []string) ([]byte, []byte, error, bool) {
	return func(_ context.Context, sub string, _ []string) ([]byte, []byte, error, bool) {
		if sub != "push" {
			return nil, nil, nil, false
		}
		return []byte(stdout), nil, err, true
	}
}

func newBranchLine() string {
	return "*\trefs/heads/" + demoBranch + ":refs/heads/" + demoBranch + "\t[new branch]\n"
}

func envLookup(env []string, key string) (string, bool) {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v, true
		}
	}
	return "", false
}

// witness writes a script that leaves a mark when something runs it, and
// returns its path and the mark's path.
func witness(t *testing.T) (script, mark string) {
	t.Helper()
	dir := t.TempDir()
	script = filepath.ToSlash(filepath.Join(dir, "witness.sh"))
	mark = filepath.Join(dir, "ran")
	body := "#!/bin/sh\necho ran >> '" + filepath.ToSlash(mark) + "'\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, mark
}

func noMark(t *testing.T, mark, what string) {
	t.Helper()
	if _, err := os.Stat(mark); err == nil {
		t.Errorf("%s ran", what)
	}
}

// --- Reading ---

func TestReadRemotesRunsNoNetworkCommand(t *testing.T) {
	f := newRemoteFixture(t)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", demoHTTPS)
	rec := &gitRecorder{}
	f.deps.Exec = rec.exec
	name, raw, several, err := ReadRemotes(context.Background(), f.deps, f.proj)
	if err != nil || name != "origin" || raw != demoHTTPS || several {
		t.Fatalf("ReadRemotes = %q %q %v %v", name, raw, several, err)
	}
	if len(rec.calls) != 1 || gitSubcommand(rec.calls[0].args) != "config" {
		t.Fatalf("calls = %v", rec.calls)
	}
	tail := rec.calls[0].args[len(rec.calls[0].args)-4:]
	if want := []string{"--local", "--null", "--get-regexp", `^remote\..*\.url$`}; !slices.Equal(tail, want) {
		t.Errorf("argv ends with %v, want %v", tail, want)
	}
}

func TestReadRemotesOriginThenOnlyThenSeveral(t *testing.T) {
	secret := "https://u:" + demoCanary + "@example.test/a"
	cases := []struct {
		name     string
		urls     [][2]string
		wantName string
		wantRaw  string
		several  bool
	}{
		{name: "none"},
		{name: "origin among others", urls: [][2]string{{"backup", "https://example.test/b"}, {"origin", demoHTTPS}}, wantName: "origin", wantRaw: demoHTTPS},
		{name: "the only one", urls: [][2]string{{"upstream.a_b-1", demoSSH}}, wantName: "upstream.a_b-1", wantRaw: demoSSH},
		{name: "two without origin", urls: [][2]string{{"a", demoHTTPS}, {"b", demoSSH}}, several: true},
		{name: "origin with two addresses", urls: [][2]string{{"origin", demoHTTPS}, {"origin", demoSSH}}, several: true},
		{name: "the only one with two addresses", urls: [][2]string{{"a", demoHTTPS}, {"a", demoSSH}}, several: true},
		{name: "a name Michel refuses", urls: [][2]string{{"-bad", demoHTTPS}}, several: true},
		{name: "a name Michel refuses, beside origin", urls: [][2]string{{"-bad", demoSSH}, {"origin", demoHTTPS}}, wantName: "origin", wantRaw: demoHTTPS},
		{name: "a secret stays raw here", urls: [][2]string{{"origin", secret}}, wantName: "origin", wantRaw: secret},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRemoteFixture(t)
			for _, u := range c.urls {
				gitT(t, f.env, f.proj.Path, "config", "--add", "remote."+u[0]+".url", u[1])
			}
			name, raw, several, err := ReadRemotes(context.Background(), f.deps, f.proj)
			if err != nil {
				t.Fatal(err)
			}
			if name != c.wantName || raw != c.wantRaw || several != c.several {
				t.Errorf("got %q %q %v, want %q %q %v", name, raw, several, c.wantName, c.wantRaw, c.several)
			}
		})
	}
}

func TestInsteadOfIsNotApplied(t *testing.T) {
	f := newRemoteFixture(t)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", demoHTTPS)
	gitT(t, f.env, f.proj.Path, "config", "url.https://evil.example.test/.insteadOf", "https://example.test/")
	gitT(t, f.env, f.proj.Path, "config", "remote.origin.pushurl", "https://pushed.example.test/a")
	_, raw, _, err := ReadRemotes(context.Background(), f.deps, f.proj)
	if err != nil || raw != demoHTTPS {
		t.Fatalf("raw = %q, err %v", raw, err)
	}
}

func TestRepoStateNoneEmptyOk(t *testing.T) {
	isolatePerson(t)
	f := newFixture(t)
	ctx := context.Background()
	if got, err := RepoState(ctx, f.deps, f.proj); err != nil || got != "ok" {
		t.Errorf("repository with a commit = %q, %v", got, err)
	}
	plain := project.Project{ID: f.proj.ID, Name: "demo", Path: t.TempDir()}
	if got, err := RepoState(ctx, f.deps, plain); err != nil || got != "none" {
		t.Errorf("plain folder = %q, %v", got, err)
	}
	empty := t.TempDir()
	gitT(t, f.env, empty, "init", "-q", "-b", "main")
	plain.Path = empty
	if got, err := RepoState(ctx, f.deps, plain); err != nil || got != "empty" {
		t.Errorf("no commit = %q, %v", got, err)
	}
}

func TestRepoSubfolderIsNone(t *testing.T) {
	isolatePerson(t)
	f := newFixture(t)
	sub := f.proj
	sub.Path = filepath.Join(f.proj.Path, "src")
	if got, err := RepoState(context.Background(), f.deps, sub); err != nil || got != "none" {
		t.Errorf("subfolder = %q, %v", got, err)
	}
	if name, raw, several, err := ReadRemotes(context.Background(), f.deps, sub); err == nil || name != "" || raw != "" || several {
		t.Errorf("ReadRemotes on a subfolder = %q %q %v %v", name, raw, several, err)
	}
}

// --- Sending ---

func TestPushSendsOnlyTheBranch(t *testing.T) {
	f := newRemoteFixture(t)
	before := treeDigest(t, f.proj.Path)
	got, err := f.push(t)
	if err != nil || got.Outcome != "pushed" {
		t.Fatalf("Push = %+v, %v", got, err)
	}
	want := "refs/heads/main " + f.main + "\nrefs/heads/" + demoBranch + " " + f.sha
	if refs := f.refs(t); refs != want {
		t.Errorf("remote refs:\n%s\nwant:\n%s", refs, want)
	}
	cmd := exec.Command("git", "-C", f.bare, "cat-file", "-e", f.other)
	cmd.Env = f.env
	if cmd.Run() == nil {
		t.Error("the content of another branch reached the remote")
	}
	if treeDigest(t, f.proj.Path) != before {
		t.Error("Push wrote into the project")
	}
	f.fixNetEmpty(t)
}

func TestPushArgvIsClosed(t *testing.T) {
	f := newRemoteFixture(t)
	ref := "refs/heads/" + demoBranch + ":refs/heads/" + demoBranch
	rec := &gitRecorder{fake: fakePush("To "+demoSSH+"\n*\t"+ref+"\t[new branch]\nDone\n", nil)}
	f.deps.Exec = rec.exec
	got, err := Push(context.Background(), f.deps, f.proj, demoSSH, "", demoBranch, f.sha)
	if err != nil || got.Outcome != "pushed" {
		t.Fatalf("Push = %+v, %v", got, err)
	}
	pushes := rec.find("push")
	if len(pushes) != 1 {
		t.Fatalf("pushes = %d", len(pushes))
	}
	args := pushes[0].args
	if len(args) < 3 || args[1] != "-C" {
		t.Fatalf("argv %v", args)
	}
	tmp := args[2]
	if filepath.Dir(tmp) != filepath.Join(f.deps.DataDir, "fix-net") || !regexp.MustCompile(`^[0-9A-Z]{26}\.git$`).MatchString(filepath.Base(tmp)) {
		t.Errorf("the push does not leave from a temporary repository: %s", tmp)
	}
	want := []string{"--no-pager", "-C", tmp,
		"-c", "core.hooksPath=" + filepath.Join(f.deps.DataDir, "fix-hooks"),
		"-c", "core.fsmonitor=false", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-c", "core.longpaths=true",
		"-c", "core.askPass=", "-c", "safe.bareRepository=all",
		"push", "--porcelain", "--no-follow-tags", "--no-recurse-submodules", "--no-signed", "--no-verify",
		"--", demoSSH, ref}
	if !slices.Equal(args, want) {
		t.Errorf("argv\n got %v\nwant %v", args, want)
	}
	if pushes[0].dir != f.deps.DataDir {
		t.Errorf("push runs from %s", pushes[0].dir)
	}
	clones := rec.find("clone")
	if len(clones) != 1 {
		t.Fatalf("clones = %d", len(clones))
	}
	wantClone := []string{"clone", "--bare", "--local", "--no-hardlinks", "--quiet", "--no-tags", "--single-branch", "--branch", demoBranch, "--", f.proj.Path, tmp}
	if a := clones[0].args; !slices.Equal(a[len(a)-len(wantClone):], wantClone) {
		t.Errorf("clone argv %v", a)
	}
}

func TestPushReadsOnlyItsPorcelainLine(t *testing.T) {
	ref := "refs/heads/" + demoBranch + ":refs/heads/" + demoBranch
	line := func(flag string) string { return "To " + demoSSH + "\n" + flag + "\t" + ref + "\tsummary\nDone\n" }
	cases := []struct {
		name, stdout string
		err          error
		outcome      string
		class        string
	}{
		{name: "new", stdout: line("*"), outcome: "pushed"},
		{name: "fast-forward", stdout: line(" "), outcome: "pushed"},
		{name: "up to date", stdout: line("="), outcome: "already"},
		{name: "refused, exit 1", stdout: line("!"), err: errors.New("exit status 1"), class: "rejected"},
		{name: "forced is not a success", stdout: line("+"), class: "failed"},
		{name: "deleted is not a success", stdout: line("-"), class: "failed"},
		{name: "no line", stdout: "To " + demoSSH + "\nDone\n", class: "failed"},
		{name: "the line of another ref", stdout: "*\trefs/heads/main:refs/heads/main\tsummary\n", class: "failed"},
		{name: "the To line holds a false line", stdout: "To *\t" + ref + "\n", class: "failed"},
		{name: "success line, failed process", stdout: line("*"), err: errors.New("exit status 128"), class: "failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRemoteFixture(t)
			rec := &gitRecorder{fake: fakePush(c.stdout, c.err)}
			f.deps.Exec = rec.exec
			got, err := Push(context.Background(), f.deps, f.proj, demoSSH, "", demoBranch, f.sha)
			if c.class != "" {
				wantClass(t, err, c.class)
				return
			}
			if err != nil || got.Outcome != c.outcome {
				t.Errorf("Push = %+v, %v", got, err)
			}
		})
	}
}

func TestPushTwiceIsAlready(t *testing.T) {
	f := newRemoteFixture(t)
	if got, err := f.push(t); err != nil || got.Outcome != "pushed" {
		t.Fatalf("first Push = %+v, %v", got, err)
	}
	refs := f.refs(t)
	got, err := f.push(t)
	if err != nil || got.Outcome != "already" {
		t.Fatalf("second Push = %+v, %v", got, err)
	}
	if f.refs(t) != refs {
		t.Error("the second push changed the remote")
	}
}

func TestPushNeverForces(t *testing.T) {
	f := newRemoteFixture(t)
	gitT(t, f.env, f.proj.Path, "push", "-q", f.bare, f.other+":refs/heads/"+demoBranch)
	refs := f.refs(t)
	_, err := f.push(t)
	wantClass(t, err, "rejected")
	if f.refs(t) != refs {
		t.Error("the remote changed")
	}
	f.fixNetEmpty(t)
}

func TestPushRefusesAMovedBranch(t *testing.T) {
	f := newRemoteFixture(t)
	refs := f.refs(t)
	rec := &gitRecorder{}
	f.deps.Exec = rec.exec
	for name, c := range map[string][2]string{
		"another commit": {demoBranch, f.main},
		"no such branch": {"michel/fix-01jmissing", f.sha},
		"not a fix":      {"main", f.main},
		"not a commit":   {demoBranch, "HEAD"},
		"an option":      {"--all", f.sha},
	} {
		_, err := Push(context.Background(), f.deps, f.proj, f.bare, "", c[0], c[1])
		wantClass(t, err, "branch_moved")
		if len(rec.find("push")) != 0 {
			t.Errorf("%s: pushed", name)
		}
	}
	if f.refs(t) != refs {
		t.Error("the remote changed")
	}
}

// The branch moves between the check and the clone: what is in the temporary
// repository is not what was approved.
func TestPushChecksTheBranchAgainInTheTemporaryRepository(t *testing.T) {
	f := newRemoteFixture(t)
	rec := &gitRecorder{}
	rec.fake = func(_ context.Context, sub string, _ []string) ([]byte, []byte, error, bool) {
		if sub == "clone" {
			gitT(t, f.env, f.proj.Path, "update-ref", "refs/heads/"+demoBranch, f.other)
		}
		return nil, nil, nil, false
	}
	f.deps.Exec = rec.exec
	_, err := f.push(t)
	wantClass(t, err, "branch_moved")
	if len(rec.find("push")) != 0 {
		t.Error("pushed")
	}
	f.fixNetEmpty(t)
}

func TestLocalRemoteNeedsTheSeam(t *testing.T) {
	f := newRemoteFixture(t)
	refs := f.refs(t)
	f.deps.AllowLocalRemote = false
	if _, err := f.push(t); err == nil {
		t.Fatal("a local remote was reached")
	}
	if f.refs(t) != refs {
		t.Error("the remote changed")
	}
}

func TestPushRunsNoProjectConfig(t *testing.T) {
	f := newRemoteFixture(t)
	script, mark := witness(t)
	decoy := filepath.ToSlash(filepath.Join(t.TempDir(), "decoy.git"))
	gitT(t, f.env, filepath.Dir(decoy), "init", "-q", "--bare", "-b", "main", decoy)
	run := "sh '" + script + "'"
	for _, kv := range [][2]string{
		{"core.sshCommand", run},
		{"credential.helper", "!" + run},
		{"url." + decoy + ".insteadOf", f.bare},
		{"remote." + f.bare + ".receivepack", run},
		{"remote." + f.bare + ".pushurl", decoy},
	} {
		gitT(t, f.env, f.proj.Path, "config", "--local", kv[0], kv[1])
	}
	got, err := f.push(t)
	if err != nil || got.Outcome != "pushed" {
		t.Fatalf("Push = %+v, %v", got, err)
	}
	noMark(t, mark, "a program named in the project's config")
	if !strings.Contains(f.refs(t), demoBranch) {
		t.Error("the branch did not reach the right place")
	}
	if refs := gitT(t, f.env, decoy, "for-each-ref"); refs != "" {
		t.Errorf("the push went elsewhere: %s", refs)
	}
}

// Over SSH the program is the person's, never the project's. Nothing leaves
// the machine: the person's program is a script that stops there.
func TestPushOverSSHUsesThePersonsCommandNotTheProjects(t *testing.T) {
	f := newRemoteFixture(t)
	projectScript, projectMark := witness(t)
	personScript, personMark := witness(t)
	writeFile(t, f.home, ".gitconfig", "[core]\n\tsshCommand = sh '"+personScript+"'\n")
	gitT(t, f.env, f.proj.Path, "config", "--local", "core.sshCommand", "sh '"+projectScript+"'")
	if _, err := Push(context.Background(), f.deps, f.proj, demoSSH, "", demoBranch, f.sha); err == nil {
		t.Fatal("the script stops the connection, Push must fail")
	}
	noMark(t, projectMark, "the project's core.sshCommand")
	if _, err := os.Stat(personMark); err != nil {
		t.Error("the person's core.sshCommand did not run")
	}
}

func TestPushRunsNoHook(t *testing.T) {
	f := newRemoteFixture(t)
	script, mark := witness(t)
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	global := filepath.Join(t.TempDir(), "global-hooks")
	dirs := []string{filepath.Join(f.proj.Path, ".git", "hooks"), filepath.Join(f.deps.DataDir, "fix-hooks"), global}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"pre-push", "post-checkout"} {
			if err := os.WriteFile(filepath.Join(dir, name), body, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeFile(t, f.home, ".gitconfig", "[core]\n\thooksPath = "+filepath.ToSlash(global)+"\n")

	// The hook is a real one: a plain push from the project does run it.
	control := exec.Command("git", "-C", f.proj.Path, "push", "-q", f.bare, "main")
	control.Env = f.env
	_ = control.Run()
	if _, err := os.Stat(mark); err != nil {
		t.Fatal("control: the planted hook does not run on a plain push")
	}
	if err := os.Remove(mark); err != nil {
		t.Fatal(err)
	}

	got, err := f.push(t)
	if err != nil || got.Outcome != "pushed" {
		t.Fatalf("Push = %+v, %v", got, err)
	}
	noMark(t, mark, "a hook")
}

func TestPushEnvIsAllowlistedAndCannotPrompt(t *testing.T) {
	sshCommand := func(t *testing.T, f remoteFixture) (string, bool, *gitRecorder) {
		t.Helper()
		rec := &gitRecorder{fake: fakePush(newBranchLine(), nil)}
		f.deps.Exec = rec.exec
		if _, err := Push(context.Background(), f.deps, f.proj, demoSSH, "", demoBranch, f.sha); err != nil {
			t.Fatal(err)
		}
		v, ok := envLookup(rec.find("push")[0].env, "GIT_SSH_COMMAND")
		return v, ok, rec
	}
	t.Run("nothing set by the person", func(t *testing.T) {
		f := newRemoteFixture(t)
		t.Setenv("MICHEL_TEST_CANARY", demoCanary)
		t.Setenv("GIT_ASKPASS", "/bin/false")
		t.Setenv("SSH_ASKPASS", "/bin/false")
		t.Setenv("HTTPS_PROXY", "http://other.example.test:1")
		t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "x"))
		v, ok, rec := sshCommand(t, f)
		if !ok || v != "ssh -o BatchMode=yes" {
			t.Errorf("GIT_SSH_COMMAND = %q %v", v, ok)
		}
		env := rec.find("push")[0].env
		for k, want := range map[string]string{
			"GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never", "SSH_ASKPASS_REQUIRE": "never",
			"GIT_NO_REPLACE_OBJECTS": "1", "LC_ALL": "C", "LANGUAGE": "C", "GIT_ALLOW_PROTOCOL": "https:ssh:file",
		} {
			if got, _ := envLookup(env, k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
		for _, k := range []string{"MICHEL_TEST_CANARY", "GIT_ASKPASS", "SSH_ASKPASS", "HTTPS_PROXY", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_COUNT"} {
			if _, ok := envLookup(env, k); ok {
				t.Errorf("%s reached git", k)
			}
		}
		if home, _ := envLookup(env, "HOME"); home != f.home {
			t.Errorf("HOME = %q, want the person's", home)
		}
		read := slices.DeleteFunc(rec.find("config"), func(c gitCall) bool { return !slices.Contains(c.args, "--global") })
		if len(read) != 1 || !slices.Equal(read[0].args, []string{"config", "--global", "--includes", "--get", "core.sshCommand"}) || read[0].dir != f.deps.DataDir {
			t.Errorf("reading the person's setting: %+v", read)
		}
	})
	t.Run("the person's variable is kept", func(t *testing.T) {
		f := newRemoteFixture(t)
		t.Setenv("GIT_SSH_COMMAND", "ssh -i demo")
		if v, _, _ := sshCommand(t, f); v != "ssh -i demo" {
			t.Errorf("GIT_SSH_COMMAND = %q", v)
		}
	})
	t.Run("GIT_SSH is not overridden", func(t *testing.T) {
		f := newRemoteFixture(t)
		t.Setenv("GIT_SSH", "plink")
		v, ok, rec := sshCommand(t, f)
		if ok {
			t.Errorf("GIT_SSH_COMMAND = %q", v)
		}
		if got, _ := envLookup(rec.find("push")[0].env, "GIT_SSH"); got != "plink" {
			t.Errorf("GIT_SSH = %q", got)
		}
	})
	t.Run("the person's global setting is kept", func(t *testing.T) {
		f := newRemoteFixture(t)
		writeFile(t, f.home, ".gitconfig", "[core]\n\tsshCommand = ssh -i demo\n")
		if v, ok, _ := sshCommand(t, f); ok {
			t.Errorf("GIT_SSH_COMMAND = %q would override the person's setting", v)
		}
	})
	t.Run("the seam alone opens the file protocol", func(t *testing.T) {
		f := newRemoteFixture(t)
		f.deps.AllowLocalRemote = false
		_, _, rec := sshCommand(t, f)
		if got, _ := envLookup(rec.find("push")[0].env, "GIT_ALLOW_PROTOCOL"); got != "https:ssh" {
			t.Errorf("GIT_ALLOW_PROTOCOL = %q", got)
		}
	})
}

func TestPushTimesOut(t *testing.T) {
	f := newRemoteFixture(t)
	reached := false
	rec := &gitRecorder{fake: func(ctx context.Context, sub string, _ []string) ([]byte, []byte, error, bool) {
		if sub != "push" {
			return nil, nil, nil, false
		}
		reached = true
		<-ctx.Done()
		return nil, []byte("Permission denied"), ctx.Err(), true
	}}
	f.deps.Exec = rec.exec
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := Push(ctx, f.deps, f.proj, f.bare, "", demoBranch, f.sha)
	wantClass(t, err, "timeout")
	if !reached {
		t.Error("the clone used the whole delay: the test did not reach the push")
	}
	f.fixNetEmpty(t)
}

func TestPushHasItsDelay(t *testing.T) {
	f := newRemoteFixture(t)
	var left time.Duration
	rec := &gitRecorder{fake: func(ctx context.Context, sub string, _ []string) ([]byte, []byte, error, bool) {
		if sub != "push" {
			return nil, nil, nil, false
		}
		if dl, ok := ctx.Deadline(); ok {
			left = time.Until(dl)
		}
		return nil, nil, errors.New("exit status 128"), true
	}}
	f.deps.Exec = rec.exec
	_, _ = f.push(t)
	if left <= time.Minute || left > 2*time.Minute {
		t.Errorf("time left at the push: %v", left)
	}
}

func TestProxyTokenNotInArgv(t *testing.T) {
	f := newRemoteFixture(t)
	proxy := "http://michel:" + demoCanary + "@127.0.0.1:9"
	rec := &gitRecorder{fake: fakePush(newBranchLine(), nil)}
	f.deps.Exec = rec.exec
	if _, err := Push(context.Background(), f.deps, f.proj, demoHTTPS, proxy, demoBranch, f.sha); err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.calls {
		if strings.Contains(strings.Join(c.args, " "), demoCanary) {
			t.Errorf("the token is in an argv: %v", c.args)
		}
		if gitSubcommand(c.args) != "push" && strings.Contains(strings.Join(c.env, "\n"), demoCanary) {
			t.Errorf("the token reached git %s", gitSubcommand(c.args))
		}
	}
	env := rec.find("push")[0].env
	for k, want := range map[string]string{
		"HTTPS_PROXY": proxy, "https_proxy": proxy, "ALL_PROXY": proxy, "all_proxy": proxy,
		"NO_PROXY": "", "no_proxy": "",
		"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.proxy", "GIT_CONFIG_VALUE_0": proxy,
	} {
		if got, ok := envLookup(env, k); !ok || got != want {
			t.Errorf("%s = %q %v, want %q", k, got, ok, want)
		}
	}
}

func TestPushOverSSHGetsNoProxy(t *testing.T) {
	f := newRemoteFixture(t)
	rec := &gitRecorder{fake: fakePush(newBranchLine(), nil)}
	f.deps.Exec = rec.exec
	if _, err := Push(context.Background(), f.deps, f.proj, demoSSH, "http://t@127.0.0.1:9", demoBranch, f.sha); err != nil {
		t.Fatal(err)
	}
	env := rec.find("push")[0].env
	for _, k := range []string{"HTTPS_PROXY", "ALL_PROXY", "GIT_CONFIG_COUNT"} {
		if _, ok := envLookup(env, k); ok {
			t.Errorf("%s set for an SSH address", k)
		}
	}
}

// Without the proxy, an https push would go straight out, past the gateway.
func TestPushHTTPSWithoutProxyIsRefused(t *testing.T) {
	f := newRemoteFixture(t)
	rec := &gitRecorder{fake: fakePush("", nil)}
	f.deps.Exec = rec.exec
	_, err := Push(context.Background(), f.deps, f.proj, demoHTTPS, "", demoBranch, f.sha)
	wantClass(t, err, "failed")
	if len(rec.find("push")) != 0 {
		t.Error("pushed without a proxy")
	}
	f.fixNetEmpty(t)
}

func TestClassifyTable(t *testing.T) {
	cases := map[string]string{
		"fatal: Authentication failed for 'https://example.test/a'":                              "auth",
		"git@example.test: Permission denied (publickey).":                                       "auth",
		"fatal: could not read Username for 'https://example.test': No such device":              "auth",
		"fatal: terminal prompts disabled":                                                       "auth",
		"no matching publickey":                                                                  "auth",
		"fatal: unable to access 'https://example.test/': The requested URL returned error: 401": "auth",
		"fatal: unable to access 'https://example.test/': The requested URL returned error: 403": "auth",
		"Host key verification failed.":                                                          "host_key",
		"remote: Repository not found.":                                                          "not_found",
		"fatal: 'x' does not appear to be a git repository":                                      "not_found",
		"remote: GH006: this branch is protected":                                                "rejected",
		"error: failed to push some refs: rejected":                                              "rejected",
		"hint: non-fast-forward":                                                                 "rejected",
		"hint: fetch first":                                                                      "rejected",
		"remote: pre-receive hook declined":                                                      "rejected",
		"ssh: Could not resolve hostname example.test":                                           "network",
		"fatal: unable to access 'https://example.test/': Could not resolve host":                "network",
		"connect to host example.test port 22: Connection timed out":                             "network",
		"connect to host example.test port 22: Connection refused":                               "network",
		"Failed to connect to example.test port 443":                                             "network",
		"fatal: unable to access 'https://example.test/': Recv failure":                          "network",
		"Could not connect to the proxy":                                                         "network",
		"":                                                                                       "failed",
		"fatal: something Michel has never seen":                                                 "failed",
	}
	for in, want := range cases {
		if got := classify([]byte(in)); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFailureHoldsNoOutput(t *testing.T) {
	f := newRemoteFixture(t)
	rec := &gitRecorder{fake: func(_ context.Context, sub string, _ []string) ([]byte, []byte, error, bool) {
		if sub != "push" {
			return nil, nil, nil, false
		}
		return []byte("To https://u:" + demoCanary + "@example.test/a\n"),
			[]byte("fatal: Authentication failed for https://u:" + demoCanary + "@example.test/a"),
			errors.New("exit status 128"), true
	}}
	f.deps.Exec = rec.exec
	_, err := Push(context.Background(), f.deps, f.proj, demoSSH, "", demoBranch, f.sha)
	wantClass(t, err, "auth")
	if s := fmt.Sprintf("%v %+v %#v", err, err, err); strings.Contains(s, demoCanary) {
		t.Errorf("the failure holds git's output: %s", s)
	}
	var gf *GitFailure
	errors.As(err, &gf)
	if gf.Error() != "git: auth" {
		t.Errorf("Error() = %q", gf.Error())
	}
}

func TestNotDefaultFailureIsSanitizedAndCut(t *testing.T) {
	gf := notDefaultFailure("a\x1b[31m"+strings.Repeat("é", 200), "main")
	if strings.ContainsRune(gf.Current, 0x1b) {
		t.Errorf("Current kept a control character: %q", gf.Current)
	}
	if n := len([]rune(gf.Current)); n > 100 {
		t.Errorf("Current has %d characters", n)
	}
	if !strings.HasPrefix(gf.Current, "a") || gf.Default != "main" || gf.Class != "not_default" {
		t.Errorf("failure = %+v", gf)
	}
	if strings.Contains(gf.Error(), "main") {
		t.Errorf("Error() says more than the class: %q", gf.Error())
	}
}

// proxyListener answers every CONNECT with a refusal and tells which targets
// it was asked for. Nothing leaves the machine.
func proxyListener(t *testing.T) (url string, asked <-chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	lines := make(chan string, 16)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(conn).ReadString('\n')
			lines <- strings.TrimSpace(line)
			_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			_ = conn.Close()
		}
	}()
	return "http://" + l.Addr().String(), lines
}

// A real git, a real https address: it asks Michel's proxy, not the person's
// http.proxy, and reaches nothing else.
func TestPushHTTPSGoesThroughTheProxy(t *testing.T) {
	f := newRemoteFixture(t)
	michel, asked := proxyListener(t)
	person, personAsked := proxyListener(t)
	writeFile(t, f.home, ".gitconfig", "[http]\n\tproxy = "+person+"\n")
	_, err := Push(context.Background(), f.deps, f.proj, demoHTTPS, michel, demoBranch, f.sha)
	wantClass(t, err, "network")
	select {
	case line := <-asked:
		if !strings.HasPrefix(line, "CONNECT example.test:443 ") {
			t.Errorf("the proxy was asked %q", line)
		}
	default:
		t.Error("git did not go through Michel's proxy")
	}
	select {
	case line := <-personAsked:
		t.Errorf("git used the global http.proxy: %q", line)
	default:
	}
	f.fixNetEmpty(t)
}
