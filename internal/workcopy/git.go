// Package workcopy is the fix copy of a project: an isolated git clone in
// Michel's data folder, where dependencies are installed without scripts,
// the project's tests run and the change is committed, then applied to the
// user's repository as a new branch fetched from the copy. Apply, Push and
// UpdateFolder are its only writes. Apply writes in the user's repository git
// objects and one refs/heads/michel/fix-<id> ref, never the working tree, the
// index or HEAD. Push writes on the remote, one branch, on a click, and nothing
// in the project. UpdateFolder, on a click, moves the current branch of the
// user's folder forward, and is the only code that writes in its working tree,
// its index or HEAD.
package workcopy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
)

// ExecFunc runs name with exactly env (never Michel's own environment) from
// dir and returns what it wrote on stdout and stderr.
type ExecFunc func(ctx context.Context, name string, args, env []string, dir string) (stdout, stderr []byte, err error)

// Deps are the collaborators of the fix copy.
type Deps struct {
	// DataDir is Michel's data folder: copies live in <DataDir>/worktrees,
	// the subprocesses' home in <DataDir>/fix-home.
	DataDir string
	// Exec runs a subprocess. Nil means defaultExec.
	Exec ExecFunc
	// ProxyAddr is Michel's egress proxy, given to every subprocess for
	// every scheme: host:port, or the http:// URL allowproxy.Listen returns
	// (with its token). Empty means an address where nothing listens, so a
	// subprocess reaches no network.
	ProxyAddr string
	// Now dates the commits of the copy. Nil means time.Now.
	Now func() time.Time
	// AllowLocalRemote lets a push reach a remote on the local disk, whose
	// hooks the local transport would run. It is the only source of ":file" in
	// GIT_ALLOW_PROTOCOL: set by tests and by the trial build, nothing at run
	// time opens it.
	AllowLocalRemote bool
	// assumeOldGit makes the runner behave as with a git older than 2.45: tests.
	assumeOldGit bool
}

func (d Deps) exec() ExecFunc {
	if d.Exec != nil {
		return d.Exec
	}
	return defaultExec
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// maxStream caps what Michel keeps of each output stream of the install and
// the tests (scan.SanitizeText applied).
const maxStream = 64 << 10

// maxGitOutput caps the stdout of a git command. A diff is refused rather
// than cut (ErrDiffTooLarge): a cut diff would show less than what is
// applied.
const maxGitOutput = 8 << 20

// capped keeps the first max bytes written to it and drops the rest.
type capped struct {
	buf bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

// DefaultExec is the runner used when Deps.Exec is nil, for the packages
// that drive other fix subprocesses (internal/agent).
var DefaultExec ExecFunc = defaultExec

// defaultExec runs name with exactly env (never Michel's own environment),
// from dir, without stdin, stdout capped at maxGitOutput and stderr at
// maxStream (the same runner as the plugins of internal/plugin).
func defaultExec(ctx context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append([]string{}, env...) // never nil: nil would pass Michel's environment
	cmd.Stdin = nil
	out, errOut := &capped{max: maxGitOutput}, &capped{max: maxStream}
	cmd.Stdout, cmd.Stderr = out, errOut
	cmd.WaitDelay = 5 * time.Second
	killTreeOnCancel(cmd)
	err := cmd.Run()
	return out.buf.Bytes(), errOut.buf.Bytes(), err
}

// home is the folder the subprocesses of the fix copy use as their home, in
// the data folder: their settings and caches stay there and none of the
// user's own (global git config, composer or npm credentials) is read.
// hooks is git's hooks folder, outside the home (a subprocess may write in
// its home), emptied before every batch of git commands.
type home struct{ dir, hooks string }

func (h home) gitconfig() string { return filepath.Join(h.dir, "gitconfig") }
func (h home) npmrc() string     { return filepath.Join(h.dir, "npmrc") }

// ensureHome creates <data>/fix-home with an empty git configuration, an
// empty npmrc and the composer and npm caches, and recreates
// <data>/fix-hooks empty: whatever was planted there never runs.
func ensureHome(d Deps) (home, error) {
	if d.DataDir == "" || !filepath.IsAbs(d.DataDir) {
		return home{}, errors.New("Michel has no data folder for the fix copy")
	}
	h := home{dir: filepath.Join(d.DataDir, "fix-home"), hooks: filepath.Join(d.DataDir, "fix-hooks")}
	fail := func(err error) (home, error) {
		return home{}, fmt.Errorf("Michel cannot prepare its folder for the fix copy: %w", noPath(err))
	}
	if err := os.RemoveAll(h.hooks); err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(h.hooks, 0o700); err != nil {
		return fail(err)
	}
	for _, sub := range []string{"", "composer", "npm"} {
		if err := os.MkdirAll(filepath.Join(h.dir, sub), 0o700); err != nil {
			return fail(err)
		}
	}
	// Michel owns these files: they stay empty, whatever wrote in them.
	for _, f := range []string{h.gitconfig(), h.npmrc()} {
		if info, err := os.Lstat(f); err != nil || !info.Mode().IsRegular() || info.Size() > 0 {
			_ = os.RemoveAll(f)
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				return fail(err)
			}
		}
	}
	return h, nil
}

// env is the whole environment of a subprocess of the fix copy: the few
// variables a program needs to start (PATH, SystemRoot, TEMP, TMP, and
// PATHEXT so that npm.cmd starts on Windows), the home and caches in the
// data folder, the egress proxy for every scheme, and git without system or
// global configuration nor prompts. No secret, token or other variable of
// Michel's reaches it.
func (h home) env(proxyAddr string, extra ...string) []string {
	var env []string
	for _, k := range []string{"PATH", "SystemRoot", "TEMP", "TMP", "PATHEXT"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:9" // discard port: nothing answers
	}
	proxyAddr = strings.TrimPrefix(proxyAddr, "http://")
	env = append(env, "HOME="+h.dir, "USERPROFILE="+h.dir,
		"COMPOSER_HOME="+filepath.Join(h.dir, "composer"), "npm_config_cache="+filepath.Join(h.dir, "npm"))
	proxy := "http://" + proxyAddr
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		env = append(env, k+"="+proxy)
	}
	env = append(env, "NO_PROXY=", "no_proxy=",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+h.gitconfig(), "GIT_TERMINAL_PROMPT=0",
		// Corepack never downloads a package manager (a pinned version must
		// already be on this machine) nor pins one in package.json.
		"COREPACK_ENABLE_DOWNLOAD_PROMPT=0", "COREPACK_ENABLE_AUTO_PIN=0", "COREPACK_ENABLE_NETWORK=0",
		// npm runs git for git dependencies: a program that does not exist,
		// so they fail instead of running git with the project's settings.
		"npm_config_git="+filepath.Join(h.dir, "no-git"),
		// npm goes through the proxy whatever the project's .npmrc
		// says (environment settings win over project files), with TLS
		// checks on.
		"npm_config_proxy="+proxy, "npm_config_https_proxy="+proxy, "npm_config_noproxy=", "npm_config_strict_ssl=true",
		"COMPOSER_NO_INTERACTION=1", "COMPOSER_CACHE_DIR="+filepath.Join(h.dir, "composer", "cache"),
		// composer installs in vendor next to the lockfile, whatever the
		// project says (environment settings win over composer.json).
		"COMPOSER_VENDOR_DIR=vendor", "COMPOSER_BIN_DIR=vendor/bin",
		// Replacement refs of a repository never change what git reads, and a
		// missing object is never fetched on its own: see execGit.
		"GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1")
	return append(env, extra...)
}

// Env returns the whole environment of a fix subprocess (see home.env),
// after creating <DataDir>/fix-home, and that folder. internal/agent starts
// Claude Code from it.
func Env(d Deps) (env []string, homeDir string, err error) {
	h, err := ensureHome(d)
	if err != nil {
		return nil, "", err
	}
	return h.env(d.ProxyAddr), h.dir, nil
}

// allowedGit is the closed list of git subcommands Michel runs.
var allowedGit = []string{"clone", "init", "archive", "add", "diff", "commit", "fetch", "merge-base", "rev-parse",
	"read-tree", "apply", "write-tree", "commit-tree", "ls-tree", "show", "config", "symbolic-ref", "check-attr", "cherry"}

// localTransport allows git's file transport, for the local clone and fetch only.
var localTransport = []string{"-c", "protocol.file.allow=always"}

// gitSubcommand is the git subcommand of a git argv built by gitArgs.
func gitSubcommand(args []string) string {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-C", "-c":
			i++
		case "--no-pager", "--no-optional-locks":
		default:
			return args[i]
		}
	}
	return ""
}

// git runs one git subcommand of the closed list on repo (git -C repo, or
// no -C when repo is ""), from cwd, with the fix environment plus env, extra (-c
// pairs) and what runGit enforces. System and global configuration are not read
// at all (GIT_CONFIG_NOSYSTEM, GIT_CONFIG_GLOBAL). Only a command asking for
// localTransport has a transport, and only that one.
func (h home) git(ctx context.Context, d Deps, cwd, repo string, extra, env []string, sub string, args ...string) ([]byte, []byte, error) {
	if !slices.Contains(allowedGit, sub) {
		return nil, nil, fmt.Errorf("git %s is not a command Michel runs", sub)
	}
	if slices.Contains(extra, localTransport[1]) {
		env = append(slices.Clone(env), "GIT_ALLOW_PROTOCOL=file")
	}
	return h.runGit(ctx, d, gitCommand{profile: gitIsolated, repo: repo, dir: cwd, env: h.env(d.ProxyAddr, env...), config: extra, sub: sub, args: args})
}

// workCommands are the only commands that run with the person's configuration on
// their folder, and status writes nothing there (--no-optional-locks).
var workCommands = []string{"status", "merge"}

// workGit runs git on the folder of project p with the person's configuration,
// not the environment of git: that one ignores core.autocrlf and would rewrite
// the line endings on Windows (R24). It reaches no network: the proxy is an
// address where nothing listens, and a partial clone does not fetch what it lacks
// (a project's core.sshCommand would run). The -c options turn off what the
// folder's configuration could start. Git cannot turn a filter off that way: see
// checkFolderConfig. Its output never leaves the caller.
func (h home) workGit(ctx context.Context, d Deps, p project.Project, sub string, args ...string) ([]byte, []byte, error) {
	if !slices.Contains(workCommands, sub) {
		return nil, nil, fmt.Errorf("git %s is not a command Michel runs on a folder", sub)
	}
	env := userEnv(ctx, d)
	const nowhere = "http://127.0.0.1:9" // discard port: nothing answers
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		env = append(env, k+"="+nowhere)
	}
	env = append(env, "NO_PROXY=", "no_proxy=")
	var options []string
	if sub == "status" {
		options = []string{"--no-optional-locks"}
	}
	return h.runGit(ctx, d, gitCommand{profile: gitFolder, repo: p.Path, dir: d.DataDir, env: env, options: options, sub: sub, args: args})
}

// gitErr is the error of a failed git command, with the first line of what
// it wrote on stderr (sanitized, without the absolute paths it may hold).
func gitErr(sub string, err error, stderr []byte) error {
	line, _, _ := strings.Cut(strings.TrimSpace(string(stderr)), "\n")
	line = absPath.ReplaceAllString(scan.SanitizeText(strings.ToValidUTF8(line, "")), "<path>")
	if len(line) > 300 {
		line = line[:300]
	}
	if line == "" {
		return fmt.Errorf("git %s failed: %w", sub, noPath(err))
	}
	return fmt.Errorf("git %s failed: %w (%s)", sub, noPath(err), line)
}

// absPath matches the absolute paths git prints (Windows or POSIX).
var absPath = regexp.MustCompile(`(?:[A-Za-z]:[\\/]|/)[^\s'"]*`)

// exitCode is the exit code of a finished command, -1 when it did not run
// or was not a process exit.
func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// noPath drops the file path of a file system error.
func noPath(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err
	}
	return err
}

// shaShape is a full commit id (SHA-1 or SHA-256).
var shaShape = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// revParseCommit returns the commit id rev names in repo, "" when it names
// no commit there.
func (h home) revParseCommit(ctx context.Context, d Deps, repo, rev string) (string, error) {
	out, stderr, err := h.git(ctx, d, d.DataDir, repo, nil, nil, "rev-parse", "--verify", "--quiet", "--end-of-options", rev+"^{commit}")
	if err != nil {
		if exitCode(err) == 1 {
			return "", nil
		}
		return "", gitErr("rev-parse", err, stderr)
	}
	sha := strings.TrimSpace(string(out))
	if !shaShape.MatchString(sha) {
		return "", fmt.Errorf("git rev-parse returned an unexpected commit id")
	}
	return sha, nil
}
