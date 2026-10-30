// Package workcopy is the fix copy of a project: an isolated git clone in
// Michel's data folder, where dependencies are installed without scripts,
// the project's tests run and the change is committed, then applied to the
// user's repository as a new branch fetched from the copy. It is the only
// code allowed to write into the user's repository, and only in Apply:
// git objects and one refs/heads/michel/fix-<id> ref, never the working
// tree, the index or HEAD.
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
	// ProxyAddr is the host:port of Michel's egress proxy, given to every
	// subprocess for every scheme. Empty means an address where nothing
	// listens, so a subprocess reaches no network.
	ProxyAddr string
	// Now dates the commits of the copy. Nil means time.Now.
	Now func() time.Time
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
	env = append(env, "HOME="+h.dir, "USERPROFILE="+h.dir,
		"COMPOSER_HOME="+filepath.Join(h.dir, "composer"), "npm_config_cache="+filepath.Join(h.dir, "npm"))
	proxy := "http://" + proxyAddr
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		env = append(env, k+"="+proxy)
	}
	env = append(env, "NO_PROXY=", "no_proxy=",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+h.gitconfig(), "GIT_TERMINAL_PROMPT=0",
		// Corepack never downloads a package manager nor pins one in package.json.
		"COREPACK_ENABLE_DOWNLOAD_PROMPT=0", "COREPACK_ENABLE_AUTO_PIN=0")
	return append(env, extra...)
}

// allowedGit is the closed list of git subcommands Michel runs.
var allowedGit = []string{"clone", "init", "archive", "add", "diff", "commit", "fetch", "merge-base", "rev-parse",
	"read-tree", "apply", "write-tree", "commit-tree"}

// safeConfig neutralizes, for every git command, the settings of a
// repository's own .git/config (the user's project is not trusted) that make
// git run a program or write on its own: hooks (an empty folder of Michel's
// outside the subprocesses' home, as core.hooksPath), the file system monitor, automatic gc and
// maintenance, credential helpers and commit signing. System and global
// configuration are not read at all (GIT_CONFIG_NOSYSTEM, GIT_CONFIG_GLOBAL).
func (h home) safeConfig() []string {
	return []string{
		"-c", "core.hooksPath=" + h.hooks,
		"-c", "core.fsmonitor=false",
		"-c", "gc.auto=0",
		"-c", "maintenance.auto=false",
		"-c", "credential.helper=",
		"-c", "commit.gpgSign=false",
	}
}

// localTransport allows git's file transport, for the local clone and fetch only.
var localTransport = []string{"-c", "protocol.file.allow=always"}

// gitSubcommand is the git subcommand of a git argv built by gitArgs.
func gitSubcommand(args []string) string {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-C", "-c":
			i++
		case "--no-pager":
		default:
			return args[i]
		}
	}
	return ""
}

// git runs one git subcommand of the closed list on repo (git -C repo, or
// no -C when repo is ""), from cwd, with the safe configuration plus extra
// (-c pairs) and the fix environment plus env.
func (h home) git(ctx context.Context, d Deps, cwd, repo string, extra, env []string, sub string, args ...string) ([]byte, []byte, error) {
	if !slices.Contains(allowedGit, sub) {
		return nil, nil, fmt.Errorf("git %s is not a command Michel runs", sub)
	}
	argv := []string{"--no-pager"}
	if repo != "" {
		argv = append(argv, "-C", repo)
	}
	argv = append(argv, h.safeConfig()...)
	argv = append(argv, extra...)
	argv = append(argv, sub)
	argv = append(argv, args...)
	return d.exec()(ctx, "git", argv, h.env(d.ProxyAddr, env...), cwd)
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
