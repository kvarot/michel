package workcopy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This file is the only way to start git. A project is untrusted input: its
// .git/config, and whatever that file includes, is read by git on every command
// run with -C on the project, and it must never make Michel run a program.
// TestNoOtherWayToStartGit keeps other calls out of the packages that handle a
// project, and TestHostileConfigRunsNoProgram holds a witness for each key.
//
// Three means, because no single one covers every key:
//   - the environment of execGit, on every command: no lazy fetch, and no
//     transport unless the command asks for one (a rewritten address is refused
//     whatever the project's protocol.* or url.*.insteadOf say);
//   - the -c options of enforced, which beat the project's value of a key with a
//     fixed name;
//   - checkProject, for keys Git cannot turn off with -c because a part of their
//     name is free: it reads the names of the project's keys and refuses.

// gitProfile says whose configuration a command reads, besides the repository's.
type gitProfile int

const (
	// gitIsolated reads Michel's empty configuration (home.env) and has no
	// transport but, on request, the local one.
	gitIsolated gitProfile = iota
	// gitFolder reads the person's configuration for what it does to the files
	// (core.autocrlf), and has no transport.
	gitFolder
	// gitRemote reads the person's configuration for its transport: keys, agent,
	// credential manager. It only ever runs in a temporary repository of Michel's,
	// so no key in it comes from the project.
	gitRemote
)

// gitCommand is one git command.
type gitCommand struct {
	profile gitProfile
	repo    string   // git -C, "" for none
	dir     string   // where it runs from
	env     []string // the whole environment of the profile
	config  []string // -c pairs of this command
	options []string // options before -C
	sub     string
	args    []string
}

// execGit starts git. Every command has these variables, whoever calls: they beat
// a repository's configuration. GIT_ALLOW_PROTOCOL also beats protocol.* and
// applies to an address url.*.insteadOf rewrote.
func execGit(ctx context.Context, d Deps, argv, env []string, dir string) ([]byte, []byte, error) {
	env = append(slices.Clone(env), "GIT_NO_LAZY_FETCH=1", "GIT_NO_REPLACE_OBJECTS=1")
	if !slices.ContainsFunc(env, func(kv string) bool { return strings.HasPrefix(kv, "GIT_ALLOW_PROTOCOL=") }) {
		env = append(env, "GIT_ALLOW_PROTOCOL="+noProtocol)
	}
	stdout, stderr, err := d.exec()(ctx, "git", argv, env, dir)
	// A process killed at the deadline ends with a code, sometimes 1, which some
	// commands use for an answer. It answered nothing.
	if err != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	return stdout, stderr, err
}

// noProtocol is a name no transport has: nothing is allowed.
const noProtocol = "none"

// runGit runs one command on a repository, with what the profile enforces. The
// enforced options come last: the last value of a key wins.
func (h home) runGit(ctx context.Context, d Deps, c gitCommand) ([]byte, []byte, error) {
	if err := h.checkProject(ctx, d, c); err != nil {
		return nil, nil, err
	}
	argv := append([]string{"--no-pager"}, c.options...)
	if c.repo != "" {
		argv = append(argv, "-C", c.repo)
	}
	argv = append(argv, c.config...)
	argv = append(argv, h.enforced(c.profile)...)
	argv = append(argv, c.sub)
	argv = append(argv, c.args...)
	return execGit(ctx, d, argv, c.env, c.dir)
}

// readPersonGlobal reads one setting of the person's own global configuration,
// included files too. It names no repository: nothing of a project is read.
func readPersonGlobal(ctx context.Context, d Deps, env []string, key string) ([]byte, []byte, error) {
	return execGit(ctx, d, []string{"config", "--global", "--includes", "--get", key}, env, d.DataDir)
}

// enforced turns off, for every command, what a repository's configuration could
// start or write on its own. core.longpaths lets git on Windows handle paths over
// 260 characters (a data folder deep in the profile); other systems ignore it.
func (h home) enforced(profile gitProfile) []string {
	always := []string{
		"-c", "core.hooksPath=" + h.hooks,
		"-c", "core.fsmonitor=false",
		"-c", "gc.auto=0",
		"-c", "maintenance.auto=false",
		"-c", "core.longpaths=true",
	}
	noTransport := []string{
		"-c", "credential.helper=",
		"-c", "commit.gpgSign=false",
		"-c", "core.sshCommand=",
		"-c", "core.alternateRefsCommand=",
		"-c", "fetch.bundleURI=",
	}
	switch profile {
	case gitRemote:
		// The person's helper and their ssh stay. Without GIT_ASKPASS git would use
		// core.askPass, a window nobody may be looking at. A bare repository is what
		// the person's safe.bareRepository=explicit refuses, and netGit only runs in
		// Michel's own.
		return append(always, "-c", "core.askPass=", "-c", "safe.bareRepository=all")
	case gitFolder:
		return slices.Concat(always, noTransport,
			[]string{"-c", "submodule.recurse=false", "-c", "merge.verifySignatures=false"})
	default:
		return slices.Concat(always, noTransport, []string{"-c", "core.attributesFile="})
	}
}

// errProjectConfig stops a command on a project before git starts.
var errProjectConfig = errors.New("Michel does not run this command on a project with these Git settings")

// ownRepo says whether repo is one Michel made, whose configuration is its own.
func ownRepo(d Deps, repo string) bool {
	for _, sub := range []string{"worktrees", "fix-mirrors", "fix-net"} {
		rel, err := filepath.Rel(filepath.Join(d.DataDir, sub), repo)
		if err == nil && rel != "." && filepath.IsLocal(rel) {
			return true
		}
	}
	return false
}

// checkProject refuses a command on a project when a key of the project would
// start something the options cannot turn off. Most commands need no reading,
// with a git that honors GIT_NO_LAZY_FETCH: reading the keys is one more process.
func (h home) checkProject(ctx context.Context, d Deps, c gitCommand) error {
	if c.repo == "" || c.sub == "config" || ownRepo(d, c.repo) {
		return nil
	}
	old := gitIsOld(d)
	onFiles := c.sub == "status" || c.sub == "merge"
	if !old && !onFiles && c.sub != "fetch" {
		return nil
	}
	keys, err := h.commandConfigKeys(ctx, d, c)
	if err != nil {
		return err
	}
	switch {
	case old && slices.ContainsFunc(keys, isPromisorKey):
		return errProjectConfig
	case onFiles && slices.ContainsFunc(keys, isFolderKey):
		return errProjectConfig
	case c.sub == "fetch" && slices.ContainsFunc(keys, isPathRemoteKey):
		return errProjectConfig
	}
	return nil
}

// localConfigKeys reads the names of a repository's own keys in small letters,
// included files and config.worktree too: git follows them, so the check does.
// --local alone follows no include, and --worktree is an error with several
// working trees when that file is not on. git config fetches nothing.
func (h home) localConfigKeys(ctx context.Context, d Deps, repo string) ([]string, error) {
	return h.commandConfigKeys(ctx, d, gitCommand{profile: gitIsolated, repo: repo, dir: d.DataDir, env: h.env(d.ProxyAddr)})
}

// commandConfigKeys reads those names in the environment of the command c: an
// include can depend on HOME or on the person's configuration (includeIf), so
// what counts is what that very command would read.
func (h home) commandConfigKeys(ctx context.Context, d Deps, c gitCommand) ([]string, error) {
	read := func(scope string) ([]string, error) {
		out, _, err := h.runGit(ctx, d, gitCommand{profile: c.profile, repo: c.repo, dir: c.dir, env: c.env, sub: "config",
			args: []string{scope, "--includes", "--name-only", "--list"}})
		if err != nil {
			return nil, err
		}
		return strings.Split(strings.ToLower(string(out)), "\n"), nil
	}
	keys, err := read("--local")
	if err != nil {
		return nil, err
	}
	if slices.Contains(keys, "extensions.worktreeconfig") {
		more, err := read("--worktree")
		if err != nil {
			return nil, err
		}
		keys = append(keys, more...)
	}
	return keys, nil
}

// isPromisorKey is a key that makes git fetch a missing object on its own.
func isPromisorKey(k string) bool {
	return k == "extensions.partialclone" || strings.HasPrefix(k, "remote.") && strings.HasSuffix(k, ".promisor")
}

// isFolderKey is a key that makes git status or git merge start a program (a
// filter) or work on another tree.
func isFolderKey(k string) bool {
	return strings.HasPrefix(k, "filter.") || k == "core.worktree"
}

// isPathRemoteKey is a program named for a remote called like a path. A fetch from
// a path reads remote.<that path>.*, and uploadpack or vcs there name a program.
// The name is free, so no option can turn it off.
func isPathRemoteKey(k string) bool {
	rest, ok := strings.CutPrefix(k, "remote.")
	return ok && strings.ContainsAny(rest, `/\:`) &&
		(strings.HasSuffix(rest, ".uploadpack") || strings.HasSuffix(rest, ".vcs"))
}

// refusePromisor says whether a project declares a remote that fetches on its
// own. It is asked first by what a page or a click on a remote reaches, whatever
// the version of git: such a project gets no click.
func (h home) refusePromisor(ctx context.Context, d Deps, repo string) bool {
	keys, err := h.localConfigKeys(ctx, d, repo)
	return err != nil || slices.ContainsFunc(keys, isPromisorKey)
}

// gitVersion asks once, outside any repository, which git this machine has.
var gitVersion = sync.OnceValue(func() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var env []string
	for _, k := range []string{"PATH", "SystemRoot"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	out, _, err := defaultExec(ctx, "git", []string{"version"}, env, "")
	return err != nil || versionIsOld(string(out))
})

// gitIsOld says whether git may ignore GIT_NO_LAZY_FETCH.
func gitIsOld(d Deps) bool { return d.assumeOldGit || gitVersion() }

var gitVersionShape = regexp.MustCompile(`^git version (\d+)\.(\d+)`)

// versionIsOld reads git version: older than 2.45, or a version it cannot read.
func versionIsOld(out string) bool {
	m := gitVersionShape.FindStringSubmatch(out)
	if m == nil {
		return true
	}
	major, err1 := strconv.Atoi(m[1])
	minor, err2 := strconv.Atoi(m[2])
	return err1 != nil || err2 != nil || major < 2 || major == 2 && minor < 45
}
