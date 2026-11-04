package workcopy

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
)

// netTimeout bounds a command that talks to a Git host.
const netTimeout = 2 * time.Minute

// maxFailureName caps a branch name carried by a GitFailure.
const maxFailureName = 100

// RepoState values.
const (
	RepoNone  = "none"
	RepoEmpty = "empty"
	RepoOK    = "ok"
)

// PushResult outcomes.
const (
	PushPushed  = "pushed"
	PushAlready = "already"
)

// Classes of a GitFailure.
const (
	classAuth        = "auth"
	classHostKey     = "host_key"
	classNotFound    = "not_found"
	classRejected    = "rejected"
	classNetwork     = "network"
	classTimeout     = "timeout"
	classFailed      = "failed"
	classBranchMoved = "branch_moved"
	classNotDefault  = "not_default"
)

// GitFailure is the only error of the operations on a remote. It holds a closed
// class and never git's output, which may hold an address, a secret or a line
// written by the service. Current and Default are set for not_default only.
type GitFailure struct {
	Class, Current, Default string
}

// Error says the class and nothing else.
func (e *GitFailure) Error() string { return "git: " + e.Class }

func failure(class string) *GitFailure { return &GitFailure{Class: class} }

// notDefaultFailure carries two branch names read from a repository.
func notDefaultFailure(current, def string) *GitFailure {
	return &GitFailure{Class: classNotDefault, Current: failureName(current), Default: failureName(def)}
}

func failureName(s string) string {
	s = scan.SanitizeText(s)
	if r := []rune(s); len(r) > maxFailureName {
		return string(r[:maxFailureName])
	}
	return s
}

// classRules are read in order on git's stderr, in English (LC_ALL=C).
var classRules = []struct {
	class string
	says  []string
}{
	{classAuth, []string{"Authentication failed", "Permission denied", "could not read Username", "terminal prompts disabled", "publickey", "returned error: 401", "returned error: 403"}},
	{classHostKey, []string{"Host key verification failed"}},
	{classNotFound, []string{"not found", "does not appear to be a git repository"}},
	{classRejected, []string{"protected", "rejected", "non-fast-forward", "fetch first", "declined"}},
	{classNetwork, []string{"Could not resolve host", "Connection timed out", "Connection refused", "Failed to connect", "unable to access", "Could not connect"}},
}

// classify decides a class from git's stderr, which is then forgotten.
func classify(stderr []byte) string {
	for _, rule := range classRules {
		for _, s := range rule.says {
			if bytes.Contains(stderr, []byte(s)) {
				return rule.class
			}
		}
	}
	return classFailed
}

// userVars are the only variables of Michel's environment a command on a
// remote or on the person's folder receives.
var userVars = []string{"PATH", "SystemRoot", "TEMP", "TMP", "PATHEXT", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
	"APPDATA", "LOCALAPPDATA", "ProgramData", "XDG_CONFIG_HOME", "SSH_AUTH_SOCK", "SSH_AGENT_PID", "GIT_SSH", "GIT_SSH_COMMAND"}

// userEnv is the person's own setup, to reach their keys, agent and credential
// manager, with a closed list of variables and no way to prompt. It never sets
// GIT_CONFIG_NOSYSTEM nor GIT_CONFIG_GLOBAL: this configuration is the person's.
// SSH runs in batch mode unless the person chose their own program, which a
// variable or core.sshCommand tells. That setting is read directly: the
// GIT_CONFIG_GLOBAL of home.git points to Michel's empty file.
func userEnv(ctx context.Context, d Deps) []string {
	var env []string
	ownSSH := false
	for _, k := range userVars {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
			ownSSH = ownSSH || k == "GIT_SSH" || k == "GIT_SSH_COMMAND"
		}
	}
	env = append(env, "LC_ALL=C", "LANGUAGE=C", "GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=never",
		"SSH_ASKPASS_REQUIRE=never", "GIT_NO_REPLACE_OBJECTS=1")
	if !ownSSH {
		_, _, err := d.exec()(ctx, "git", []string{"config", "--global", "--get", "core.sshCommand"}, env, d.DataDir)
		if err != nil { // code 1: absent; any other failure must not allow a prompt
			env = append(env, "GIT_SSH_COMMAND=ssh -o BatchMode=yes")
		}
	}
	return env
}

// netDir holds the temporary repositories a command on a remote leaves from.
func netDir(d Deps) string { return filepath.Join(d.DataDir, "fix-net") }

var netCommands = []string{"push", "fetch"}

// netGit runs git push or fetch against address url, only from a temporary
// repository of Michel's: never the project, whose configuration is not trusted
// (core.sshCommand, credential.helper, url.*.insteadOf would run a program or
// change the destination when git holds real access), and which home.safeConfig
// cannot make safe without emptying the person's credential.helper.
//
// An https address goes through the authorizing proxy: its token stays in the
// environment, and http.proxy wins over a global one. Git's output is kept for
// the caller only on stdout; stderr is classified here and forgotten.
func (h home) netGit(ctx context.Context, d Deps, repo, url, proxyURL, sub string, args ...string) ([]byte, *GitFailure) {
	if !slices.Contains(netCommands, sub) || filepath.Dir(repo) != netDir(d) {
		return nil, failure(classFailed)
	}
	env := userEnv(ctx, d)
	protocols := "https:ssh"
	if d.AllowLocalRemote {
		protocols += ":file"
	}
	env = append(env, "GIT_ALLOW_PROTOCOL="+protocols)
	if strings.HasPrefix(url, "https://") {
		if proxyURL == "" {
			return nil, failure(classFailed)
		}
		for _, k := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
			env = append(env, k+"="+proxyURL)
		}
		env = append(env, "NO_PROXY=", "no_proxy=",
			"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.proxy", "GIT_CONFIG_VALUE_0="+proxyURL)
	}
	argv := []string{"--no-pager", "-C", repo,
		"-c", "core.hooksPath=" + h.hooks,
		"-c", "core.fsmonitor=false",
		"-c", "gc.auto=0",
		"-c", "maintenance.auto=false",
		"-c", "core.longpaths=true",
		sub}
	argv = append(argv, args...)
	ctx, cancel := context.WithTimeout(ctx, netTimeout)
	defer cancel()
	stdout, stderr, err := d.exec()(ctx, "git", argv, env, d.DataDir)
	switch {
	case err == nil:
		return stdout, nil
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return stdout, failure(classTimeout)
	default:
		return stdout, failure(classify(stderr))
	}
}

// netClone makes a temporary repository from the project, the way Prepare makes
// its mirror: nothing of the project's configuration comes with it.
func (h home) netClone(ctx context.Context, d Deps, p project.Project, options ...string) (repo string, cleanup func(), fail *GitFailure) {
	if err := os.MkdirAll(netDir(d), 0o700); err != nil {
		return "", nil, failure(classFailed)
	}
	repo = filepath.Join(netDir(d), ulid.Make().String()+".git")
	cleanup = func() { _ = os.RemoveAll(repo) }
	args := append([]string{"--bare", "--local", "--no-hardlinks", "--quiet", "--no-tags"}, options...)
	args = append(args, "--", p.Path, repo)
	if _, _, err := h.git(ctx, d, netDir(d), "", localTransport, nil, "clone", args...); err != nil {
		cleanup()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", nil, failure(classTimeout)
		}
		return "", nil, failure(classFailed)
	}
	return repo, cleanup, nil
}

// RepoState tells what the folder of a project is: not a repository (only the
// folder itself is looked at, not its parents), a repository without a commit,
// or one Michel can work on.
func RepoState(ctx context.Context, d Deps, p project.Project) (string, error) {
	if !filepath.IsAbs(p.Path) || !IsGitRepo(p.Path) {
		return RepoNone, nil
	}
	h, err := ensureHome(d)
	if err != nil {
		return "", failure(classFailed)
	}
	head, err := h.revParseCommit(ctx, d, p.Path, "HEAD")
	if err != nil {
		return "", failure(classFailed)
	}
	if head == "" {
		return RepoEmpty, nil
	}
	return RepoOK, nil
}

// remoteName is the shape of a remote's name Michel accepts.
var remoteName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

const (
	remoteKeyPrefix = "remote."
	remoteKeySuffix = ".url"
)

// ReadRemotes reads, without network, the address written in the project's own
// .git/config, unresolved: neither insteadOf nor pushurl apply. It chooses
// origin, or else the only remote. When it cannot choose it says several and
// returns no address. raw is untrusted and may hold a secret: it goes to
// gitremote.Parse and nowhere else.
func ReadRemotes(ctx context.Context, d Deps, p project.Project) (name, raw string, several bool, err error) {
	if !filepath.IsAbs(p.Path) || !IsGitRepo(p.Path) {
		return "", "", false, failure(classFailed)
	}
	h, herr := ensureHome(d)
	if herr != nil {
		return "", "", false, failure(classFailed)
	}
	out, _, gerr := h.git(ctx, d, d.DataDir, p.Path, nil, nil, "config", "--local", "--null", "--get-regexp", `^remote\..*\.url$`)
	if gerr != nil {
		if exitCode(gerr) == 1 {
			return "", "", false, nil
		}
		return "", "", false, failure(classFailed)
	}
	urls := map[string][]string{}
	for _, entry := range strings.Split(string(out), "\x00") {
		if entry == "" {
			continue
		}
		key, value, _ := strings.Cut(entry, "\n") // no newline: a key without a value
		n := strings.TrimSuffix(strings.TrimPrefix(key, remoteKeyPrefix), remoteKeySuffix)
		urls[n] = append(urls[n], value)
	}
	chosen := "origin"
	if _, ok := urls[chosen]; !ok {
		switch len(urls) {
		case 0:
			return "", "", false, nil
		case 1:
			for n := range urls {
				chosen = n
			}
		default:
			return "", "", true, nil
		}
	}
	// A name Michel refuses is not a remote it can choose, and saying there is
	// none would be false.
	if len(urls[chosen]) != 1 || !remoteName.MatchString(chosen) {
		return "", "", true, nil
	}
	return chosen, urls[chosen][0], false, nil
}

// PushResult is what happened to the branch on the remote.
type PushResult struct {
	Outcome string // PushPushed or PushAlready
}

// Push sends one fix branch to the address url, from a temporary repository
// that holds that branch alone and is removed afterwards. It writes nothing in
// the project. The branch must still be the approved commit. It never forces.
// url comes from the caller, read and checked by gitremote: a password in it
// would be in the argv. proxyURL is required for an https address and unused
// otherwise.
func Push(ctx context.Context, d Deps, p project.Project, url, proxyURL, branch, sha string) (PushResult, error) {
	if !branchShape.MatchString(branch) || !shaShape.MatchString(sha) {
		return PushResult{}, failure(classBranchMoved)
	}
	if !filepath.IsAbs(p.Path) || !IsGitRepo(p.Path) {
		return PushResult{}, failure(classFailed)
	}
	h, err := ensureHome(d)
	if err != nil {
		return PushResult{}, failure(classFailed)
	}
	ref := "refs/heads/" + branch
	if f := h.checkBranch(ctx, d, p.Path, ref, sha); f != nil {
		return PushResult{}, f
	}
	repo, cleanup, f := h.netClone(ctx, d, p, "--single-branch", "--branch", branch)
	if f != nil {
		return PushResult{}, f
	}
	defer cleanup()
	// The branch may have moved during the clone: what leaves is what was approved.
	if f := h.checkBranch(ctx, d, repo, ref, sha); f != nil {
		return PushResult{}, f
	}
	refspec := ref + ":" + ref
	stdout, f := h.netGit(ctx, d, repo, url, proxyURL, "push",
		"--porcelain", "--no-follow-tags", "--no-recurse-submodules", "--no-signed", "--no-verify", "--", url, refspec)
	if f != nil && f.Class == classTimeout {
		return PushResult{}, f
	}
	flag, found := pushFlag(stdout, refspec)
	if found && flag == "!" {
		return PushResult{}, failure(classRejected)
	}
	if f != nil {
		return PushResult{}, f
	}
	switch {
	case found && (flag == "*" || flag == " "):
		return PushResult{Outcome: PushPushed}, nil
	case found && flag == "=":
		return PushResult{Outcome: PushAlready}, nil
	}
	return PushResult{}, failure(classFailed)
}

// checkBranch compares a branch with the commit it must be on.
func (h home) checkBranch(ctx context.Context, d Deps, repo, ref, sha string) *GitFailure {
	got, err := h.revParseCommit(ctx, d, repo, ref)
	if err != nil {
		return failure(classFailed)
	}
	if got != sha {
		return failure(classBranchMoved)
	}
	return nil
}

// pushFlag reads the status of one reference in git's porcelain output: only
// its tab-separated line, flag then from:to. The To line holds the address and
// is not read.
func pushFlag(stdout []byte, refspec string) (string, bool) {
	for line := range strings.Lines(string(stdout)) {
		fields := strings.Split(strings.TrimRight(line, "\r\n"), "\t")
		if len(fields) >= 2 && len(fields[0]) == 1 && fields[1] == refspec {
			return fields[0], true
		}
	}
	return "", false
}
