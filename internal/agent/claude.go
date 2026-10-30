package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/workcopy"
)

// Spec is one launch of Claude Code for a fix attempt.
type Spec struct {
	// Dir is the work copy, <DataDir>/worktrees/<project>/<attempt>: the
	// working folder of Claude Code and the only folder its file tools reach.
	Dir string
	// Prompt is the first user message, written on stdin (never in argv).
	// Empty sends nothing until Send.
	Prompt string
	// ResumeID resumes that Claude Code session (Session.ID of a previous
	// launch); empty starts a new one.
	ResumeID string
	// MCPCommand starts Michel's MCP server (michel mcp): the only server
	// of the generated MCP configuration. Empty declares none.
	MCPCommand []string
	// MCPEnv is the environment of the MCP server (fix.EnvAttempt,
	// fix.EnvToken), written in the generated MCP configuration only.
	MCPEnv map[string]string
	// Timeout ends the session, its process tree killed. 0 means
	// DefaultTimeout.
	Timeout time.Duration
	// MaxTurns caps Claude Code's agentic turns (--max-turns); 0 means no
	// cap besides Timeout.
	MaxTurns int
}

// DefaultTimeout is the time a fix attempt's session may run.
const DefaultTimeout = 20 * time.Minute

// tools are the only built-in tools of the session (--tools): the file
// tools. No Bash (controller ruling 33: Michel runs updates, installs and
// tests itself with closed argv), web, subagent, notebook or other tool
// exists in it.
const tools = "Read,Edit,Write,Glob,Grep"

// disallowed is the --disallowedTools value: Bash and the web tools,
// denied whatever else would allow them.
const disallowed = "Bash,WebFetch,WebSearch"

// mcpServer is the name of Michel's server in the generated MCP config.
const mcpServer = "michel"

// allowRules give the file tools the working folder (the copy) only, and
// the tools of Michel's MCP server when there is one.
func allowRules(s Spec) []string {
	rules := []string{"Read(./**)", "Edit(./**)", "Write(./**)", "Glob", "Grep"}
	if len(s.MCPCommand) > 0 {
		rules = append(rules, "mcp__"+mcpServer+"__*")
	}
	return rules
}

// protected are the paths of the copy the agent never writes: install
// folders (what Michel installs there runs in its tests), git's folder, and
// Claude Code's project settings and MCP file. Each at the root and at any
// depth.
var protected = []string{"vendor/**", "node_modules/**", ".git/**", ".claude/**", ".mcp.json"}

// denyRules are refused whatever else allows them: Bash, the web tools,
// writes to the protected paths, and reads of the user's Claude Code files
// (login, settings) and keys.
func denyRules() []string {
	rules := []string{"Bash", "WebFetch", "WebSearch"}
	for _, tool := range []string{"Edit", "Write"} {
		for _, p := range protected {
			rules = append(rules, tool+"(./"+p+")", tool+"(./**/"+p+")")
		}
	}
	return append(rules, "Read(~/.claude/**)", "Read(~/.claude.json)", "Read(~/.ssh/**)")
}

// generated returns the settings file and the MCP configuration of a
// session. The settings hold only keys of Claude Code's settings schema (a
// file that fails validation is silently ignored with --print; the argv
// carries the same permissions for that reason): permissions, no hook at
// all, project MCP servers off.
func generated(s Spec) (settings, mcp []byte, err error) {
	settings, err = json.MarshalIndent(map[string]any{
		"permissions": map[string]any{
			"defaultMode":                  "dontAsk",
			"allow":                        allowRules(s),
			"deny":                         denyRules(),
			"disableBypassPermissionsMode": "disable",
		},
		"disableAllHooks":            true,
		"enableAllProjectMcpServers": false,
	}, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	servers := map[string]any{}
	if len(s.MCPCommand) > 0 {
		env := s.MCPEnv
		if env == nil {
			env = map[string]string{}
		}
		servers[mcpServer] = map[string]any{"type": "stdio", "command": s.MCPCommand[0], "args": append([]string{}, s.MCPCommand[1:]...), "env": env}
	}
	mcp, err = json.MarshalIndent(map[string]any{"mcpServers": servers}, "", "  ")
	return settings, mcp, err
}

// loginVars are the variables Claude Code reads to find a login the user
// set up outside its config folder, passed through by name when Michel's
// own environment has them (their values are never logged). The
// CLAUDE_CODE_GIT_BASH_PATH is the Git Bash Claude Code looks for at start
// on Windows (the agent has no Bash tool). ANTHROPIC_BASE_URL and the other providers' variables are not
// passed: the allow proxy only reaches Anthropic.
var loginVars = []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_GIT_BASH_PATH"}

// isolationEnv turns off what Claude Code would load or reach besides
// Michel's settings: CLAUDE.md memory files (of the copy, its parents and
// the user), auto memory, claude.ai MCP connectors, the auto updater and
// the non-essential traffic (telemetry, error reports). The npm settings
// keep the agent's npm install without scripts and the user's ~/.npmrc.
func isolationEnv(fixHome string) []string {
	return []string{
		"CLAUDE_CODE_DISABLE_CLAUDE_MDS=1",
		"CLAUDE_CODE_DISABLE_AUTO_MEMORY=1",
		"ENABLE_CLAUDEAI_MCP_SERVERS=false",
		"DISABLE_AUTOUPDATER=1",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		"DISABLE_TELEMETRY=1",
		"npm_config_ignore_scripts=true",
		"npm_config_userconfig=" + filepath.Join(fixHome, "npmrc"),
	}
}

// environment is the whole environment of Claude Code: the workcopy
// allowlist (PATH, SystemRoot, TEMP, TMP, PATHEXT, the proxy for every
// scheme, caches and git settings in fix-home), the user's real profile as
// HOME and USERPROFILE (Claude Code finds the login there: the agent's
// setting sources and strict MCP keep the settings there unread), the login
// variables and isolationEnv.
func environment(d Deps) ([]string, error) {
	base, fixHome, err := workcopy.Env(d.workcopy())
	if err != nil {
		return nil, err
	}
	home, err := d.home()
	if err != nil || !filepath.IsAbs(home) {
		return nil, errors.New("Michel cannot find the user's profile folder, where Claude Code keeps its login")
	}
	override := map[string]bool{"HOME": true, "USERPROFILE": true}
	for _, kv := range isolationEnv(fixHome) {
		k, _, _ := strings.Cut(kv, "=")
		override[strings.ToUpper(k)] = true
	}
	var env []string
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if !override[strings.ToUpper(k)] {
			env = append(env, kv)
		}
	}
	env = append(env, "HOME="+home, "USERPROFILE="+home)
	for _, k := range loginVars {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			env = append(env, k+"="+v)
		}
	}
	return append(env, isolationEnv(fixHome)...), nil
}

// sessionID is the shape of a Claude Code session id (a UUID).
var sessionID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// argv is the closed argv of a session: every value is Michel's, the
// session id and the turn count are checked, the prompt goes on stdin.
func argv(s Spec, mcpPath, settingsPath string) ([]string, error) {
	a := []string{"-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose",
		"--mcp-config", mcpPath, "--strict-mcp-config",
		"--settings", settingsPath, "--setting-sources", "",
		"--restricted", "--tools", tools,
		"--permission-mode", "dontAsk", "--permission-prompts", "none",
		"--disable-slash-commands",
		"--allowedTools"}
	a = append(a, allowRules(s)...)
	a = append(a, "--disallowedTools", disallowed)
	if s.ResumeID != "" {
		if !sessionID.MatchString(s.ResumeID) {
			return nil, errors.New("the session to resume is not a Claude Code session id")
		}
		a = append(a, "--resume", s.ResumeID)
	}
	if s.MaxTurns < 0 {
		return nil, errors.New("the turn cap is negative")
	}
	if s.MaxTurns > 0 {
		a = append(a, "--max-turns", strconv.Itoa(s.MaxTurns))
	}
	return a, nil
}

// copyDir checks that dir is a copy, <DataDir>/worktrees/<project>/<attempt>,
// an existing folder (not a link).
func copyDir(d Deps, dir string) error {
	if d.DataDir == "" || !filepath.IsAbs(d.DataDir) || !filepath.IsAbs(dir) {
		return errors.New("the agent needs the absolute folder of the copy in Michel's data folder")
	}
	rel, err := filepath.Rel(filepath.Join(d.DataDir, "worktrees"), filepath.Clean(dir))
	if err != nil || len(strings.Split(filepath.ToSlash(rel), "/")) != 2 || strings.HasPrefix(rel, "..") {
		return errors.New("the agent runs only in a copy of Michel's data folder")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return errors.New("the copy folder is missing or is not a folder")
	}
	return nil
}

// Start launches Claude Code for s. It refuses when Claude Code is missing
// (ErrNotInstalled) or lacks the isolation options (ErrTooOld), writes the
// settings and MCP files of the session in fix-home, starts claude from the
// copy with its own process group (job object on Windows), sends s.Prompt
// and returns the session, whose events end when the process ends.
func Start(ctx context.Context, d Deps, s Spec) (*Session, error) {
	if err := copyDir(d, s.Dir); err != nil {
		return nil, err
	}
	if _, err := installed(ctx, d); err != nil {
		return nil, err
	}
	if err := isolated(ctx, d); err != nil {
		return nil, err
	}
	env, err := environment(d)
	if err != nil {
		return nil, err
	}
	settings, mcp, err := generated(s)
	if err != nil {
		return nil, err
	}
	fixHome := filepath.Join(d.DataDir, "fix-home")
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	tag := hex.EncodeToString(id[:])
	mcpPath := filepath.Join(fixHome, "mcp-"+tag+".json")
	settingsPath := filepath.Join(fixHome, "settings-"+tag+".json")
	files := []string{mcpPath, settingsPath}
	removeFiles := func() {
		for _, f := range files {
			_ = os.Remove(f)
		}
	}
	for f, b := range map[string][]byte{mcpPath: mcp, settingsPath: settings} {
		if err := os.WriteFile(f, b, 0o600); err != nil {
			removeFiles()
			return nil, errors.New("Michel cannot write the settings of the agent")
		}
	}
	args, err := argv(s, mcpPath, settingsPath)
	if err != nil {
		removeFiles()
		return nil, err
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	cmd := exec.Command(d.binary(), args...)
	cmd.Dir = s.Dir
	cmd.Env = env
	setProcessGroup(cmd)
	sess, err := launch(cmd, timeout, removeFiles)
	if err != nil {
		removeFiles()
		return nil, fmt.Errorf("Michel cannot start Claude Code: %w", noPath(err))
	}
	go func() {
		select {
		case <-ctx.Done():
			sess.kill(CauseCancelled)
		case <-sess.done:
		}
	}()
	if s.Prompt != "" {
		if err := sess.Send(s.Prompt); err != nil {
			_ = sess.Close()
			return nil, err
		}
	}
	return sess, nil
}

// noPath drops the file path of a file system or exec error.
func noPath(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	var ee *exec.Error
	if errors.As(err, &ee) {
		return ee.Err
	}
	return err
}
