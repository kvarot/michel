// Command fakeclaude stands in for the claude CLI in the tests of
// internal/agent. Its behaviour comes from fake.json next to its
// executable (the environment it gets is allowlisted, so it cannot carry
// the test's settings). It records its argv, environment, working folder
// and stdin lines in record.json next to it, and emulates the parts of
// Claude Code the isolation relies on: the settings sources it loads, the
// hooks of the settings it loads, the --version, --help and auth status
// answers, and a replayed stream-json conversation.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type config struct {
	Version  string     `json:"version"`
	Old      bool       `json:"old"`       // --help without the isolation flags
	LoggedIn bool       `json:"logged_in"` // auth status
	Turns    [][]string `json:"turns"`     // lines written after each stdin message
	Hang     bool       `json:"hang"`      // start a child and sleep forever
	ExitCode int        `json:"exit_code"`
}

type record struct {
	Args  []string `json:"args"`
	Env   []string `json:"env"`
	Dir   string   `json:"dir"`
	Stdin []string `json:"stdin"`
}

func main() {
	exe, err := os.Executable()
	if err != nil {
		os.Exit(3)
	}
	dir := filepath.Dir(exe)
	if len(os.Args) > 2 && os.Args[1] == "child" {
		heartbeat(os.Args[2])
		return
	}
	var cfg config
	if b, err := os.ReadFile(filepath.Join(dir, "fake.json")); err == nil {
		_ = json.Unmarshal(b, &cfg)
	}
	args := os.Args[1:]
	switch {
	case slices.Equal(args, []string{"--version"}):
		fmt.Printf("%s (Claude Code)\n", cfg.Version)
		return
	case slices.Equal(args, []string{"--help"}):
		fmt.Print(help(cfg.Old))
		return
	case slices.Equal(args, []string{"auth", "status", "--json"}):
		fmt.Printf(`{"loggedIn":%t,"authMethod":"claude.ai","email":"someone@example.invalid"}`+"\n", cfg.LoggedIn)
		return
	}
	cwd, _ := os.Getwd()
	rec := record{Args: args, Env: os.Environ(), Dir: cwd}
	save := func() {
		b, _ := json.Marshal(rec)
		_ = os.WriteFile(filepath.Join(dir, "record.json"), b, 0o600)
	}
	save()
	runHooks(args, cwd)
	if cfg.Hang {
		child := exec.Command(exe, "child", filepath.Join(dir, "heartbeat"))
		_ = child.Start()
		time.Sleep(time.Hour)
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	turn := 0
	for in.Scan() {
		rec.Stdin = append(rec.Stdin, in.Text())
		save()
		if turn < len(cfg.Turns) {
			for _, l := range cfg.Turns[turn] {
				fmt.Println(l)
			}
		}
		turn++
	}
	os.Exit(cfg.ExitCode)
}

// heartbeat rewrites a file every 50 ms until the process is killed.
func heartbeat(path string) {
	for i := 0; ; i++ {
		_ = os.WriteFile(path, []byte(fmt.Sprint(i)), 0o600)
		time.Sleep(50 * time.Millisecond)
	}
}

// value returns the argument after flag, and whether flag is present.
func value(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// runHooks emulates Claude Code's settings loading: the sources named by
// --setting-sources (all of them when the flag is missing), then the
// --settings file. A hook command "canary <path>" of a loaded settings file
// writes that path, unless the settings loaded so far disable all hooks.
func runHooks(args []string, cwd string) {
	sources := []string{"user", "project", "local"}
	if v, ok := value(args, "--setting-sources"); ok {
		sources = nil
		if v != "" {
			sources = strings.Split(v, ",")
		}
	}
	var files []string
	home := os.Getenv("USERPROFILE")
	if home == "" {
		home = os.Getenv("HOME")
	}
	for _, s := range sources {
		switch s {
		case "user":
			files = append(files, filepath.Join(home, ".claude", "settings.json"))
		case "project":
			files = append(files, filepath.Join(cwd, ".claude", "settings.json"))
		case "local":
			files = append(files, filepath.Join(cwd, ".claude", "settings.local.json"))
		}
	}
	if v, ok := value(args, "--settings"); ok {
		files = append(files, v)
	}
	var cmds []string
	disabled := false
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var s struct {
			DisableAllHooks bool `json:"disableAllHooks"`
			Hooks           map[string][]struct {
				Hooks []struct {
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"hooks"`
		}
		if json.Unmarshal(b, &s) != nil {
			continue
		}
		disabled = disabled || s.DisableAllHooks
		for _, groups := range s.Hooks {
			for _, g := range groups {
				for _, h := range g.Hooks {
					cmds = append(cmds, h.Command)
				}
			}
		}
	}
	if disabled {
		return
	}
	for _, c := range cmds {
		if p, ok := strings.CutPrefix(c, "canary "); ok {
			_ = os.WriteFile(p, []byte("hook ran"), 0o600)
		}
	}
}

func help(old bool) string {
	flags := []string{"-p, --print", "--input-format <format>", "--output-format <format>", "--verbose",
		"--mcp-config <configs...>", "--settings <file-or-json>", "--permission-mode <mode>", "--allowedTools, --allowed-tools <tools...>",
		"--disallowedTools, --disallowed-tools <tools...>", "-r, --resume [value]", "--tools <tools...>", "--permission-prompts <target>",
		"--disable-slash-commands"}
	if !old {
		flags = append(flags, "--strict-mcp-config", "--setting-sources <sources>", "--restricted")
	}
	return "Usage: claude [options] [command] [prompt]\n\nOptions:\n  " + strings.Join(flags, "\n  ") + "\n  (choices: \"acceptEdits\", \"dontAsk\", \"plan\")\n"
}
