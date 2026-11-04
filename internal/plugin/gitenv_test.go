package plugin

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A tool may run git on the project by itself: Semgrep lists its files with git
// ls-files. What the project's configuration names must not run then.
func TestToolEnvTurnsOffWhatTheProjectConfigStarts(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	mark := filepath.Join(dir, "ran")
	script := filepath.ToSlash(filepath.Join(dir, "witness.sh"))
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho \"$1\" >> '"+filepath.ToSlash(mark)+"'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "gitconfig")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(dir, "proj")
	setup := append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+empty,
		"GIT_AUTHOR_NAME=demo", "GIT_AUTHOR_EMAIL=demo@example.test", "GIT_COMMITTER_NAME=demo", "GIT_COMMITTER_EMAIL=demo@example.test")
	git := func(env []string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", proj}, args...)...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	git(setup, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(proj, "a.txt"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(setup, "add", "-A")
	git(setup, "commit", "-q", "-m", "init")
	git(setup, "config", "core.fsmonitor", script)
	git(setup, "config", "core.sshCommand", "sh '"+script+"' core.sshCommand")
	git(setup, "config", "core.repositoryformatversion", "1")
	git(setup, "config", "extensions.partialClone", "evil")
	git(setup, "config", "remote.evil.promisor", "true")
	git(setup, "config", "remote.evil.url", "ssh://example.test/demo.git")
	head := filepath.Join(proj, ".git", "refs", "heads", "main")
	if err := os.WriteFile(head, []byte(strings.Repeat("d", 40)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tool := append(toolEnv("127.0.0.1:1", filepath.Join(dir, "home")), "GIT_CONFIG_GLOBAL="+empty)
	run := func(env []string, args ...string) {
		cmd := exec.Command("git", append([]string{"-C", proj}, args...)...)
		cmd.Env = env
		_ = cmd.Run()
	}
	for _, args := range [][]string{
		{"ls-files", "--cached", "--others", "--exclude-standard"},
		{"status", "--porcelain"},
		{"rev-parse", "--verify", "--quiet", "HEAD^{commit}"},
		{"rev-parse", "--is-inside-work-tree"},
	} {
		run(tool, args...)
		if b, err := os.ReadFile(mark); err == nil {
			t.Errorf("git %v in a tool's environment ran: %s", args, b)
			_ = os.Remove(mark)
		}
	}
	// The witnesses are alive: the same commands without these variables run them.
	for _, args := range [][]string{{"status", "--porcelain"}, {"rev-parse", "--verify", "--quiet", "HEAD^{commit}"}} {
		run(setup, args...)
		if _, err := os.Stat(mark); err != nil {
			t.Errorf("control: plain git %v ran nothing, so this test proves nothing", args)
		}
		_ = os.Remove(mark)
	}
}
