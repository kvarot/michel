//go:build !windows

package agent

import (
	"os/exec"
	"syscall"
)

// setProcessGroup starts Claude Code as the leader of a new process group,
// which every process it starts joins unless it leaves it.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// processTree is Claude Code's process group.
type processTree struct{ pgid int }

func newProcessTree(cmd *exec.Cmd) (processTree, error) {
	return processTree{pgid: cmd.Process.Pid}, nil
}

// kill sends SIGKILL to the whole group.
func (t processTree) kill() {
	if t.pgid > 0 {
		_ = syscall.Kill(-t.pgid, syscall.SIGKILL)
	}
}

// close kills what is left of the group once Claude Code has ended (a
// process it left running must not outlive the session).
func (t processTree) close() { t.kill() }
