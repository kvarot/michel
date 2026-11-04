//go:build !windows

package workcopy

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// killTreeOnCancel starts the command as the leader of a new process group, and
// makes the end of the context stop the whole group.
func killTreeOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}
