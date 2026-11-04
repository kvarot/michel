//go:build windows

package workcopy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

// killTreeOnCancel makes the end of the context stop every process the command
// started: git.exe on PATH is a wrapper that starts the real one, which starts
// ssh. A job object would be assigned after the start, too late for a child
// started at once. A taskkill that fails falls back on the process itself.
func killTreeOnCancel(cmd *exec.Cmd) {
	cmd.Cancel = func() error { return killTree(cmd) }
}

func killTree(cmd *exec.Cmd) error {
	kill := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "taskkill.exe"),
		"/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid))
	kill.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := kill.Run(); err != nil {
		return cmd.Process.Kill()
	}
	return nil
}
