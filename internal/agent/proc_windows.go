//go:build windows

package agent

import (
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// setProcessGroup starts Claude Code in a new process group (no console
// signal from Michel's own console reaches it).
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}

// processTree is the job object holding Claude Code and every process it
// starts (the MCP server, any helper): killing the job
// kills them all, and so does closing its last handle (Michel exiting).
type processTree struct{ job windows.Handle }

// newProcessTree puts the started process in a new job object that kills
// everything in it when its last handle closes. Any failure is an error:
// Start then kills the process rather than run it outside the job. A
// process it started before the assignment would be outside the job
// (Claude Code starts nothing before reading its input).
func newProcessTree(cmd *exec.Cmd) (processTree, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return processTree{}, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return processTree{}, err
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		_ = windows.CloseHandle(job)
		return processTree{}, err
	}
	defer windows.CloseHandle(h)
	if err := windows.AssignProcessToJobObject(job, h); err != nil {
		_ = windows.CloseHandle(job)
		return processTree{}, err
	}
	return processTree{job: job}, nil
}

// kill ends every process of the job.
func (t processTree) kill() {
	if t.job != 0 {
		_ = windows.TerminateJobObject(t.job, 1)
	}
}

// close releases the job, killing what is left in it.
func (t processTree) close() {
	if t.job != 0 {
		_ = windows.CloseHandle(t.job)
	}
}
