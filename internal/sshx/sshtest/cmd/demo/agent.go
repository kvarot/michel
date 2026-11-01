package main

import (
	"net"
	"os"
	"path/filepath"
)

// maxSocketPath stays under the length a Unix socket path may have (108
// bytes on Linux and Windows, 104 on macOS).
const maxSocketPath = 100

// listenAgent opens a Unix socket of its own for the demo agent (never
// $SSH_AUTH_SOCK, never the system's agent pipe), readable by the current
// user only: in dir when its path is short enough, else in a new temporary
// folder. Windows 10 and later have Unix sockets too; Michel's
// ssh.agent_pipe takes their path.
func listenAgent(dir string) (net.Listener, string, error) {
	p := filepath.Join(dir, "agent.sock")
	if len(p) > maxSocketPath {
		d, err := os.MkdirTemp("", "michel-agent-")
		if err != nil {
			return nil, "", err
		}
		p = filepath.Join(d, "agent.sock")
	}
	_ = os.Remove(p) // a socket left by an earlier run of the demo
	ln, err := net.Listen("unix", p)
	if err != nil {
		return nil, "", err
	}
	if err := os.Chmod(p, 0o600); err != nil {
		ln.Close()
		return nil, "", err
	}
	return ln, p, nil
}
