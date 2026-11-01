//go:build windows

package sshx

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"

	"github.com/kvarot/michel/internal/egress"
)

// DefaultAgentPipe is the named pipe of the Windows OpenSSH agent (Pageant in
// OpenSSH mode can be reached through its own pipe, set by ssh.agent_pipe).
const DefaultAgentPipe = `\\.\pipe\openssh-ssh-agent`

// SystemAgent returns the Deps.Agent function that connects to the SSH agent
// of this machine: the named pipe path, or DefaultAgentPipe when empty. Only
// local pipes (\\.\pipe\...) and, for the agents that offer one, the absolute
// path of a Unix socket on a drive of this computer (Windows 10 and later)
// are accepted. No private key is ever read.
func SystemAgent(path string) func() (agent.ExtendedAgent, io.Closer, error) {
	return func() (agent.ExtendedAgent, io.Closer, error) {
		p := path
		if p == "" {
			p = DefaultAgentPipe
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if !strings.HasPrefix(p, `\\.\pipe\`) {
			if !localSocketPath(p) {
				return nil, nil, fmt.Errorf("the SSH agent pipe %q is not a local pipe (\\\\.\\pipe\\...) nor a local socket path", p)
			}
			conn, err := egress.DialLocalSocket(ctx, p)
			if err != nil {
				return nil, nil, err
			}
			return agent.NewClient(conn), conn, nil
		}
		conn, err := winio.DialPipeContext(ctx, p)
		if err != nil {
			return nil, nil, err
		}
		return agent.NewClient(conn), conn, nil
	}
}

// localSocketPath tells whether p is the absolute path of a file on a drive
// of this computer ("C:\..."), never a share (\\host\...) or a device path.
func localSocketPath(p string) bool {
	return filepath.IsAbs(p) && len(p) > 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}
