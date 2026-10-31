//go:build windows

package sshx

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"
)

// DefaultAgentPipe is the named pipe of the Windows OpenSSH agent (Pageant in
// OpenSSH mode can be reached through its own pipe, set by ssh.agent_pipe).
const DefaultAgentPipe = `\\.\pipe\openssh-ssh-agent`

// SystemAgent returns the Deps.Agent function that connects to the SSH agent
// of this machine: the named pipe path, or DefaultAgentPipe when empty. Only
// local pipes (\\.\pipe\...) are accepted. No private key is ever read.
func SystemAgent(path string) func() (agent.ExtendedAgent, io.Closer, error) {
	return func() (agent.ExtendedAgent, io.Closer, error) {
		p := path
		if p == "" {
			p = DefaultAgentPipe
		}
		if !strings.HasPrefix(p, `\\.\pipe\`) {
			return nil, nil, fmt.Errorf("the SSH agent pipe %q is not a local pipe (\\\\.\\pipe\\...)", p)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := winio.DialPipeContext(ctx, p)
		if err != nil {
			return nil, nil, err
		}
		return agent.NewClient(conn), conn, nil
	}
}
