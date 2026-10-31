//go:build !windows

package sshx

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/kvarot/michel/internal/egress"
)

// SystemAgent returns the Deps.Agent function that connects to the SSH agent
// of this machine: the Unix socket path, or $SSH_AUTH_SOCK when empty. No
// private key is ever read.
func SystemAgent(path string) func() (agent.ExtendedAgent, io.Closer, error) {
	return func() (agent.ExtendedAgent, io.Closer, error) {
		p := path
		if p == "" {
			p = os.Getenv("SSH_AUTH_SOCK")
		}
		if p == "" {
			return nil, nil, errors.New("SSH_AUTH_SOCK is not set")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := egress.DialLocalSocket(ctx, p)
		if err != nil {
			return nil, nil, err
		}
		return agent.NewClient(conn), conn, nil
	}
}
