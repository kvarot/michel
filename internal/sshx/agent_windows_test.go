//go:build windows

package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh/agent"
)

// An agent that offers a Unix socket on Windows is reached by its path; a
// share or a relative path is refused before anything is dialed.
func TestSystemAgentTakesALocalSocketPath(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Skipf("no Unix sockets here: %v", err)
	}
	defer ln.Close()
	kr := agent.NewKeyring()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := kr.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = agent.ServeAgent(kr, c) }()
		}
	}()
	ag, closer, err := SystemAgent(p)()
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	keys, err := ag.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("List: %v, %d keys", err, len(keys))
	}
	for _, bad := range []string{`\host\share\agent.sock`, `agent.sock`, `\?\C:\agent.sock`, `C:agent.sock`} {
		if _, _, err := SystemAgent(bad)(); err == nil {
			t.Errorf("SystemAgent(%q) was accepted", bad)
		}
	}
}
