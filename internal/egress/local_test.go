package egress_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/kvarot/michel/internal/egress"
)

func TestDialLocalSocketRefusesRelativePath(t *testing.T) {
	if _, err := egress.DialLocalSocket(context.Background(), "agent.sock"); err == nil {
		t.Fatal("a relative socket path was dialed")
	}
}

func TestDialLocalSocketConnects(t *testing.T) {
	dir, err := os.MkdirTemp("", "mx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	c, err := egress.DialLocalSocket(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
