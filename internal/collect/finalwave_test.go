package collect_test

import (
	"context"
	"io"
	"testing"

	"github.com/kvarot/michel/internal/collect"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/target"
)

// Final wave I3: a login shell without `command` (tcsh, csh) answers
// exit 1 with nothing on its output, as bash does when every name is
// missing. The sentinel (`command -v sh` must print a path) tells them
// apart: the lookup failed, it is not "no PHP".
func TestShellWithoutCommandIsAFailedLookup(t *testing.T) {
	h := debian(t)
	cmds := h.commands()
	cmds["command"] = func(e sshtest.Exec) int {
		io.WriteString(e.Stderr, "command: Command not found.\n")
		return 1
	}
	e := restart(t, start(t, h), sshtest.New(t, sshtest.Options{Commands: cmds}))
	inv, err := collect.Run(context.Background(), e.deps, e.client, e.tgt, demoLinks)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(inv.PHP) != 0 || !hasUnseen(inv, "discovery", collect.ReasonProbe) {
		t.Fatalf("tcsh-like answer read as no PHP: unseen %+v, php %+v", inv.Unseen, inv.PHP)
	}
	// The same exit 127 of dash with nothing printed at all.
	cmds["command"] = func(e sshtest.Exec) int { return 127 }
	e = restart(t, start(t, h), sshtest.New(t, sshtest.Options{Commands: cmds}))
	if inv, _ := collect.Run(context.Background(), e.deps, e.client, e.tgt, demoLinks); !hasUnseen(inv, "discovery", collect.ReasonProbe) {
		t.Fatalf("exit 127 without the sentinel: unseen %+v", inv.Unseen)
	}
}

// A shell that has `command` and simply no PHP: not installed, no Unseen.
func TestNoPHPWithSentinelIsNotInstalled(t *testing.T) {
	h := debian(t)
	h.bins = map[string]string{}
	inv := run(t, start(t, h), demoLinks)
	if len(inv.PHP) != 0 || hasUnseen(inv, "discovery", collect.ReasonProbe) {
		t.Fatalf("no PHP: unseen %+v, php %+v", inv.Unseen, inv.PHP)
	}
	if got := collect.Commands(target.Target{})[2]; len(got) < 3 || got[0] != "command" || got[2] != "sh" {
		t.Errorf("the lookup does not ask for sh first: %q", got)
	}
}
