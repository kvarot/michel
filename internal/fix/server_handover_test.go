package fix

import (
	"context"
	"errors"
	"testing"

	"github.com/kvarot/michel/internal/target"
)

// handOverFixture is a server whose settings say the user runs the scripts:
// the fix prepared is for them. Returns it approved.
func handOverFixture(t *testing.T) (*serverFixture, *demoServer, Attempt, Proposal) {
	t.Helper()
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecUser, target.SudoNopasswd, func(t *target.Target) { t.Sudo = target.SudoNone })
	f.mustCheck(s)
	a, p := f.startApproved(s, "expose_php")
	if p.Server.Executor != target.ExecUser {
		t.Fatalf("executor %s", p.Server.Executor)
	}
	return f, s, a, p
}

// setSettings changes the server's executor and sudo after the approval.
func setSettings(t *testing.T, f *serverFixture, s *demoServer, ex target.Executor, sudo target.SudoMode) {
	t.Helper()
	tg := s.t
	tg.Executor, tg.Sudo = ex, sudo
	if err := f.targets.Update(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
}

// B1 (R62 b): the user turned on "Michel runs it" after validating. One
// click makes Michel run the same scripts, under a new approval of who runs
// them; nothing runs without that click.
func TestHandOverRunsTheSameScriptsByMichel(t *testing.T) {
	ctx := context.Background()
	f, s, a, p := handOverFixture(t)
	setSettings(t, f, s, target.ExecMichel, target.SudoNopasswd)
	if sent(s) != 0 {
		t.Fatal("something ran before the click")
	}
	if err := HandOverToMichel(ctx, f.d, a.ID, p.Hash); err != nil {
		t.Fatalf("HandOverToMichel: %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed {
		t.Fatalf("state %s cause %q", got.State, got.Cause)
	}
	if sent(s) != 1 {
		t.Errorf("scripts sent: %d", sent(s))
	}
	np := f.proposal(a.ID)
	if np.Scripts.Hash != p.Scripts.Hash || np.Scripts.Apply != p.Scripts.Apply || np.Scripts.Undo != p.Scripts.Undo {
		t.Error("the scripts are not the validated ones")
	}
	if np.Server.Executor != target.ExecMichel || np.Server.CorrectionID != p.Server.CorrectionID {
		t.Errorf("executor %s correction %s", np.Server.Executor, np.Server.CorrectionID)
	}
	if auditCount(t, f.st, "server_fix.hand_over", "ok") != 1 {
		t.Error("hand over not audited")
	}
}

func TestHandOverRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("settings still say the user runs it", func(t *testing.T) {
		f, s, a, p := handOverFixture(t)
		// Michel, but root needs sudo without a password: still not Michel's.
		setSettings(t, f, s, target.ExecMichel, target.SudoNone)
		if err := HandOverToMichel(ctx, f.d, a.ID, p.Hash); !errors.Is(err, ErrNotMichelExecutor) {
			t.Fatalf("got %v", err)
		}
		if got := f.attempt(a.ID); got.State != StateApproved || sent(s) != 0 {
			t.Errorf("state %s, sent %d", got.State, sent(s))
		}
	})
	t.Run("stale or missing hash", func(t *testing.T) {
		f, s, a, _ := handOverFixture(t)
		setSettings(t, f, s, target.ExecMichel, target.SudoNopasswd)
		for _, h := range []string{"", "0000"} {
			if err := HandOverToMichel(ctx, f.d, a.ID, h); !errors.Is(err, ErrStaleProposal) {
				t.Errorf("hash %q: %v", h, err)
			}
		}
		if got := f.attempt(a.ID); got.State != StateApproved || sent(s) != 0 {
			t.Errorf("state %s, sent %d", got.State, sent(s))
		}
	})
	t.Run("the code changed since", func(t *testing.T) {
		f, s, a, p := handOverFixture(t)
		setSettings(t, f, s, target.ExecMichel, target.SudoNopasswd)
		s.srv.SetFile(s.ini, "[PHP]\nengine = On\nmemory_limit = 128M\n\nexpose_php = On\n")
		f.mustCheck(s)
		if err := HandOverToMichel(ctx, f.d, a.ID, p.Hash); !errors.Is(err, ErrScriptChanged) {
			t.Fatalf("got %v", err)
		}
		if sent(s) != 0 {
			t.Error("a script was sent")
		}
	})
	t.Run("not approved, or Michel's already", func(t *testing.T) {
		f := newServerFixture(t)
		s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
		f.mustCheck(s)
		a, p := f.startApproved(s, "expose_php")
		// Approved by a person for Michel: the click tries the run again
		// (TestHandOverRetriesARunThatDidNotStart); here the hash is stale.
		if err := HandOverToMichel(ctx, f.d, a.ID, p.Hash+"x"); !errors.Is(err, ErrStaleProposal) {
			t.Errorf("michel's own: %v", err)
		}
		f2 := newServerFixture(t)
		s2 := f2.addServer("srv-demo", "8.2", demoIni, target.ExecUser, target.SudoNopasswd, nil)
		f2.mustCheck(s2)
		a2, err := StartServer(ctx, f2.d, f2.finding(s2, "expose_php").ID)
		if err != nil {
			t.Fatal(err)
		}
		p2 := f2.proposal(a2.ID)
		if err := HandOverToMichel(ctx, f2.d, a2.ID, p2.Hash); !errors.Is(err, ErrBadTransition) {
			t.Errorf("proposed: %v", err)
		}
	})
	t.Run("a rule never does it", func(t *testing.T) {
		f, s, a, p := handOverFixture(t)
		setSettings(t, f, s, target.ExecMichel, target.SudoNopasswd)
		d := f.d
		d.Actor = ActorAuto
		if err := HandOverToMichel(ctx, d, a.ID, p.Hash); err == nil {
			t.Fatal("a rule handed a fix over")
		}
		if sent(s) != 0 {
			t.Error("a script was sent")
		}
	})
}
