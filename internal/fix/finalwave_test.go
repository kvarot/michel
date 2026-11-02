package fix

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/target"
)

const twoRisksIni = "[PHP]\nengine = On\nexpose_php = On\ndisplay_errors = On\nmemory_limit = 128M\n"

// setState moves an attempt to st directly (a test arranging a past).
func (f *serverFixture) setState(id string, st State) {
	f.t.Helper()
	if _, err := f.st.DB().Exec(`UPDATE fix_attempt SET state = ? WHERE id = ?`, string(st), id); err != nil {
		f.t.Fatal(err)
	}
}

// Final wave I1: while a server fix is applied (site check, undo,
// recollection) or unknown, no other fix of that server is prepared,
// approved by a rule or run, and the server cannot be removed.
func TestOneServerFixAtATimeLevel3(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", twoRisksIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) {
		tg.FixLevel, tg.AutoConfig = 3, true
	})
	f.mustCheck(s)
	// B is prepared first, then set aside so A can start.
	b, err := StartServer(ctx, f.d, f.finding(s, "display_errors_prod").ID)
	if err != nil {
		t.Fatal(err)
	}
	f.setState(b.ID, StateFailed)
	a, err := StartServer(ctx, f.d, f.finding(s, "expose_php").ID)
	if err != nil {
		t.Fatal(err)
	}
	other := f.d
	other.Sessions = NewSessions()
	var during struct {
		state         State
		start, apply  error
		autoRan       int
		autoErr       error
		claimed       bool
		block         string
		sentAtCheck   int
		sentAfterAuto int
	}
	site := f.d.SiteCheck
	checked := false
	f.d.SiteCheck = func(c context.Context, url string) error {
		if !checked {
			checked = true
			during.state = f.attempt(a.ID).State
			during.sentAtCheck = sent(s)
			// A new fix of another finding of the same server.
			f.setState(b.ID, StateFailed)
			_, during.start = StartServer(ctx, other, f.finding(s, "display_errors_prod").ID)
			// B, waiting for the user, must not run alone either.
			f.setState(b.ID, StateProposed)
			during.autoRan, during.autoErr = ApplyAutoServer(ctx, other)
			during.sentAfterAuto = sent(s)
			// Nor can a second approved fix be claimed.
			if err := Approve(ctx, other, b.ID, f.proposal(b.ID).Hash); err != nil {
				t.Errorf("Approve B: %v", err)
			}
			during.apply = Apply(ctx, other, b.ID)
			during.claimed, _ = f.d.repo().Claim(ctx, b.ID, time.Now().Add(time.Hour))
			f.setState(b.ID, StateFailed)
			// Only A is left: the server cannot leave Michel meanwhile.
			during.block, _ = f.d.repo().TargetBlock(ctx, s.t.ID)
		}
		return site(c, url)
	}
	if n, err := ApplyAutoServer(ctx, f.d); err != nil || n != 1 {
		t.Fatalf("ApplyAutoServer: %d %v", n, err)
	}
	if during.state != StateApplied {
		t.Fatalf("A during its site check: %s", during.state)
	}
	if !errors.Is(during.start, ErrBusy) {
		t.Errorf("StartServer while A is applied: %v, want ErrBusy", during.start)
	}
	if during.autoRan != 0 || during.sentAfterAuto != during.sentAtCheck {
		t.Errorf("a fix ran alone while A is applied: ran %d (%v), sent %d then %d", during.autoRan, during.autoErr, during.sentAtCheck, during.sentAfterAuto)
	}
	if during.claimed {
		t.Error("Claim took a second fix while A is applied")
	}
	if !errors.Is(during.apply, ErrBusy) {
		t.Errorf("Apply of B while A is applied: %v, want ErrBusy", during.apply)
	}
	if during.block != BlockWait {
		t.Errorf("TargetBlock while A is applied: %q, want %q", during.block, BlockWait)
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed {
		t.Errorf("A ended %s", got.State)
	}
}

// Final wave I1, by hand: an unknown attempt blocks a new fix and a claim.
func TestUnknownServerFixBlocksManualFix(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", twoRisksIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	b, _ := f.startApproved(s, "display_errors_prod")
	f.setState(b.ID, StateFailed)
	a, err := StartServer(ctx, f.d, f.finding(s, "expose_php").ID)
	if err != nil {
		t.Fatal(err)
	}
	f.setState(a.ID, StateUnknown)
	if _, err := StartServer(ctx, f.d, f.finding(s, "display_errors_prod").ID); !errors.Is(err, ErrBusy) {
		t.Errorf("StartServer next to an unknown fix: %v, want ErrBusy", err)
	}
	f.setState(b.ID, StateApproved)
	if err := Apply(ctx, f.d, b.ID); !errors.Is(err, ErrBusy) {
		t.Errorf("Apply next to an unknown fix: %v, want ErrBusy", err)
	}
	if ok, err := f.d.repo().Claim(ctx, b.ID, time.Now().Add(time.Hour)); err != nil || ok {
		t.Errorf("Claim next to an unknown fix: %v %v", ok, err)
	}
	if sent(s) != 0 {
		t.Errorf("sent %d scripts", sent(s))
	}
	// Once the unknown one is settled, the claim goes through.
	f.setState(a.ID, StateFailed)
	if ok, err := f.d.repo().Claim(ctx, b.ID, time.Now().Add(time.Hour)); err != nil || !ok {
		t.Errorf("Claim alone: %v %v", ok, err)
	}
}

// Final wave I2: the rollback's own lines (and codes 8, 9) win over the
// exit code; a code of the scripts' own (3 to 7) counts only with its line.
func TestClassifyExitRollbackFirst(t *testing.T) {
	rolled := []byte("[01-Nov] reloading\necho: fichiers remis\n" + serverfix.MsgRolledBack + "\n")
	bad := []byte(serverfix.MsgRollbackFailed + "\n")
	for _, c := range []struct {
		code   int
		stderr []byte
		pkg    bool
		want   error
	}{
		{3, rolled, false, ErrServerRolledBack},
		{4, rolled, false, ErrServerRolledBack},
		{5, rolled, false, ErrServerRolledBack},
		{6, rolled, false, ErrServerRolledBack},
		{7, rolled, false, ErrServerRolledBack},
		{126, rolled, false, ErrServerRolledBack},
		{127, rolled, false, ErrServerRolledBack},
		{9, nil, false, ErrServerRolledBack},
		{5, bad, false, ErrServerRollbackFailed},
		{3, bad, false, ErrServerRollbackFailed},
		{8, nil, false, ErrServerRollbackFailed},
		// The scripts' own refusals come with their line.
		{5, []byte("ligne introuvable\n"), false, ErrServerLineMoved},
		{3, []byte("lance ce script en root\n"), false, ErrServerWrongUser},
		{4, []byte("correction deja appliquee\n"), false, ErrServerAlreadyApplied},
		{6, []byte("lien refuse\n"), false, ErrServerLink},
		{7, []byte("dossier non sur\n"), false, ErrServerUnsafe},
		// Without it, it is another command's code.
		{5, nil, false, ErrServerStopped},
		{4, []byte("sed: couldn't write\n"), false, ErrServerStopped},
		{3, nil, true, ErrPackageFailed},
		{7, nil, true, ErrPackageFailed},
		{3, []byte("lance ce script en root\n"), true, ErrServerWrongUser},
	} {
		if got := classifyExit(c.code, c.stderr, c.pkg); !errors.Is(got, c.want) {
			t.Errorf("exit %d pkg %v stderr %q: %v, want %v", c.code, c.pkg, c.stderr, got, c.want)
		}
	}
}

// Final wave I2 end to end, under the sshtest shell: the reload after the
// change exits 5 ("unit not found"), the trap puts the file back. Michel
// reads a rollback (alert, cause rolled_back), never "the line moved", and
// prepares no new fix by itself.
func TestReloadExit5AfterChangeIsARollback(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) {
		tg.FixLevel, tg.AutoConfig = 3, true
	})
	f.mustCheck(s)
	s.reloads = []int{5}
	a, err := StartServer(ctx, f.d, f.finding(s, "expose_php").ID)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := ApplyAutoServer(ctx, f.d); n != 1 || err != nil {
		t.Fatalf("ApplyAutoServer: %d %v", n, err)
	}
	if file(t, s, s.ini) != demoIni {
		t.Errorf("php.ini not restored:\n%s", file(t, s, s.ini))
	}
	got := f.attempt(a.ID)
	if got.State != StateFailed || got.Cause != CauseRolledBack {
		t.Errorf("state %s cause %q", got.State, got.Cause)
	}
	if k := alertKinds(f); len(k) != 1 || k[0] != servercheck.AlertRolledBack {
		t.Errorf("alerts %v", k)
	}
	for _, st := range []State{StatePreparing, StateProposed, StateApproved} {
		if list, _ := f.d.repo().ListAttempts(ctx, s.t.ID, string(st)); len(list) != 0 {
			t.Errorf("a new fix was prepared (%s): %+v", st, list)
		}
	}
	// Nothing more runs on the next passes.
	before := sent(s)
	for i := 0; i < 3; i++ {
		_, _ = ApplyAutoServer(ctx, f.d)
	}
	if sent(s) != before {
		t.Errorf("sent %d more scripts", sent(s)-before)
	}
	var rolled bool
	for _, st := range f.proposal(a.ID).Steps {
		rolled = rolled || st.Detail == detailRolledBack
	}
	if !rolled {
		t.Errorf("steps do not say rolled back: %+v", f.proposal(a.ID).Steps)
	}
}

// Final wave I2: a re-proposal after a line that moved happens once; when
// the fix made again meets a moved line too, Michel prepares none and
// alerts, even at level 3.
func TestLineMovedTwiceStopsAndAlerts(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) {
		tg.FixLevel, tg.AutoConfig = 3, true
	})
	f.mustCheck(s)
	a, err := StartServer(ctx, f.d, f.finding(s, "expose_php").ID)
	if err != nil {
		t.Fatal(err)
	}
	// Each time a script reaches the server, the line has moved again.
	layouts := []string{"[PHP]\nengine = On\n\nexpose_php = On\n", "[PHP]\nengine = On\n\n\nexpose_php = On\n", "[PHP]\n\nengine = On\n\n\nexpose_php = On\n"}
	moves := 0
	move := func() {
		if moves < len(layouts) {
			s.srv.SetFile(s.ini, layouts[moves])
			moves++
		}
	}
	move()
	if n, err := ApplyAutoServer(ctx, f.d); n != 1 || err != nil || f.attempt(a.ID).Cause != f.d.causeOf(ErrServerLineMoved) {
		t.Fatalf("first run: %d %v %q", n, err, f.attempt(a.ID).Cause)
	}
	list, _ := f.d.repo().ListAttempts(ctx, s.t.ID, string(StateProposed))
	if len(list) != 1 || list[0].ID == a.ID {
		t.Fatalf("no fix made again: %+v", list)
	}
	move()
	if n, err := ApplyAutoServer(ctx, f.d); n != 1 || err != nil || f.attempt(list[0].ID).Cause != f.d.causeOf(ErrServerLineMoved) {
		t.Fatalf("second run: %d %v %q", n, err, f.attempt(list[0].ID).Cause)
	}
	move()
	for i := 0; i < 3; i++ {
		_, _ = ApplyAutoServer(ctx, f.d)
	}
	if n := sent(s); n != 2 {
		t.Errorf("sent %d scripts, want 2 (the fix and its one re-proposal)", n)
	}
	for _, st := range []State{StatePreparing, StateProposed, StateApproved} {
		if l, _ := f.d.repo().ListAttempts(ctx, s.t.ID, string(st)); len(l) != 0 {
			t.Errorf("a third fix was prepared (%s)", st)
		}
	}
	if k := alertKinds(f); len(k) != 1 || k[0] != servercheck.AlertLineMovedAgain {
		t.Errorf("alerts %v, want one %s", k, servercheck.AlertLineMovedAgain)
	}
}

// Final wave n2: scripts that are not valid text (the page cannot show
// them) are never approved, by the user or by a rule.
func TestApproveRefusesUnreadableScripts(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, err := StartServer(ctx, f.d, f.finding(s, "expose_php").ID)
	if err != nil {
		t.Fatal(err)
	}
	p := f.proposal(a.ID)
	for name, mod := range map[string]func(b *serverfix.Bundle){
		"apply": func(b *serverfix.Bundle) { b.Apply += "\xff\xfe" },
		"undo":  func(b *serverfix.Bundle) { b.Undo = "\xc3" + b.Undo },
	} {
		bad := p
		sc := *p.Scripts
		mod(&sc)
		bad.Scripts = &sc
		if err := f.d.approveServer(ctx, a, bad, bad.Hash); !errors.Is(err, ErrScriptsUnreadable) {
			t.Errorf("%s: approveServer: %v, want ErrScriptsUnreadable", name, err)
		}
	}
	if got := f.attempt(a.ID); got.State != StateProposed {
		t.Errorf("state %s", got.State)
	}
	if key := ErrorKey(ErrScriptsUnreadable); key != "fix.server.scripts_unreadable" {
		t.Errorf("key %q", key)
	}
	// Readable scripts still go through.
	if err := f.d.approveServer(ctx, a, p, p.Hash); err != nil {
		t.Errorf("approveServer: %v", err)
	}
}
