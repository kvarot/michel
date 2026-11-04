package fix

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/target"
)

// watchStates records every state an attempt row moves through.
func watchStates(t *testing.T, f *serverFixture) func() []string {
	t.Helper()
	db := f.st.DB()
	for _, q := range []string{
		`CREATE TABLE seen_state (state TEXT)`,
		`CREATE TRIGGER seen_state_t AFTER UPDATE OF state ON fix_attempt BEGIN INSERT INTO seen_state VALUES (NEW.state); END`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return func() []string {
		rows, err := db.Query(`SELECT state FROM seen_state`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		return out
	}
}

// I1: the hand over is atomic for the worker: the attempt never shows as
// proposed, so a rule cannot approve it.
func TestHandOverNeverPassesThroughProposed(t *testing.T) {
	f, s, a, p := handOverFixture(t)
	setSettings(t, f, s, target.ExecMichel, target.SudoNopasswd)
	states := watchStates(t, f)
	if err := HandOverToMichel(context.Background(), f.d, a.ID, p.Hash); err != nil {
		t.Fatal(err)
	}
	got := states()
	if slices.Contains(got, string(StateProposed)) {
		t.Errorf("the attempt showed as proposed: %v", got)
	}
	if !slices.Contains(got, string(StateRunning)) {
		t.Errorf("no run: %v", got)
	}
}

// I1: when the new proposal cannot be stored, nothing moved: same approval,
// same proposal, nothing sent, and the worker has nothing to take.
func TestHandOverFailureKeepsTheApproval(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecUser, target.SudoNopasswd, func(tg *target.Target) {
		tg.FixLevel, tg.AutoConfig, tg.SiteURL = 3, true, "https://demo.example.test"
	})
	f.mustCheck(s)
	a, p := f.startApproved(s, "expose_php")
	setSettings(t, f, s, target.ExecMichel, target.SudoNopasswd)
	if _, err := f.st.DB().Exec(`CREATE TRIGGER no_insert BEFORE INSERT ON fix_proposal BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
		t.Fatal(err)
	}
	if err := HandOverToMichel(ctx, f.d, a.ID, p.Hash); err == nil {
		t.Fatal("no error")
	}
	got := f.attempt(a.ID)
	if got.State != StateApproved || got.ApprovedHash != p.Hash || got.ApprovedProposal != p.ID {
		t.Errorf("attempt moved: %+v", got)
	}
	if cur := f.proposal(a.ID); cur.ID != p.ID || cur.Server.Executor != target.ExecUser {
		t.Errorf("proposal moved: %+v", cur)
	}
	if _, err := ApplyAutoServer(ctx, f.d); err != nil {
		t.Fatal(err)
	}
	if sent(s) != 0 || f.attempt(a.ID).State != StateApproved {
		t.Errorf("the worker took it: sent %d, state %s", sent(s), f.attempt(a.ID).State)
	}
}

// I2: a server set to report only, or turned off, runs nothing by hand over.
func TestHandOverRefusedOnReportOnlyOrOff(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*target.Target)
		want   error
	}{
		"report only": {func(tg *target.Target) { tg.FixLevel = 0 }, ErrReportOnly},
		"turned off":  {func(tg *target.Target) { tg.Active = false }, ErrServerOff},
	} {
		t.Run(name, func(t *testing.T) {
			f, s, a, p := handOverFixture(t)
			tg, err := f.targets.Get(context.Background(), s.t.ID)
			if err != nil {
				t.Fatal(err)
			}
			tg.Executor, tg.Sudo = target.ExecMichel, target.SudoNopasswd
			tc.change(&tg)
			if err := f.targets.Update(context.Background(), tg); err != nil {
				t.Fatal(err)
			}
			if MichelRuns(tg, true) {
				t.Error("the page would offer the button")
			}
			if err := HandOverToMichel(context.Background(), f.d, a.ID, p.Hash); !errors.Is(err, tc.want) {
				t.Fatalf("got %v", err)
			}
			if got := f.attempt(a.ID); got.State != StateApproved || sent(s) != 0 {
				t.Errorf("state %s, sent %d", got.State, sent(s))
			}
			if f.auditCount("server_fix.hand_over", "refused") != 1 {
				t.Error("refusal not audited")
			}
		})
	}
}

// The ruling on I2: approving on a server set to report only is refused too.
func TestApproveRefusedOnReportOnly(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, err := StartServer(ctx, f.d, f.finding(s, "expose_php").ID)
	if err != nil {
		t.Fatal(err)
	}
	tg, err := f.targets.Get(ctx, s.t.ID)
	if err != nil {
		t.Fatal(err)
	}
	tg.FixLevel = 0
	if err := f.targets.Update(ctx, tg); err != nil {
		t.Fatal(err)
	}
	if err := Approve(ctx, f.d, a.ID, f.proposal(a.ID).Hash); !errors.Is(err, ErrReportOnly) {
		t.Fatalf("got %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateProposed {
		t.Errorf("state %s", got.State)
	}
}

// I3: a server Michel cannot reach leaves the fix to the person: the copy
// and « Je l'ai appliqué » stay, nothing is rewritten.
func TestHandOverUnreachableStaysThePersons(t *testing.T) {
	ctx := context.Background()
	f, s, a, p := handOverFixture(t)
	tg, err := f.targets.Get(ctx, s.t.ID)
	if err != nil {
		t.Fatal(err)
	}
	tg.Executor, tg.Sudo = target.ExecMichel, target.SudoNopasswd
	real := tg.Port
	tg.Port = closedPort(t)
	if err := f.targets.Update(ctx, tg); err != nil {
		t.Fatal(err)
	}
	if err := HandOverToMichel(ctx, f.d, a.ID, p.Hash); err == nil {
		t.Fatal("no error")
	}
	got := f.attempt(a.ID)
	if got.State != StateApproved || got.ApprovedHash != p.Hash {
		t.Errorf("attempt %+v", got)
	}
	if cur := f.proposal(a.ID); cur.ID != p.ID || cur.Server.Executor != target.ExecUser {
		t.Errorf("the fix left the person: %+v", cur.Server)
	}
	if f.auditCount("server_fix.hand_over", "refused") != 1 {
		t.Error("refusal not audited")
	}
	// The person can still say they ran it.
	tg.Port = real
	if err := f.targets.Update(ctx, tg); err != nil {
		t.Fatal(err)
	}
	if err := AppliedByMe(ctx, f.d, a.ID); err != nil {
		t.Errorf("applied by me: %v", err)
	}
}

// I3: a fix approved for Michel whose run could not start is tried again by
// the person's click; a rule's own attempt is not theirs to retry here.
func TestHandOverRetriesARunThatDidNotStart(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, p := f.startApproved(s, "expose_php")
	if err := HandOverToMichel(ctx, f.d, a.ID, "0000"); !errors.Is(err, ErrStaleProposal) {
		t.Fatalf("stale hash: %v", err)
	}
	if err := HandOverToMichel(ctx, f.d, a.ID, p.Hash); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed || sent(s) != 1 {
		t.Errorf("state %s sent %d", got.State, sent(s))
	}

	f2 := newServerFixture(t)
	s2 := f2.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f2.mustCheck(s2)
	a2, err := StartServer(ctx, f2.d, f2.finding(s2, "expose_php").ID)
	if err != nil {
		t.Fatal(err)
	}
	p2 := f2.proposal(a2.ID)
	auto := f2.d
	auto.Actor = ActorAuto
	if err := Approve(ctx, auto, a2.ID, p2.Hash); err != nil {
		t.Fatal(err)
	}
	if err := HandOverToMichel(ctx, f2.d, a2.ID, p2.Hash); !errors.Is(err, ErrNotUserExecutor) {
		t.Errorf("a rule's approval: %v", err)
	}
}

// I4: the agent's session is closed before the root script runs, as Apply does.
func TestHandOverClosesTheAgentSession(t *testing.T) {
	f, s, a, p := handOverFixture(t)
	setSettings(t, f, s, target.ExecMichel, target.SudoNopasswd)
	done := make(chan struct{})
	sess := &fakeCloser{done: done}
	f.d.sessions().add(a.ID, &running{sess: sess, done: done})
	if err := HandOverToMichel(context.Background(), f.d, a.ID, p.Hash); err != nil {
		t.Fatal(err)
	}
	if !sess.closed {
		t.Error("the session stayed open")
	}
}

// I12: a second click after a success does nothing; AppliedByMe neither.
func TestHandOverSecondClick(t *testing.T) {
	ctx := context.Background()
	f, s, a, p := handOverFixture(t)
	setSettings(t, f, s, target.ExecMichel, target.SudoNopasswd)
	if err := HandOverToMichel(ctx, f.d, a.ID, p.Hash); err != nil {
		t.Fatal(err)
	}
	np := f.proposal(a.ID)
	for _, h := range []string{p.Hash, np.Hash} {
		if err := HandOverToMichel(ctx, f.d, a.ID, h); !errors.Is(err, ErrBadTransition) {
			t.Errorf("hash %s: %v", h, err)
		}
	}
	if err := AppliedByMe(ctx, f.d, a.ID); err == nil {
		t.Error("applied by me after a hand over")
	}
	if sent(s) != 1 {
		t.Errorf("scripts sent: %d", sent(s))
	}
}

// I12: a package upgrade keeps its snapshot note, and is simulated first.
func TestHandOverOfAPackageFix(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	f.pkgFinding = true
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecUser, target.SudoNopasswd, nil)
	s.sim = "Inst libdemo [1.0-1] (1.1-1 Debian:12/stable [amd64])\n"
	f.mustCheck(s)
	a, err := StartServer(ctx, f.d, f.finding(s, "DSA-DEMO-1").ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := SnapshotDone(ctx, f.d, a.ID, "test"); err != nil {
		t.Fatal(err)
	}
	p := f.proposal(a.ID)
	if err := Approve(ctx, f.d, a.ID, p.Hash); err != nil {
		t.Fatal(err)
	}
	setSettings(t, f, s, target.ExecMichel, target.SudoNopasswd)
	if err := HandOverToMichel(ctx, f.d, a.ID, p.Hash); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := f.d.repo().SnapshotAck(ctx, a.ID); err != nil || !ok {
		t.Errorf("snapshot note lost: %v %v", ok, err)
	}
	sim := false
	for _, l := range s.srv.Log() {
		if strings.Contains(l, "apt-get") && strings.Contains(l, "-s") {
			sim = true
		}
	}
	if !sim {
		t.Errorf("no simulation: %v", s.srv.Log())
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed {
		t.Errorf("state %s cause %q", got.State, got.Cause)
	}
}

// I12: on a preprod, the production's fix is still built once it is proven.
func TestHandOverOnAPreprodStillPromotes(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	pre := f.addServer("srv-demo-pre", "8.3", demoIni, target.ExecUser, target.SudoNopasswd, func(tg *target.Target) { tg.Env = target.EnvPreprod })
	prod := f.addServer("srv-demo", "8.2", demoIni, target.ExecUser, target.SudoNopasswd, func(tg *target.Target) { tg.PreprodID = pre.t.ID })
	f.mustCheck(pre)
	f.mustCheck(prod)
	a, err := StartServer(ctx, f.d, f.finding(prod, "expose_php").ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.Work.Server.TargetID != pre.t.ID {
		t.Fatalf("not started on the preprod: %+v", a.Work.Server)
	}
	p := f.proposal(a.ID)
	if err := Approve(ctx, f.d, a.ID, p.Hash); err != nil {
		t.Fatal(err)
	}
	setSettings(t, f, pre, target.ExecMichel, target.SudoNopasswd)
	if err := HandOverToMichel(ctx, f.d, a.ID, p.Hash); err != nil {
		t.Fatal(err)
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed {
		t.Fatalf("state %s %q", got.State, got.Cause)
	}
	list, _ := f.d.repo().ListAttempts(ctx, prod.t.ID, "")
	if len(list) != 1 || list[0].State != StateProposed {
		t.Fatalf("no production fix: %+v", list)
	}
}

// closedPort is a local port nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// fakeCloser is an agent session: closing it ends its run.
type fakeCloser struct {
	Session
	done   chan struct{}
	closed bool
}

func (f *fakeCloser) Close() error {
	if !f.closed {
		f.closed = true
		close(f.done)
	}
	return nil
}
