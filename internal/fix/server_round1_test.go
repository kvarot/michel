package fix

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/target"
)

// pkgFixture is a server with the libdemo advisory, its fix prepared,
// snapshot acknowledged and approved.
func pkgApproved(t *testing.T) (*serverFixture, *demoServer, Attempt) {
	t.Helper()
	f := newServerFixture(t)
	f.pkgFinding = true
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	s.sim = "Inst libdemo [1.0-1] (1.1-1 Debian:12/stable [amd64])\n"
	f.mustCheck(s)
	ctx := context.Background()
	a, err := StartServer(ctx, f.d, f.finding(s, "DSA-DEMO-1").ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := SnapshotDone(ctx, f.d, a.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if err := Approve(ctx, f.d, a.ID, f.proposal(a.ID).Hash); err != nil {
		t.Fatal(err)
	}
	return f, s, a
}

func alertKinds(f *serverFixture) []string {
	var out []string
	for _, a := range f.alerts {
		out = append(out, a.Kind)
	}
	return out
}

// C1: a package upgrade that fails is never "undone, as before".
func TestPackageFailureIsNotRolledBack(t *testing.T) {
	f, s, a := pkgApproved(t)
	s.aptExit = 100
	if err := Apply(context.Background(), f.d, a.ID); !errors.Is(err, ErrPackageFailed) {
		t.Fatalf("Apply: %v", err)
	}
	got := f.attempt(a.ID)
	if got.State != StateFailed || got.Cause != CausePackageFailed {
		t.Errorf("state %s cause %q", got.State, got.Cause)
	}
	if CauseText(i18n.FR, got.Cause) == got.Cause || !strings.Contains(CauseText(i18n.EN, got.Cause), "snapshot") {
		t.Errorf("cause text %q", CauseText(i18n.EN, got.Cause))
	}
	if len(f.alerts) != 1 || f.alerts[0].Kind != servercheck.AlertRestoreSnapshot || !f.alerts[0].Urgent {
		t.Errorf("alerts %+v", f.alerts)
	}
	if sent(s) != 1 {
		t.Errorf("sent %d scripts, want the apply only (no undo)", sent(s))
	}
}

// C1: an upgrade that takes the site down asks for the snapshot, no undo.
func TestSiteDownAfterUpgradeAsksSnapshot(t *testing.T) {
	f, s, a := pkgApproved(t)
	f.siteDown = func(d *demoServer) bool { return d.pkgVer == "1.1-1" }
	if err := Apply(context.Background(), f.d, a.ID); !errors.Is(err, ErrSiteDownAfterUpgrade) {
		t.Fatalf("Apply: %v", err)
	}
	got := f.attempt(a.ID)
	if got.State != StateFailed || got.Cause != CauseSiteDownAfterUpgrade || got.Cause == CauseRolledBack {
		t.Errorf("state %s cause %q", got.State, got.Cause)
	}
	if len(f.alerts) != 1 || f.alerts[0].Kind != servercheck.AlertRestoreSnapshot || !f.alerts[0].Urgent {
		t.Errorf("alerts %+v", f.alerts)
	}
	if sent(s) != 1 {
		t.Errorf("sent %d scripts, want no undo", sent(s))
	}
	var n int
	if err := f.st.DB().QueryRow(`SELECT COUNT(*) FROM fix_attempt WHERE cause = ?`, CauseRolledBack).Scan(&n); err != nil || n != 0 {
		t.Errorf("rolled back count %d %v", n, err)
	}
}

// I1: the attempt is claimed before anything is sent: a second Apply (from
// another process, its own session registry) and a Refuse during the run
// are refused, the script runs once.
func TestConcurrentApplyRunsOnce(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	other := f.d
	other.Sessions = NewSessions()
	var second, refuse error
	var once sync.Once
	s.onFPMTest = func(sshtest.Exec) {
		once.Do(func() {
			if got := f.attempt(a.ID); got.State != StateRunning {
				t.Errorf("state during the run %s", got.State)
			}
			second = Apply(context.Background(), other, a.ID)
			refuse = Refuse(context.Background(), other, a.ID, "")
		})
	}
	if err := Apply(context.Background(), f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(second, ErrBusy) || !errors.Is(refuse, ErrBadTransition) {
		t.Errorf("second Apply %v, Refuse %v", second, refuse)
	}
	if sent(s) != 1 || f.attempt(a.ID).State != StateProvenFixed {
		t.Errorf("sent %d, state %s", sent(s), f.attempt(a.ID).State)
	}
	// Two goroutines at once: exactly one runs.
	f2 := newServerFixture(t)
	s2 := f2.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f2.mustCheck(s2)
	a2, _ := f2.startApproved(s2, "expose_php")
	d2 := f2.d
	d2.Sessions = NewSessions()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, d := range []Deps{f2.d, d2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = Apply(context.Background(), d, a2.ID)
		}()
	}
	wg.Wait()
	busy := 0
	for _, e := range errs {
		if errors.Is(e, ErrBusy) {
			busy++
		} else if e != nil {
			t.Errorf("Apply: %v", e)
		}
	}
	if busy != 1 || sent(s2) != 1 {
		t.Errorf("busy %d, sent %d", busy, sent(s2))
	}
}

// I2: a caller that goes away (request cancelled) never cuts the script nor
// what Michel records after it.
func TestCancelledContextStillFinishes(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	ctx, cancel := context.WithCancel(context.Background())
	s.onFPMTest = func(sshtest.Exec) { cancel(); time.Sleep(50 * time.Millisecond) }
	_ = Apply(ctx, f.d, a.ID)
	if got := f.attempt(a.ID); got.State != StateProvenFixed {
		t.Errorf("state %s cause %q", got.State, got.Cause)
	}
	if auditCount(t, f.st, "server_fix.proven", "ok") != 1 || s.srv.Signals() != 0 {
		t.Errorf("proof not recorded, or the script was signalled (%d)", s.srv.Signals())
	}
}

// I3: the scripts are not bound by the collection's per-command cap.
func TestApplyNotBoundByCommandCap(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	f.d.SSH.CommandTimeout = 100 * time.Millisecond
	s.onFPMTest = func(sshtest.Exec) { time.Sleep(400 * time.Millisecond) }
	if err := Apply(context.Background(), f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed {
		t.Errorf("state %s", got.State)
	}
}

// I3: past its bound, the script is never killed nor guessed undone: the
// state is unknown, an urgent alert asks to look, the server is checked.
func TestApplyBoundExceededIsUnknown(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	f.d.ConfigApplyTimeout = 200 * time.Millisecond
	s.onFPMTest = func(sshtest.Exec) { time.Sleep(time.Second) }
	if err := Apply(context.Background(), f.d, a.ID); !errors.Is(err, ErrServerUnknownState) {
		t.Fatalf("Apply: %v", err)
	}
	unknownAfter(t, f, s, a)
}

func unknownAfter(t *testing.T, f *serverFixture, s *demoServer, a Attempt) {
	t.Helper()
	if got := f.attempt(a.ID); got.State != StateUnknown || got.Cause != i18n.T(i18n.EN, "fix.server.unknown_state") {
		t.Errorf("state %s cause %q", got.State, got.Cause)
	}
	if len(f.alerts) != 1 || f.alerts[0].Kind != servercheck.AlertUnknownState || !f.alerts[0].Urgent {
		t.Errorf("alerts %+v", f.alerts)
	}
	if s.srv.Signals() != 0 || sent(s) != 1 {
		t.Errorf("signals %d, sent %d (no kill, no undo)", s.srv.Signals(), sent(s))
	}
	steps := f.proposal(a.ID).Steps
	if len(steps) == 0 || steps[len(steps)-1].Op != StepRecollect {
		t.Errorf("no recollection: %+v", steps)
	}
}

// I3/I4: the connection drops in the middle of the script.
func TestSSHDropMidScriptIsUnknown(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	var once sync.Once
	s.onFPMTest = func(sshtest.Exec) { once.Do(s.srv.DropConnections) }
	if err := Apply(context.Background(), f.d, a.ID); !errors.Is(err, ErrServerUnknownState) {
		t.Fatalf("Apply: %v", err)
	}
	unknownAfter(t, f, s, a)
}

// I4: the snapshot gate holds at apply time too.
func TestApplyRechecksSnapshotGate(t *testing.T) {
	f, s, a := pkgApproved(t)
	if _, err := f.st.DB().Exec(`DELETE FROM server_snapshot_ack`); err != nil {
		t.Fatal(err)
	}
	accepted := s.srv.Accepted()
	if err := Apply(context.Background(), f.d, a.ID); !errors.Is(err, ErrSnapshotRequired) {
		t.Fatalf("Apply: %v", err)
	}
	if sent(s) != 0 || s.srv.Accepted() != accepted {
		t.Error("something reached the server")
	}
}

// I4 and minor 1: the server's settings changed after the approval: Michel
// no longer runs the fix, and the attempt ends so the server is not blocked.
func TestApplyRechecksExecutorAndSudo(t *testing.T) {
	for name, mod := range map[string]func(*target.Target){
		"sudo no longer nopasswd": func(t *target.Target) { t.Sudo = target.SudoNone },
		"executor now user":       func(t *target.Target) { t.Executor = target.ExecUser },
	} {
		t.Run(name, func(t *testing.T) {
			f := newServerFixture(t)
			s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
			f.mustCheck(s)
			a, _ := f.startApproved(s, "expose_php")
			tg := s.t
			mod(&tg)
			if err := f.targets.Update(context.Background(), tg); err != nil {
				t.Fatal(err)
			}
			if err := Apply(context.Background(), f.d, a.ID); !errors.Is(err, ErrNotMichelExecutor) {
				t.Fatalf("Apply: %v", err)
			}
			if sent(s) != 0 {
				t.Error("a script was sent")
			}
			if got := f.attempt(a.ID); got.State != StateFailed {
				t.Errorf("state %s", got.State)
			}
			if _, err := StartServer(context.Background(), f.d, a.FindingID); err != nil {
				t.Errorf("a new fix is blocked: %v", err)
			}
		})
	}
}

// I4: the server changed after the approval in a way Validate accepts, but
// the rendered scripts differ: caught by the hash, nothing sent, the
// attempt ends.
func TestInventoryChangeCaughtByHash(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	s.srv.SetFile(s.ini, "[PHP]\nengine = On\nmemory_limit = 128M\nexpose_php = On\n")
	f.mustCheck(s)
	if err := Apply(context.Background(), f.d, a.ID); !errors.Is(err, ErrScriptChanged) {
		t.Fatalf("Apply: %v", err)
	}
	var ev string
	if err := f.st.DB().QueryRow(`SELECT evidence FROM audit_event WHERE action = 'server_fix.apply' AND result = 'refused'`).Scan(&ev); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ev, "scripts differ") {
		t.Errorf("not caught by the hash: %s", ev)
	}
	if sent(s) != 0 || f.attempt(a.ID).State != StateFailed {
		t.Errorf("sent %d state %s", sent(s), f.attempt(a.ID).State)
	}
	if _, err := StartServer(context.Background(), f.d, a.FindingID); err != nil {
		t.Errorf("a new fix is blocked: %v", err)
	}
}

// Minor 3: exits that are not the script's are never counted as rolled back.
func TestClassifyExit(t *testing.T) {
	rolled := []byte("echec: fichiers remis\n")
	for _, c := range []struct {
		code   int
		stderr []byte
		pkg    bool
		want   error
	}{
		{1, rolled, false, ErrServerRolledBack},
		{1, []byte("sudo: a password is required\n"), false, ErrServerSudoRefused},
		{1, nil, false, ErrServerStopped},
		{126, nil, false, ErrServerNotRun},
		{127, nil, false, ErrServerNotRun},
		{8, nil, false, ErrServerRollbackFailed},
		{3, []byte("lance ce script en root\n"), true, ErrServerWrongUser},
		{1, []byte("sudo: a password is required\n"), true, ErrServerSudoRefused},
		{100, nil, true, ErrPackageFailed},
		{1, nil, true, ErrPackageFailed},
		{2, rolled, false, ErrServerRolledBack},
	} {
		if got := classifyExit(c.code, c.stderr, c.pkg); !errors.Is(got, c.want) {
			t.Errorf("exit %d pkg %v: %v, want %v", c.code, c.pkg, got, c.want)
		}
	}
	// The line the classification looks for is the scripts' own.
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	_, p := f.startApproved(s, "expose_php")
	if !strings.Contains(p.Scripts.Apply, scriptRolledBack) {
		t.Error("the apply script does not print the rolled back line")
	}
}

// Minor 3: sudo refused on the server: nothing ran, not a rollback.
func TestSudoRefusedIsNotRolledBack(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNone, func(t *target.Target) { t.Sudo = target.SudoNopasswd })
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	if err := Apply(context.Background(), f.d, a.ID); !errors.Is(err, ErrServerSudoRefused) {
		t.Fatalf("Apply: %v", err)
	}
	if got := f.attempt(a.ID); got.Cause == CauseRolledBack || got.State != StateFailed {
		t.Errorf("state %s cause %q", got.State, got.Cause)
	}
	if len(f.alerts) != 0 {
		t.Errorf("alerts %+v", f.alerts)
	}
}

// Minor 4: the simulation runs with the apply's privilege.
func TestSimulationUsesSudoWhenNopasswd(t *testing.T) {
	f, s, _ := pkgApproved(t)
	_ = f
	var viaSudo bool
	for _, l := range s.srv.Log() {
		viaSudo = viaSudo || strings.HasPrefix(l, "'sudo' '-n' 'apt-get' '-s'")
	}
	if !viaSudo {
		t.Errorf("simulation not run with sudo -n: %q", s.srv.Log())
	}
}

// Minor 5: the preprod's own fix level counts, and so does the prod's at
// promotion.
func TestPreprodFixLevelsChecked(t *testing.T) {
	f := newServerFixture(t)
	pre := f.addServer("srv-demo-pre", "8.3", demoIni, target.ExecMichel, target.SudoNopasswd, func(t *target.Target) { t.Env = target.EnvPreprod; t.FixLevel = 0 })
	prod := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(t *target.Target) { t.PreprodID = pre.t.ID })
	f.mustCheck(pre)
	f.mustCheck(prod)
	ctx := context.Background()
	if _, err := StartServer(ctx, f.d, f.finding(prod, "expose_php").ID); !errors.Is(err, ErrReportOnly) {
		t.Fatalf("preprod at level 0: %v", err)
	}
	tg := pre.t
	tg.FixLevel = 1
	if err := f.targets.Update(ctx, tg); err != nil {
		t.Fatal(err)
	}
	a, err := StartServer(ctx, f.d, f.finding(prod, "expose_php").ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := Approve(ctx, f.d, a.ID, f.proposal(a.ID).Hash); err != nil {
		t.Fatal(err)
	}
	pt := prod.t
	pt.FixLevel = 0
	if err := f.targets.Update(ctx, pt); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := f.d.repo().ListAttempts(ctx, prod.t.ID, ""); len(list) != 0 {
		t.Errorf("a prod fix was prepared at level 0: %+v", list)
	}
}

// Minor 6: backups are encrypted at rest on every system, checked on read,
// and never stored without the key store.
func TestBackupsEncryptedOnEveryOS(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	ctx := context.Background()
	if err := Apply(ctx, f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	var blob string
	if err := f.st.DB().QueryRow(`SELECT blob FROM server_backup`).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(blob)
	if strings.Contains(blob, "expose_php") || strings.Contains(string(raw), "expose_php") {
		t.Error("the backup is stored in clear")
	}
	if bs, err := f.d.backups(ctx, a.ID); err != nil || len(bs) != 1 || string(bs[0].Content) != demoIni {
		t.Fatalf("backups %+v %v", bs, err)
	}
	if _, err := f.st.DB().Exec(`UPDATE server_backup SET sha256 = '00'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.backups(ctx, a.ID); err == nil {
		t.Error("a backup that does not match its hash was read")
	}
	// No key store: no backup stored, said in the audit.
	f2 := newServerFixture(t)
	f2.d.Secrets = nil
	s2 := f2.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f2.mustCheck(s2)
	a2, _ := f2.startApproved(s2, "expose_php")
	if err := Apply(ctx, f2.d, a2.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f2.st.DB().QueryRow(`SELECT COUNT(*) FROM server_backup`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d backups stored without a key", n)
	}
	if auditCount(t, f2.st, "server_fix.backup", "refused") != 1 {
		t.Error("the unstored backup is not audited")
	}
}

// Minor 9: AppliedByMe refuses a fix Michel runs.
func TestAppliedByMeRefusesMichelExecutor(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	if err := AppliedByMe(context.Background(), f.d, a.ID); !errors.Is(err, ErrNotUserExecutor) {
		t.Fatalf("AppliedByMe: %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateApproved {
		t.Errorf("state %s", got.State)
	}
}

// A run left running by a stopped process ends unknown at the next start.
func TestSweepEndsStaleRunningUnknown(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	if err := f.d.repo().SetState(context.Background(), a.ID, []State{StateApproved}, StateRunning, ""); err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(2 * time.Hour)
	if err := Sweep(context.Background(), f.d); err != nil {
		t.Fatal(err)
	}
	if got := f.attempt(a.ID); got.State != StateUnknown {
		t.Errorf("state %s", got.State)
	}
	_ = scan.StatusGone
}
