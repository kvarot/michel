package fix

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/target"
)

// agentAttempt is an agent attempt made by hand on s for finding fid (no
// session): ProposeServer can be called on it.
func (f *serverFixture) agentAttempt(s *demoServer, fid string) Attempt {
	f.t.Helper()
	a, err := f.d.repo().CreateAttempt(context.Background(), Attempt{FindingID: fid, ProjectID: s.t.ID, Origin: OriginAgent,
		Work: Work{Server: &ServerWork{TargetID: s.t.ID}}})
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}

func (f *serverFixture) auditCount(action, result string) int {
	f.t.Helper()
	var n int
	if err := f.st.DB().QueryRow(`SELECT COUNT(*) FROM audit_event WHERE action = ? AND result = ?`, action, result).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// I1: only Michel's own fix proven on the preprod opens the production's
// fix at level 3, and only the production fix built from it.
func TestPreprodProofMustBeMichelsOwnFix(t *testing.T) {
	ctx := context.Background()
	lvl3 := func(tg *target.Target) { tg.FixLevel, tg.AutoConfig = 3, true }
	f := newServerFixture(t)
	pre := f.addServer("srv-demo-pre", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) {
		lvl3(tg)
		tg.Env = target.EnvPreprod
	})
	prod := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) {
		lvl3(tg)
		tg.PreprodID = pre.t.ID
	})
	f.mustCheck(pre)
	f.mustCheck(prod)
	pf, prf := f.finding(pre, "expose_php"), f.finding(prod, "expose_php")

	// An agent's attempt on the preprod, proven: it opens nothing.
	ag, err := f.d.repo().CreateAttempt(ctx, Attempt{FindingID: pf.ID, ProjectID: pre.t.ID, Origin: OriginAgent,
		Work: Work{Server: &ServerWork{TargetID: pre.t.ID, ProdTargetID: prod.t.ID, ProdFindingID: prf.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DB().Exec(`UPDATE fix_attempt SET state = ? WHERE id = ?`, string(StateProvenFixed), ag.ID); err != nil {
		t.Fatal(err)
	}
	// A Michel fix of the production made apart (not built from a proven
	// preprod fix of Michel's).
	mine, err := f.d.proposeServer(ctx, prod.t, prf, ServerWork{TargetID: prod.t.ID})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := ApplyAutoServer(ctx, f.d); err != nil || n != 0 || sent(prod) != 0 {
		t.Fatalf("the agent's preprod proof opened a production fix: %d %v", n, err)
	}
	if err := Refuse(ctx, f.d, mine.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DB().Exec(`UPDATE fix_attempt SET state = ? WHERE id = ?`, string(StateFailed), ag.ID); err != nil {
		t.Fatal(err)
	}

	// Michel's own path: preprod first, proven, then the production fix
	// built from it runs alone.
	a, err := StartServer(ctx, f.d, prf.ID)
	if err != nil || a.ProjectID != pre.t.ID {
		t.Fatalf("StartServer: %v %+v", err, a)
	}
	if n, err := ApplyAutoServer(ctx, f.d); err != nil || n != 1 || f.attempt(a.ID).State != StateProvenFixed {
		t.Fatalf("preprod run: %d %v %s", n, err, f.attempt(a.ID).State)
	}
	list, err := f.d.repo().ListAttempts(ctx, prod.t.ID, string(StateProposed))
	if err != nil || len(list) != 1 || list[0].Work.Server == nil || list[0].Work.Server.PreprodAttemptID != a.ID {
		t.Fatalf("promoted production fix: %+v %v", list, err)
	}
	if n, err := ApplyAutoServer(ctx, f.d); err != nil || n != 1 || sent(prod) != 1 {
		t.Fatalf("production run: %d %v sent %d", n, err, sent(prod))
	}
}

// I2: an error before the approval is audited once, not at every pass;
// a server that is gone is skipped without a row.
func TestAutoErrorAuditedOnce(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) {
		tg.FixLevel, tg.AutoConfig = 3, true
	})
	f.mustCheck(s)
	if _, err := StartServer(ctx, f.d, f.finding(s, "expose_php").ID); err != nil {
		t.Fatal(err)
	}
	// The stored inventory becomes unreadable: LatestInventory fails.
	if _, err := f.st.DB().Exec(`UPDATE target_inventory SET body = 'not json' WHERE target_id = ?`, s.t.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		_, _ = ApplyAutoServer(ctx, f.d)
	}
	if n := f.auditCount("server_fix.auto", "error"); n != 1 {
		t.Errorf("%d error rows for one persistent error, want 1", n)
	}
	if _, err := f.st.DB().Exec(`DELETE FROM target WHERE id = ?`, s.t.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, _ = ApplyAutoServer(ctx, f.d)
	}
	if n := f.auditCount("server_fix.auto", "error"); n != 1 {
		t.Errorf("a gone server added error rows: %d", n)
	}
}

// I3: the agent of a server starts with Michel's MCP tools only, in a
// folder the agent driver accepts.
func TestServerAgentHasNoFileTools(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	sa := f.withAgent(nil)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	f.consent(s)
	a, err := StartServerAgent(ctx, f.d, f.finding(s, "expose_php").ID)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(sa, a.ID)
	spec := sa.specs[0]
	if !spec.NoFileTools {
		t.Error("the server agent has file tools")
	}
	rel, err := filepath.Rel(filepath.Join(f.d.DataDir, "worktrees"), spec.Dir)
	if err != nil || len(strings.Split(filepath.ToSlash(rel), "/")) != 2 || filepath.Base(spec.Dir) != a.ID {
		t.Errorf("folder %s is not <data>/worktrees/<server>/<attempt>", spec.Dir)
	}
}

// addAgentFindings stores on s the advisories ids of PHP built by hand
// (Michel has no ready-made fix for them).
func (f *serverFixture) addAgentFindings(s *demoServer, ids ...string) []scan.Finding {
	f.t.Helper()
	ctx := context.Background()
	// These findings only: the others are gone, so nothing else is queued.
	var fs []scan.Finding
	var out []scan.Finding
	for _, id := range ids {
		x := scan.Finding{ID: scan.FindingID(s.t.ID, "php-upstream", "php", "php", id), ProjectID: s.t.ID, ManifestRelPath: "php-upstream",
			Ecosystem: "php", Package: "php", OSVID: id, SeverityLabel: "high", InstalledVersion: "8.2.7", FixedVersions: []string{"8.2.30"},
			Kind: scan.KindServerPackage, SAPI: "fpm"}
		fs = append(fs, x)
		out = append(out, x)
	}
	tx, err := f.st.DB().BeginTx(ctx, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	defer tx.Rollback()
	if _, _, _, _, err := scan.ApplyServerFindings(ctx, tx, s.t.ID, "run-agent-"+s.t.ID, f.tick(), fs, scan.ServerApply{}); err != nil {
		f.t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// I4: the daily cap of the agents started alone counts the attempts made
// on the preprod for the production.
func TestDailyCapCountsPreprodAttempts(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	sa := f.withAgent(nil)
	pre := f.addServer("srv-demo-pre", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) { tg.Env = target.EnvPreprod })
	prod := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) {
		tg.FixLevel, tg.PreprodID = 2, pre.t.ID
	})
	f.mustCheck(pre)
	f.mustCheck(prod)
	ids := []string{"PHP-DEMO-1", "PHP-DEMO-2", "PHP-DEMO-3", "PHP-DEMO-4", "PHP-DEMO-5"}
	f.addAgentFindings(pre, ids...)
	f.addAgentFindings(prod, ids...)
	// Only the preprod's inventory leaves: its consent is the one asked.
	f.consent(pre)
	if _, err := QueueEligibleServer(ctx, f.d, prod.t.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2*len(ids); i++ {
		if _, err := WorkOnce(ctx, f.d); err != nil {
			t.Fatal(err)
		}
		sa.acting.Wait()
		all, _ := f.d.repo().ListAttempts(ctx, pre.t.ID, "")
		for _, a := range all {
			f.d.sessions().Wait(a.ID, 5*time.Second)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if sa.started != MaxAutoPerDay {
		t.Errorf("%d agents started alone in one day, want %d", sa.started, MaxAutoPerDay)
	}
}

// m1: the fix layer takes only the ops the agent's tool offers.
func TestProposeServerOnlyToolOps(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	f.withAgent(nil)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	f.consent(s)
	a := f.agentAttempt(s, f.finding(s, "expose_php").ID)
	for _, op := range []string{"backup_file", "test_config", "check_site"} {
		in := ServerProposeInput{Summary: "x", Actions: []ServerActionInput{{Op: "set_directive", Directive: "expose_php", Value: "0", SAPI: "fpm"}, {Op: op, Path: s.ini}}}
		if _, err := ProposeServer(ctx, f.d, a.ID, in); !errors.Is(err, ErrAgentActionRefused) {
			t.Errorf("%s accepted: %v", op, err)
		}
	}
}

// m2: a rule's approval never lands on an agent's fix.
func TestAutoActorRefusedOnAgentAttempt(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	f.withAgent(nil)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	f.consent(s)
	a := f.agentAttempt(s, f.finding(s, "expose_php").ID)
	p, err := ProposeServer(ctx, f.d, a.ID, ServerProposeInput{Summary: "x", Actions: []ServerActionInput{{Op: "set_directive", Directive: "expose_php", Value: "0", SAPI: "fpm"}}})
	if err != nil {
		t.Fatal(err)
	}
	auto := f.d
	auto.Actor = ActorAuto
	if err := Approve(ctx, auto, a.ID, p.Hash); !errors.Is(err, ErrBadTransition) {
		t.Fatalf("auto approval of an agent's fix: %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateProposed {
		t.Fatalf("state %s", got.State)
	}
}

// m3: a fix approved by the rule whose run could not start (server
// unreachable) tells the user once and is tried again once per check.
func TestAutoFallbackAlertsOnceRetriesPerCheck(t *testing.T) {
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
	port := s.t.Port
	if _, err := f.st.DB().Exec(`UPDATE target SET port = 1 WHERE id = ?`, s.t.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, _ = ApplyAutoServer(ctx, f.d)
	}
	notRun := func() int {
		n := 0
		for _, al := range f.alerts {
			if al.Kind == servercheck.AlertAutoNotRun {
				n++
			}
		}
		return n
	}
	if got := f.attempt(a.ID); got.State != StateApproved || got.ApprovedBy != ActorAuto {
		t.Fatalf("after an unreachable server: %s by %q", got.State, got.ApprovedBy)
	}
	if notRun() != 1 {
		t.Errorf("auto_not_run alerts: %d, want 1", notRun())
	}
	if n := f.auditCount("server_fix.auto", "ok"); n != 1 {
		t.Errorf("tried %d times without a new check, want 1", n)
	}
	// The next check: one more try, which now runs.
	if _, err := f.st.DB().Exec(`UPDATE target SET port = ? WHERE id = ?`, port, s.t.ID); err != nil {
		t.Fatal(err)
	}
	f.mustCheck(s)
	if n, err := ApplyAutoServer(ctx, f.d); err != nil || n != 1 {
		t.Fatalf("retry after the check: %d %v", n, err)
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed {
		t.Fatalf("after the retry: %s %s", got.State, got.Cause)
	}
	if notRun() != 1 {
		t.Errorf("auto_not_run alerts: %d", notRun())
	}
}

// m9: the agent's package simulations are capped per attempt, and a server
// that cannot be reached is told as such.
func TestAgentSimulationsCappedAndUnreachable(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	f.pkgFinding = true
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	s.sim = "Inst libdemo [1.0-1] (1.1-1 Debian:12/stable [amd64])\n"
	f.withAgent(nil)
	f.mustCheck(s)
	f.consent(s)
	a := f.agentAttempt(s, f.finding(s, "expose_php").ID)
	pkg := ServerProposeInput{Summary: "x", Actions: []ServerActionInput{{Op: "package_upgrade", Package: "libdemo", Version: "1.1-1"}}}
	port := s.t.Port
	if _, err := f.st.DB().Exec(`UPDATE target SET port = 1 WHERE id = ?`, s.t.ID); err != nil {
		t.Fatal(err)
	}
	var ref *ServerRefusal
	if _, err := ProposeServer(ctx, f.d, a.ID, pkg); !errors.As(err, &ref) || ref.Key != "fix.server.agent_refused.unreachable" {
		t.Fatalf("unreachable: %v", err)
	}
	if _, err := f.st.DB().Exec(`UPDATE target SET port = ? WHERE id = ?`, port, s.t.ID); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < MaxAgentSimulations; i++ {
		if _, err := ProposeServer(ctx, f.d, a.ID, pkg); err != nil {
			t.Fatalf("simulation %d: %v", i+1, err)
		}
	}
	before := len(s.srv.Log())
	if _, err := ProposeServer(ctx, f.d, a.ID, pkg); !errors.As(err, &ref) || ref.Key != "fix.server.agent_refused.simulation_limit" {
		t.Fatalf("over the cap: %v", err)
	}
	if len(s.srv.Log()) != before {
		t.Error("a simulation ran over the cap")
	}
}

// Consent revocation: audited, and the next start asks again.
func TestRevokeServerConsent(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	sa := f.withAgent(nil)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	f.consent(s)
	if err := RevokeServerConsent(ctx, f.d, s.t.ID); err != nil {
		t.Fatal(err)
	}
	if ok, _ := ServerConsent(ctx, f.d, s.t.ID); ok {
		t.Fatal("consent still recorded")
	}
	if n := f.auditCount("ai.consent_revoked", "ok"); n != 1 {
		t.Errorf("revocation audited %d times", n)
	}
	if _, err := StartServerAgent(ctx, f.d, f.finding(s, "expose_php").ID); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("start after revocation: %v", err)
	}
	if sa.started != 0 {
		t.Fatal("an agent started")
	}
	// An agent attempt made while consent was given proposes nothing after.
	a := f.agentAttempt(s, f.finding(s, "expose_php").ID)
	if _, err := ProposeServer(ctx, f.d, a.ID, ServerProposeInput{Summary: "x", Actions: []ServerActionInput{{Op: "set_directive", Directive: "expose_php", Value: "0", SAPI: "fpm"}}}); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("propose after revocation: %v", err)
	}
}
