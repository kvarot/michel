package fix

import (
	"context"
	"testing"

	"github.com/kvarot/michel/internal/target"
)

// linkedServers is a production and its preprod, both checked.
func linkedServers(t *testing.T, f *serverFixture) (pre, prod *demoServer) {
	t.Helper()
	pre = f.addServer("srv-demo-pre", "8.3", demoIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) { tg.Env = target.EnvPreprod })
	prod = f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) { tg.PreprodID = pre.t.ID })
	f.mustCheck(pre)
	f.mustCheck(prod)
	return pre, prod
}

// A fix restarted from a preprod's own attempt keeps the production it was
// tried for: proven there, the production's fix is still built.
func TestPreprodRestartKeepsTheProduction(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	pre, prod := linkedServers(t, f)
	prodFinding, preFinding := f.finding(prod, "expose_php"), f.finding(pre, "expose_php")
	first, err := StartServer(ctx, f.d, prodFinding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := Refuse(ctx, f.d, first.ID, "not now"); err != nil {
		t.Fatal(err)
	}
	// The guide's button posts the preprod's finding to the preprod.
	again, err := StartServer(ctx, f.d, preFinding.ID)
	if err != nil {
		t.Fatal(err)
	}
	w := again.Work.Server
	if w.TargetID != pre.t.ID || w.ProdTargetID != prod.t.ID || w.ProdFindingID != prodFinding.ID {
		t.Fatalf("the link is lost: %+v", w)
	}
	if err := Approve(ctx, f.d, again.ID, f.proposal(again.ID).Hash); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, f.d, again.ID); err != nil {
		t.Fatal(err)
	}
	if got := f.attempt(again.ID); got.State != StateProvenFixed {
		t.Fatalf("preprod state %s %q", got.State, got.Cause)
	}
	list, _ := f.d.repo().ListAttempts(ctx, prod.t.ID, "")
	if len(list) != 1 || list[0].State != StateProposed || list[0].FindingID != prodFinding.ID {
		t.Fatalf("no production fix was built: %+v", list)
	}
}

// A preprod no longer linked, or a fix never tried for a production, is the
// preprod's own fix: nothing is promoted.
func TestPreprodRestartNeedsTheLink(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	pre, prod := linkedServers(t, f)
	preFinding := f.finding(pre, "expose_php")
	own, err := StartServer(ctx, f.d, preFinding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if own.Work.Server.ProdTargetID != "" {
		t.Fatalf("a link out of nowhere: %+v", own.Work.Server)
	}
	if err := Refuse(ctx, f.d, own.ID, "not now"); err != nil {
		t.Fatal(err)
	}
	first, err := StartServer(ctx, f.d, f.finding(prod, "expose_php").ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := Refuse(ctx, f.d, first.ID, "not now"); err != nil {
		t.Fatal(err)
	}
	// The production is unlinked since.
	tg := prod.t
	tg.PreprodID = ""
	if err := f.targets.Update(ctx, tg); err != nil {
		t.Fatal(err)
	}
	again, err := StartServer(ctx, f.d, preFinding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.Work.Server.ProdTargetID != "" || again.Work.Server.ProdFindingID != "" {
		t.Fatalf("the link outlived the unlinking: %+v", again.Work.Server)
	}
}

// startServerAgent reads the same link as StartServer.
func TestPreprodLinkIsTheSameForAnAgent(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	pre, prod := linkedServers(t, f)
	prodFinding, preFinding := f.finding(prod, "expose_php"), f.finding(pre, "expose_php")
	first, err := StartServer(ctx, f.d, prodFinding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := Refuse(ctx, f.d, first.ID, "not now"); err != nil {
		t.Fatal(err)
	}
	w, err := f.d.workOn(ctx, pre.t, preFinding)
	if err != nil {
		t.Fatal(err)
	}
	if w.TargetID != pre.t.ID || w.ProdTargetID != prod.t.ID || w.ProdFindingID != prodFinding.ID {
		t.Fatalf("workOn = %+v", w)
	}
}
