package digest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
)

func TestDigestFixLines(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	waiting := f.seed(finding{pkg: "acme/lib", osv: "ACME-1", severity: "high", firstSeen: now.Add(-10 * 24 * time.Hour)})
	proven := f.seed(finding{pkg: "left-pad", osv: "NPM-2", severity: "high", firstSeen: now.Add(-10 * 24 * time.Hour), status: "gone"})
	queued := f.seed(finding{pkg: "acme/other", osv: "ACME-3", severity: "low", firstSeen: now.Add(-10 * 24 * time.Hour)})
	repo := fix.NewRepo(f.st)
	repo.Now = func() time.Time { return now.Add(-time.Hour) }
	a, err := repo.CreateAttempt(ctx, fix.Attempt{FindingID: waiting, ProjectID: f.proj.ID, Origin: fix.OriginAgent,
		Work: fix.Work{Plan: fix.Plan{Target: "1.2.5"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.AddProposal(ctx, fix.Proposal{AttemptID: a.ID, Summary: "SECRET-SUMMARY", Diff: "+++ b/composer.lock", Hash: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetState(ctx, a.ID, []fix.State{fix.StatePreparing}, fix.StateProposed, ""); err != nil {
		t.Fatal(err)
	}
	b, err := repo.CreateAttempt(ctx, fix.Attempt{FindingID: proven, ProjectID: f.proj.ID, Origin: fix.OriginAgentAuto})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range [][2]fix.State{{fix.StatePreparing, fix.StateProposed}, {fix.StateProposed, fix.StateApproved}, {fix.StateApproved, fix.StateApplied}, {fix.StateApplied, fix.StateProvenFixed}} {
		if err := repo.SetState(ctx, b.ID, []fix.State{s[0]}, s[1], ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.Enqueue(ctx, queued, f.proj.ID); err != nil {
		t.Fatal(err)
	}
	d := f.compute(i18n.EN, Options{})
	p := projectNamed(t, d, "demo")
	if len(p.FixWaiting) != 1 || p.FixWaiting[0].Package != "acme/lib" || p.FixWaiting[0].Target != "1.2.5" || p.FixWaiting[0].AttemptID != a.ID {
		t.Errorf("waiting = %+v", p.FixWaiting)
	}
	if len(p.FixApplied) != 1 || p.FixApplied[0].Package != "left-pad" || p.FixApplied[0].Branch != fix.Branch(b.ID) {
		t.Errorf("applied = %+v", p.FixApplied)
	}
	if p.FixQueued != 1 || p.Attention < 1 {
		t.Errorf("queued = %d attention = %d", p.FixQueued, p.Attention)
	}
	text, err := RenderText(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"1 fix waits for your decision:", "acme/lib ACME-1 → 1.2.5", "left-pad NPM-2: fixed in your code (branch " + fix.Branch(b.ID) + " merged). Remember to deploy.",
		"1 fix will start as soon as Michel is running."} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "SECRET-SUMMARY") || strings.Contains(text, "composer.lock") {
		t.Errorf("the digest holds the proposal's content:\n%s", text)
	}
	fr, err := RenderText(f.compute(i18n.FR, Options{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"1 correction attend ta décision", "corrigée dans ton code", "Pense à déployer", "démarrera dès que Michel sera lancé"} {
		if !strings.Contains(fr, want) {
			t.Errorf("French text lacks %q:\n%s", want, fr)
		}
	}
	page, err := RenderHTML(d)
	if err != nil || !strings.Contains(page, "Fixed in your code") || !strings.Contains(page, "acme/lib") {
		t.Errorf("html: %v\n%s", err, page)
	}
}
