package digest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/workcopy"
)

func TestDigestSaysAHeldFixWaitsForAnAnswer(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id := f.seed(finding{pkg: "acme/lib", osv: "ACME-1", severity: "high", firstSeen: now.Add(-10 * 24 * time.Hour)})
	repo := fix.NewRepo(f.st)
	repo.Now = func() time.Time { return now.Add(-time.Hour) }
	a, err := repo.CreateAttempt(ctx, fix.Attempt{FindingID: id, ProjectID: f.proj.ID, Origin: fix.OriginAgentAuto})
	if err != nil {
		t.Fatal(err)
	}
	w := fix.Work{HoldSum: "sum", Copy: workcopy.Copy{SecretHits: []mask.Hit{{File: "src/private-config.php", Line: 2, Kind: mask.KindAWSKey, Strong: true}}}}
	if err := repo.SetWork(ctx, a.ID, w); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetState(ctx, a.ID, []fix.State{fix.StatePreparing}, fix.StateHeld, ""); err != nil {
		t.Fatal(err)
	}
	d := f.compute(i18n.EN, Options{})
	p := projectNamed(t, d, "demo")
	if len(p.FixHeld) != 1 || p.FixHeld[0].Package != "acme/lib" || p.FixHeld[0].OSVID != "ACME-1" || len(p.FixWaiting) != 0 {
		t.Fatalf("held %+v waiting %+v", p.FixHeld, p.FixWaiting)
	}
	if p.Attention < 1 {
		t.Errorf("attention = %d", p.Attention)
	}
	text, err := RenderText(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "1 fix waits for your answer: possible keys in the code") || !strings.Contains(text, "acme/lib ACME-1") {
		t.Errorf("text:\n%s", text)
	}
	fr, err := RenderText(f.compute(i18n.FR, Options{}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fr, "1 correction attend ta réponse : des clés possibles dans le code") {
		t.Errorf("French text:\n%s", fr)
	}
	page, err := RenderHTML(d)
	if err != nil || !strings.Contains(page, "waits for your answer") {
		t.Errorf("html: %v\n%s", err, page)
	}
	frPage, err := RenderHTML(f.compute(i18n.FR, Options{}))
	if err != nil || !strings.Contains(frPage, "attend ta réponse") {
		t.Errorf("French html: %v\n%s", err, frPage)
	}
	// The package and the flaw id only: no file name.
	for _, out := range []string{text, fr, page, frPage} {
		if strings.Contains(out, "private-config") {
			t.Errorf("the digest names a file:\n%s", out)
		}
	}
}
