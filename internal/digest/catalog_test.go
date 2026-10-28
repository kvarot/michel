package digest

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	srcreg "github.com/kvarot/michel/internal/source"
)

// catalogFixture enables the given catalog sources and records a read on
// each: result per key.
func catalogFixture(t *testing.T, f *fixture, reads map[string]string) *srcreg.Repo {
	t.Helper()
	ctx := context.Background()
	r := srcreg.NewRepo(f.st)
	if _, _, err := srcreg.Sync(ctx, r); err != nil {
		t.Fatal(err)
	}
	// The default entries (osv.packagist, osv.npm) are part of the
	// fixture only when listed.
	for _, k := range []string{"osv.packagist", "osv.npm"} {
		if _, ok := reads[k]; !ok {
			if err := r.SetEnabled(ctx, k, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	for k, result := range reads {
		if err := r.SetEnabled(ctx, k, true); err != nil {
			t.Fatal(err)
		}
		msg := ""
		if result == "error" || result == "unreachable" {
			msg = "the server answered 500"
		}
		if err := r.RecordRead(ctx, k, now.Add(-time.Hour), result, msg, 10, ""); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func allowAll(host, purpose string) bool { return true }

func TestDigestCatalogLine(t *testing.T) {
	f := newFixture(t)
	r := catalogFixture(t, f, map[string]string{"osv.npm": "ok", "enrich.kev": "error", "enrich.epss": "ok", "feed.nginx": "unreachable"})
	user, err := r.Upsert(context.Background(), srcreg.Entry{Key: "skill.demo-audit", Kind: srcreg.KindSkill, Origin: srcreg.OriginUser,
		Name: "Demo Audit", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetStatus(context.Background(), user.Key, map[string]any{"new_version": map[string]any{"from": "aaa111", "to": "bbb222"}}); err != nil {
		t.Fatal(err)
	}
	// enrich.epss waits for consent: its host has no rule.
	allowed := func(host, purpose string) bool { return host != "epss.cyentia.com" }
	d := f.compute(i18n.EN, Options{Allowed: allowed})
	c := d.Catalog
	if c.Silent || !reflect.DeepEqual(c.Failed, []string{"enrich.kev"}) || !reflect.DeepEqual(c.WaitingConsent, []string{"enrich.epss"}) ||
		!reflect.DeepEqual(c.Unreachable, []string{"feed.nginx"}) || c.Updated != 1 ||
		!reflect.DeepEqual(c.NewVersions, []NewVersion{{Key: "skill.demo-audit", Name: "Demo Audit", From: "aaa111", To: "bbb222"}}) {
		t.Fatalf("catalog = %+v", c)
	}
	if !c.UpdatedAt.Equal(now.Add(-time.Hour)) {
		t.Errorf("updated at = %v", c.UpdatedAt)
	}
	text, err := RenderText(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Catalog: 1 source up to date, enrich.kev could not be read, feed.nginx unreachable, enrich.epss waits for your consent, new version of Demo Audit.",
		"Demo Audit: aaa111 → bbb222", "Michel used the previous data"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	html, err := RenderHTML(f.compute(i18n.FR, Options{Allowed: allowed}))
	if err != nil || !strings.Contains(html, "Catalogue : 1 source à jour, enrich.kev n&#39;a pas pu être lue") {
		t.Errorf("html: %v\n%s", err, html)
	}
	if run := RunOf(d, now); run.Summary["catalog_failed"] != 2 {
		t.Errorf("summary = %v", run.Summary)
	}

	// Everything read and nothing new: the catalog says nothing.
	g := newFixture(t)
	catalogFixture(t, g, map[string]string{"osv.npm": "ok", "enrich.kev": "ok"})
	d = g.compute(i18n.EN, Options{Allowed: allowAll})
	if !d.Catalog.Silent || d.Catalog.Updated != 2 {
		t.Errorf("all ok: %+v", d.Catalog)
	}
	if text, _ := RenderText(d); strings.Contains(text, "Catalog") {
		t.Errorf("silent catalog rendered:\n%s", text)
	}
}

func TestSupersededChainListsOnlyLatest(t *testing.T) {
	f := newFixture(t)
	old := now.Add(-9 * 24 * time.Hour)
	id := f.seed(finding{pkg: "acme/lib", osv: "ACME-1", severity: "high", status: "pending", firstSeen: old})
	// A (defer) is superseded, then B (fix) is decided and superseded too,
	// all within the window.
	f.decide(decision{finding: id, action: "defer", due: now.Add(10 * 24 * time.Hour), created: old, superAt: now.Add(-3 * time.Hour), reason: "severity_changed"})
	f.decide(decision{finding: id, action: "fix", created: now.Add(-2 * time.Hour), superAt: now.Add(-time.Hour), reason: "kev_changed"})
	p := projectNamed(t, f.compute(i18n.EN, Options{}), "demo")
	if len(p.Superseded) != 1 || p.Superseded[0].PreviousAction != "fix" || p.Superseded[0].Reason != "kev_changed" {
		t.Fatalf("superseded = %+v", p.Superseded)
	}
	if p.Attention != 1 {
		t.Errorf("attention = %d", p.Attention)
	}
}
