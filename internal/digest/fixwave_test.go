package digest

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/i18n"
)

// TestRedecidedAfterSupersessionLeavesReview: the scan took the old decision
// out of force (severity changed), then the user decided again. The digest
// no longer lists it under the decisions to review, nor counts it.
func TestRedecidedAfterSupersessionLeavesReview(t *testing.T) {
	f := newFixture(t)
	old := now.Add(-9 * 24 * time.Hour)
	handled := f.seed(finding{pkg: "acme/lib", osv: "ACME-1", severity: "critical", status: "decided", firstSeen: old})
	open := f.seed(finding{pkg: "acme/other", osv: "ACME-2", severity: "high", status: "pending", firstSeen: old})
	f.decide(decision{finding: handled, action: "defer", due: now.Add(10 * 24 * time.Hour), superAt: now.Add(-2 * time.Hour), reason: "severity_changed"})
	f.decide(decision{finding: handled, action: "fix", created: now.Add(-time.Hour)})
	f.decide(decision{finding: open, action: "defer", due: now.Add(10 * 24 * time.Hour), superAt: now.Add(-2 * time.Hour), reason: "severity_changed"})

	d := f.compute(i18n.EN, Options{})
	p := projectNamed(t, d, "demo")
	if len(p.Superseded) != 1 || p.Superseded[0].FindingID != open {
		t.Fatalf("superseded = %+v", p.Superseded)
	}
	if p.Attention != 1 || d.AttentionTotal != 1 {
		t.Errorf("attention %d / %d", p.Attention, d.AttentionTotal)
	}
}

// TestDecidedNewFindingIsNotAttention: a new critical the user already
// decided on no longer needs attention; its package line says so.
func TestDecidedNewFindingIsNotAttention(t *testing.T) {
	f := newFixture(t)
	recent := now.Add(-2 * time.Hour)
	decided := f.seed(finding{pkg: "acme/lib", osv: "ACME-1", severity: "critical", status: "decided", firstSeen: recent})
	f.decide(decision{finding: decided, action: "fix", created: now.Add(-time.Hour)})
	f.seed(finding{pkg: "vuln-pkg", osv: "ACME-2", severity: "high", firstSeen: recent})

	for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
		d := f.compute(lang, Options{})
		p := projectNamed(t, d, "demo")
		if d.NewTotal != 2 || p.Attention != 1 || d.AttentionTotal != 1 {
			t.Errorf("%s: new %d attention %d / %d", lang, d.NewTotal, p.Attention, d.AttentionTotal)
		}
		if len(p.New) != 2 || p.New[0].Name != "acme/lib" || p.New[0].Decided != "fix" || p.New[1].Decided != "" {
			t.Errorf("%s: new = %+v", lang, p.New)
		}
		want := map[i18n.Lang]string{i18n.EN: ", 1 needs your attention", i18n.FR: ", 1 mérite ton attention"}[lang]
		if !strings.HasSuffix(d.Title, want) {
			t.Errorf("%s: title %q", lang, d.Title)
		}
		wantBody := map[i18n.Lang]string{i18n.EN: "demo: 2 new, 1 to review", i18n.FR: "demo : 2 nouveautés, 1 à revoir"}[lang]
		if _, body := ToastLines(d); body != wantBody {
			t.Errorf("%s: toast %q", lang, body)
		}
	}
}

// TestRenderJSONHasNoJustification: the generic webhook gets the JSON
// rendering; the user's justifications stay out of it.
func TestRenderJSONHasNoJustification(t *testing.T) {
	f := newFixture(t)
	old := now.Add(-40 * 24 * time.Hour)
	sup := f.seed(finding{pkg: "acme/lib", osv: "ACME-1", severity: "high", status: "pending", firstSeen: old})
	due := f.seed(finding{pkg: "acme/other", osv: "ACME-2", severity: "low", status: "decided", firstSeen: old})
	f.decide(decision{finding: sup, action: "defer", due: now.Add(time.Hour), superAt: now.Add(-time.Hour), reason: "severity_changed"})
	f.decide(decision{finding: due, action: "defer", due: now.Add(time.Hour)})
	d := f.compute(i18n.EN, Options{})
	p := projectNamed(t, d, "demo")
	if len(p.Superseded) != 1 || len(p.Due) != 1 {
		t.Fatalf("superseded %+v due %+v", p.Superseded, p.Due)
	}
	b, err := RenderJSON(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "dev only") || strings.Contains(string(b), "justification") {
		t.Errorf("json carries the justification: %s", b)
	}
}

// fileLine matches a call-site reference such as src/Billing/Invoice.php:42.
var fileLine = regexp.MustCompile(`[A-Za-z0-9_]\.[A-Za-z]+:\d+`)

// TestForChannelDropsCallSite: the page keeps the call-site example in the
// "what" sentence, the channels do not.
func TestForChannelDropsCallSite(t *testing.T) {
	f := newFixture(t)
	id := f.seed(finding{pkg: "acme/lib", osv: "ACME-1", severity: "critical", firstSeen: now.Add(-time.Hour)})
	if err := analyze.NewRepo(f.st).Save(context.Background(), analyze.Analysis{
		FindingID: id, ProjectID: f.proj.ID, ComputedAt: now, MichelVersion: "test",
		Path:    analyze.DepPath{Directness: analyze.Direct},
		Upgrade: analyze.Upgrade{Target: "1.2.5", Jump: "patch"},
		Calls:   analyze.CallSites{Sites: []analyze.CallSite{{File: "src/Billing/Invoice.php", Line: 42}}, Count: 1, Quality: "psr4"},
	}); err != nil {
		t.Fatal(err)
	}
	for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
		d := f.compute(lang, Options{})
		page := projectNamed(t, d, "demo").New[0].What
		if !strings.Contains(page, "src/Billing/Invoice.php:42") {
			t.Fatalf("%s: the page lost the example: %q", lang, page)
		}
		c := ForChannel(d)
		what := projectNamed(t, c, "demo").New[0].What
		if what == "" || fileLine.MatchString(what) || !strings.Contains(what, "acme/lib") {
			t.Errorf("%s: channel what = %q", lang, what)
		}
		text, html, js := renderAll(t, c)
		for name, out := range map[string]string{"text": text, "html": html, "json": js} {
			if fileLine.MatchString(out) || strings.Contains(out, "Invoice.php") {
				t.Errorf("%s %s carries a call site:\n%s", lang, name, out)
			}
		}
		if projectNamed(t, d, "demo").New[0].What != page {
			t.Errorf("%s: ForChannel changed its input", lang)
		}
	}
}
