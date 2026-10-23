package digest

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/project"
)

// renderAll returns the three renderings of d.
func renderAll(t *testing.T, d Digest) (text, html, js string) {
	t.Helper()
	text, err := RenderText(d)
	if err != nil {
		t.Fatal(err)
	}
	html, err = RenderHTML(d)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RenderJSON(d)
	if err != nil {
		t.Fatal(err)
	}
	return text, html, string(b)
}

func TestRenderTextHasNoAbsolutePathNorCommand(t *testing.T) {
	f := newFixture(t)
	p := f.addProject("project-a", project.Project{TestCmd: "make check-everything-now", InstallCmd: "composer install-all-the-things"})
	recent := now.Add(-time.Hour)
	f.seed(finding{project: p.ID, pkg: "acme/lib", osv: "ACME-1", severity: "critical", firstSeen: recent})
	gone := f.seed(finding{project: p.ID, pkg: "vuln-pkg", osv: "ACME-2", severity: "high", status: "gone", firstSeen: recent, changed: recent})
	deferred := f.seed(finding{project: p.ID, pkg: "acme/other", osv: "ACME-3", severity: "high", status: "decided", firstSeen: recent.Add(-48 * time.Hour)})
	f.decide(decision{finding: deferred, action: "defer", due: now.Add(time.Hour)})
	f.decide(decision{finding: gone, action: "fix", superAt: recent, reason: "severity_changed"})
	for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
		d := f.compute(lang, Options{PageURL: "http://127.0.0.1:8765/today"})
		text, html, js := renderAll(t, d)
		for name, out := range map[string]string{"text": text, "html": html, "json": js} {
			for _, bad := range []string{p.Path, filepath.ToSlash(p.Path), f.proj.Path, p.TestCmd, p.InstallCmd,
				"composer.lock", `:\`, "test_cmd", "install_cmd"} {
				if strings.Contains(out, bad) {
					t.Errorf("%s %s contains %q:\n%s", lang, name, bad, out)
				}
			}
			for _, want := range []string{"acme/lib", "ACME-1", "vuln-pkg", "acme/other", "ACME-3"} {
				if !strings.Contains(out, want) {
					t.Errorf("%s %s lacks %q:\n%s", lang, name, want, out)
				}
			}
		}
		if !strings.HasPrefix(js, `{"michel_digest":1,`) || strings.Contains(js, "proven_fixed") || strings.Contains(js, "reported_fixed") {
			t.Errorf("json = %s", js)
		}
		var back map[string]any
		if err := json.Unmarshal([]byte(js), &back); err != nil || back["title"] != d.Title || back["page_url"] != d.PageURL {
			t.Errorf("json does not read back: %v %v", err, back)
		}
		if !strings.HasPrefix(text, d.Title+"\n") || !strings.Contains(text, "== project-a ==") || !strings.HasSuffix(text, "http://127.0.0.1:8765/today\n") {
			t.Errorf("%s text layout:\n%s", lang, text)
		}
	}
	text, _, _ := renderAll(t, f.compute(i18n.EN, Options{}))
	for _, want := range []string{
		"open: 2 (critical 1, high 1, medium 0, low 0)",
		"decided: fix 0, defer 1, ignore 0",
		"  [critical] acme/lib 1.0.0 → 1.2.5 (1 advisory: ACME-1)\n    acme/lib 1.0.0 has not been searched for in your code yet.",
		"  [high] vuln-pkg 1.0.0 → 1.2.5 (1 advisory: ACME-2)",
		"  vuln-pkg ACME-2: was to be fixed, the severity changed",
		"  acme/other ACME-3: deferred until 2026-10-23\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("en text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Page:") {
		t.Errorf("a page line without page url:\n%s", text)
	}
}

func TestRenderHTMLHasNoScriptNorImg(t *testing.T) {
	f := newFixture(t)
	f.seed(finding{pkg: `<script>alert(1)</script>`, osv: `ACME-"><img src=x>`, severity: "high", firstSeen: now.Add(-time.Hour)})
	page := "http://127.0.0.1:8765/today"
	for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
		d := f.compute(lang, Options{PageURL: page})
		d.OSVStale, d.OSVFetchedAt = true, now.Add(-10*24*time.Hour)
		html, err := RenderHTML(d)
		if err != nil {
			t.Fatal(err)
		}
		low := strings.ToLower(html)
		for _, bad := range []string{"<script", "<img", "javascript:", "<link", "@import", "url("} {
			if strings.Contains(low, bad) {
				t.Errorf("%s html contains %q:\n%s", lang, bad, html)
			}
		}
		if strings.Count(low, "http") != strings.Count(html, page) || !strings.Contains(html, `href="`+page+`"`) {
			t.Errorf("%s html links somewhere else than the page:\n%s", lang, html)
		}
		if !strings.Contains(html, "<style>") || !strings.Contains(html, "<h1>") || !strings.Contains(html, "&lt;script&gt;") {
			t.Errorf("%s html structure:\n%s", lang, html)
		}
		text, err := RenderText(d)
		if err != nil {
			t.Fatal(err)
		}
		want := map[i18n.Lang]string{i18n.EN: "the vulnerability database is 10 days old", i18n.FR: "la base des failles date de 10 jours"}[lang]
		if !strings.Contains(text, want) || !strings.Contains(html, want) {
			t.Errorf("%s stale banner %q missing:\n%s\n%s", lang, want, text, html)
		}
	}
}

func TestToastLines(t *testing.T) {
	f := newFixture(t)
	empty := f.compute(i18n.EN, Options{})
	if title, body := ToastLines(empty); title != empty.Title || body != "" {
		t.Errorf("empty: %q %q", title, body)
	}
	quiet := f.addProject("project-a", project.Project{})
	recent := now.Add(-time.Hour)
	f.seed(finding{project: quiet.ID, pkg: "acme/low", osv: "ACME-9", severity: "low", firstSeen: recent})
	f.seed(finding{pkg: "acme/lib", osv: "ACME-1", severity: "critical", firstSeen: recent})
	f.seed(finding{pkg: "acme/lib", osv: "ACME-2", severity: "low", firstSeen: recent})
	en := f.compute(i18n.EN, Options{})
	if title, body := ToastLines(en); title != en.Title || body != "demo: 2 new, 1 to review" {
		t.Errorf("en: %q %q", title, body)
	}
	fr := f.compute(i18n.FR, Options{})
	if title, body := ToastLines(fr); title != fr.Title || body != "demo : 2 nouveautés, 1 à revoir" {
		t.Errorf("fr: %q %q", title, body)
	}
	long := en
	long.Projects = append([]ProjectDigest{}, en.Projects...)
	for i := range long.Projects {
		long.Projects[i].Name = strings.Repeat("é", 300)
	}
	if _, body := ToastLines(long); utf8.RuneCountInString(body) > 200 || !utf8.ValidString(body) || body == "" {
		t.Errorf("long body: %d runes", utf8.RuneCountInString(body))
	}
}
