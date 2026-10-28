package explain

import (
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/scan"
)

func sampleFacts() Facts {
	return Facts{
		Package: "acme/lib", Ecosystem: "Packagist", OSVID: "GHSA-1", Summary: "Path traversal in acme/lib",
		SeverityLabel: "high", Installed: "1.2.0", Target: "1.2.5", Jump: analyze.JumpPatch,
		Directness: analyze.Direct, CallSiteCount: 2, CallSitesQuality: "psr4", TestCount: 1, TestMethod: "callsite",
		ChangelogAvailable: true, Risk: analyze.Risk{Score: 10, Recommendation: analyze.RecAutoFix},
		Certainty: "high", HasAnalysis: true, Example: "src/Foo.php:12", Constraint: "^1.2",
		ConstraintKnown: true, ConstraintOK: true, FixLevel: 2,
	}
}

func mustRender(t *testing.T, l Lang, f Facts) Explanation {
	t.Helper()
	e, err := Render(l, f)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func has(t *testing.T, label, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("%s lacks %q:\n%s", label, w, got)
		}
	}
}

func TestRenderEnglishThreeSentences(t *testing.T) {
	e := mustRender(t, EN, sampleFacts())
	has(t, "what", e.What, "acme/lib 1.2.0 is used in 2 places in your code, for example src/Foo.php:12.", `The advisory says: "Path traversal in acme/lib"`)
	has(t, "impact", e.Impact, "This flaw is serious.", "Michel is fairly sure it matters to you.")
	has(t, "cost", e.Cost, "A small patch update (1.2.0 → 1.2.5).", "No breaking change found in the changelog.",
		"1 test file covers the code that uses it.", "Michel can try this fix for you (level 2: automatic fix, to be approved).", "Constraint allows it")
}

func TestRenderFrenchThreeSentences(t *testing.T) {
	e := mustRender(t, FR, sampleFacts())
	has(t, "what", e.What, "2 endroits de ton code", "par exemple src/Foo.php:12", "L'avis dit")
	has(t, "impact", e.Impact, "Cette faille est grave.", "Michel est plutôt sûr")
	has(t, "cost", e.Cost, "petite mise à jour corrective", "Aucun changement incompatible", "1 fichier de test couvre",
		"Michel peut tenter cette correction", "Ta contrainte l'autorise")
}

func TestRenderTransitiveBlockedBreaking(t *testing.T) {
	f := sampleFacts()
	f.Directness, f.Via = analyze.Transitive, []string{"vendor/parent", "x/y"}
	f.Breaking, f.BreakingLines = true, []string{"BREAKING: a", "BREAKING: b"}
	f.TestCount, f.ConstraintOK, f.Constraint = 0, false, "~1.2.0"
	f.Jump, f.Risk.Recommendation = analyze.JumpMajor, analyze.RecHandoff
	e := mustRender(t, EN, f)
	has(t, "impact", e.Impact, "It reaches you through vendor/parent.")
	has(t, "cost", e.Cost, "A major update that may change how the package works", "2 breaking changes mentioned",
		"No test covers that code.", "Best handed to you", "Your constraint (~1.2.0) blocks it")
	e = mustRender(t, FR, f)
	has(t, "impact", e.Impact, "Elle te parvient via vendor/parent.")
	has(t, "cost", e.Cost, "mise à jour majeure", "2 changements incompatibles signalés", "Aucun test ne couvre", "Ta contrainte (~1.2.0) la bloque")
}

func TestRenderUnknownJumpIsHonest(t *testing.T) {
	f := sampleFacts()
	f.Jump = analyze.JumpUnknown
	has(t, "en", mustRender(t, EN, f).Cost, "could not tell how big the update is")
	has(t, "fr", mustRender(t, FR, f).Cost, "n'a pas pu mesurer l'ampleur")
}

func TestRenderNoFix(t *testing.T) {
	f := sampleFacts()
	f.Target, f.Jump, f.Risk.Recommendation = "", analyze.JumpNone, analyze.RecReportOnly
	e := mustRender(t, EN, f)
	has(t, "en", e.Cost, "No fixed version exists yet: nothing to update, keep watching.")
	if strings.Contains(e.Cost, "Nothing to update for now") {
		t.Errorf("no-fix cost repeats itself: %s", e.Cost)
	}
	if strings.Contains(e.Cost, "changelog") || strings.Contains(e.Cost, "Constraint") {
		t.Errorf("no-fix cost mentions an upgrade: %s", e.Cost)
	}
	has(t, "fr", mustRender(t, FR, f).Cost, "Aucune version corrigée n'existe encore")
}

func TestRenderCallSiteWordings(t *testing.T) {
	f := sampleFacts()
	f.CallSiteCount, f.Example, f.CallSitesQuality, f.Certainty = 0, "", "name", "medium"
	has(t, "name", mustRender(t, EN, f).What, "was not found in your code (searched by name only).")
	has(t, "name fr", mustRender(t, FR, f).What, "recherche par le nom seulement")
	has(t, "medium", mustRender(t, EN, f).Impact, "Michel is not sure it matters to you.")
	f.CallSitesQuality, f.Certainty = "low", "low"
	has(t, "low", mustRender(t, EN, f).What, "search not possible: dependency files are not installed locally")
	has(t, "low", mustRender(t, EN, f).Impact, "Michel could not check whether it matters to you.")
	f.CallSiteCount, f.CallSitesQuality = 1, "import"
	has(t, "one", mustRender(t, EN, f).What, "used in 1 place in your code")
}

func TestRenderWithoutAnalysis(t *testing.T) {
	fi := scan.Finding{Package: "p", Ecosystem: "npm", InstalledVersion: "1.0.0", FixedVersions: []string{"1.0.2"}, SeverityLabel: "critical"}
	f := FactsFrom(fi, analyze.Analysis{}, false)
	if f.Certainty != "low" || f.Target != "1.0.2" {
		t.Fatalf("facts = %+v", f)
	}
	e := mustRender(t, EN, f)
	has(t, "what", e.What, "has not been searched for in your code yet")
	has(t, "impact", e.Impact, "could let an attacker take control", "has not checked yet")
	has(t, "cost", e.Cost, "A small patch update (1.0.0 → 1.0.2).")
}

func TestSummaryTruncated(t *testing.T) {
	fi := scan.Finding{Package: "p", Summary: strings.Repeat("é", 400)}
	if n := len([]rune(FactsFrom(fi, analyze.Analysis{}, false).Summary)); n > 163 {
		t.Errorf("summary has %d runes", n)
	}
}

func TestCertainty(t *testing.T) {
	for _, tc := range []struct {
		q      string
		tests  int
		method string
		want   string
	}{{"psr4", 1, "callsite", "high"}, {"import", 2, "callsite", "high"}, {"psr4", 2, "reference", "medium"},
		{"psr4", 0, "none", "medium"}, {"name", 3, "callsite", "medium"}, {"low", 3, "callsite", "low"},
		{"noautoload", 1, "callsite", "low"}, {"", 0, "", "low"}} {
		a := analyze.Analysis{}
		a.Calls.Quality, a.Coverage.Count, a.Coverage.Method = tc.q, tc.tests, tc.method
		if got := FactsFrom(scan.Finding{}, a, true).Certainty; got != tc.want {
			t.Errorf("%s/%d: %s, want %s", tc.q, tc.tests, got, tc.want)
		}
	}
}

func TestRenderNeverContainsAbsolutePath(t *testing.T) {
	a := analyze.Analysis{}
	a.Calls.Count, a.Calls.Quality = 1, "psr4"
	a.Calls.Sites = []analyze.CallSite{{File: `E:\work\proj\src\Foo.php`, Line: 3}}
	for _, l := range []Lang{EN, FR} {
		e := mustRender(t, l, FactsFrom(scan.Finding{Package: "p"}, a, true))
		all := e.What + e.Impact + e.Cost
		if strings.Contains(all, `E:`) || strings.Contains(all, `work`) || strings.Contains(all, `\`) {
			t.Errorf("%s: absolute path leaked: %s", l, all)
		}
	}
	a.Calls.Sites[0].File = "/srv/work/proj/src/Foo.php"
	if e := mustRender(t, EN, FactsFrom(scan.Finding{Package: "p"}, a, true)); strings.Contains(e.What, "/srv") {
		t.Errorf("leak: %s", e.What)
	}
}

func TestAllTemplatesRenderInBothLanguages(t *testing.T) {
	for _, l := range []Lang{EN, FR} {
		for _, n := range []string{"what", "impact", "cost"} {
			s, err := renderOne(l, n, sampleFacts())
			if err != nil || s == "" || strings.HasSuffix(s, "\n") {
				t.Errorf("%s/%s: %q %v", l, n, s, err)
			}
		}
	}
	if _, err := renderOne(EN, "nope", Facts{}); err == nil {
		t.Error("missing template must fail")
	}
	if _, err := Render("de", Facts{}); err == nil {
		t.Error("unsupported language must fail")
	}
}

func TestGlossaryBothLangs(t *testing.T) {
	for _, l := range []Lang{EN, FR} {
		for _, k := range Terms() {
			if Term(l, k) == "" {
				t.Errorf("%s/%s missing", l, k)
			}
		}
	}
	if Term(EN, "nope") != "" {
		t.Error("unknown key must be empty")
	}
}

func TestWhatSentenceForMaliciousPackage(t *testing.T) {
	f := FactsFrom(scan.Finding{Package: "vuln-pkg", Ecosystem: "npm", OSVID: "MAL-2024-0001", SeverityLabel: "critical",
		InstalledVersion: "1.0.0", Malicious: true}, analyze.Analysis{}, false)
	if !f.Malicious {
		t.Fatal("FactsFrom lost Malicious")
	}
	has(t, "fr what", mustRender(t, FR, f).What, "paquet malveillant", "vuln-pkg 1.0.0")
	has(t, "en what", mustRender(t, EN, f).What, "malicious package", "vuln-pkg 1.0.0")
	if w := mustRender(t, EN, sampleFacts()).What; strings.Contains(w, "malicious") {
		t.Errorf("a plain flaw is called malicious: %s", w)
	}
}
