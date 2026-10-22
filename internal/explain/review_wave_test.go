package explain

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/scan"
)

func TestUnknownJumpNeverOffersAutomaticFix(t *testing.T) {
	f := sampleFacts() // stored as auto_fix, as an analysis made before the rule
	f.Jump = analyze.JumpUnknown
	for _, l := range []Lang{EN, FR} {
		c := mustRender(t, l, f).Cost
		for _, bad := range []string{"can try this fix", "peut tenter cette correction", "level 2;", "niveau 2 ;"} {
			if strings.Contains(c, bad) {
				t.Errorf("%s: unknown jump offers a fix: %s", l, c)
			}
		}
	}
	has(t, "en", mustRender(t, EN, f).Cost, "Best handed to you")
	has(t, "fr", mustRender(t, FR, f).Cost, "À faire par toi")
}

func TestAutoFixSentenceDependsOnFixLevel(t *testing.T) {
	f := sampleFacts()
	f.FixLevel = 1
	has(t, "en low", mustRender(t, EN, f).Cost,
		"Michel could fix this automatically at level 2; this project is at level 1, so it stays a proposal.")
	has(t, "fr low", mustRender(t, FR, f).Cost,
		"Michel pourrait corriger ça automatiquement au niveau 2 ; ce projet est au niveau 1, donc ça reste une proposition.")
	for _, lvl := range []int{2, 3} {
		f.FixLevel = lvl
		has(t, "en high", mustRender(t, EN, f).Cost, "Michel can try this fix for you (level 2: automatic fix, to be approved).")
		has(t, "fr high", mustRender(t, FR, f).Cost, "Michel peut tenter cette correction pour toi (niveau 2 : correction automatique, à valider).")
	}
}

func TestNoAutoloadWording(t *testing.T) {
	f := sampleFacts()
	f.CallSitesQuality, f.CallSiteCount, f.Example, f.Certainty = "noautoload", 0, "", "low"
	has(t, "en", mustRender(t, EN, f).What, "(search not possible: the package has no namespace to look for)")
	has(t, "fr", mustRender(t, FR, f).What, "(recherche impossible : le paquet n'a pas d'espace de noms à chercher)")
	if Enum(EN, "quality", "noautoload") == Label(EN, "unknown") || Enum(FR, "quality", "noautoload") == Label(FR, "unknown") {
		t.Error("noautoload has no plain word")
	}
}

func TestChangelogWithoutVersionsIsNotAssessed(t *testing.T) {
	a := analyze.Analysis{}
	a.Upgrade.Target, a.Upgrade.Jump = "2.0.0", analyze.JumpMajor
	a.Changelog = analyze.Changelog{Available: true, Excerpt: "text", Note: analyze.NoteNoVersionHeadings}
	f := FactsFrom(scan.Finding{Package: "p", InstalledVersion: "1.0.0"}, a, true)
	if !f.ChangelogVersionsUnread {
		t.Fatal("versions-unread flag lost")
	}
	en, fr := mustRender(t, EN, f).Cost, mustRender(t, FR, f).Cost
	has(t, "en", en, "Changelog found but its versions could not be read; breaking changes not assessed.")
	has(t, "fr", fr, "Journal des modifications trouvé mais ses versions sont illisibles ; changements incompatibles non évalués.")
	if strings.Contains(en, "No breaking change found") || strings.Contains(fr, "Aucun changement incompatible") {
		t.Errorf("an unread changelog must not claim no breaking change: %s / %s", en, fr)
	}
}

func TestRiskTermsArePlainWords(t *testing.T) {
	terms := map[string]int{"major_jump": 40, "no_tests": 20, "direct": 10, "breaking": 0,
		"many_call_sites": 0, "core_package": 0, "major_jump_unknown": 0, "jump_unknown_handoff": 1}
	en := RiskTerms(EN, terms)
	if !strings.HasPrefix(en, "major update +40, no covering test +20, direct dependency +10") ||
		!strings.Contains(en, "update size unknown") {
		t.Errorf("en: %s", en)
	}
	fr := RiskTerms(FR, terms)
	if !strings.HasPrefix(fr, "mise à jour majeure +40, aucun test qui couvre +20, dépendance directe +10") {
		t.Errorf("fr: %s", fr)
	}
	for _, s := range []string{en, fr, RiskTerms(EN, nil), RiskTerms(FR, map[string]int{"thresholds_fallback": 1})} {
		for _, raw := range []string{"no_tests", "major_jump", "_", "+0"} {
			if strings.Contains(s, raw) {
				t.Errorf("raw %q in %q", raw, s)
			}
		}
	}
	if RiskWarning(EN, 60) != "Warning: risk above 60, review carefully." ||
		RiskWarning(FR, 60) != "Attention : risque au-dessus de 60, à examiner avec soin." {
		t.Errorf("warning lines: %q / %q", RiskWarning(EN, 60), RiskWarning(FR, 60))
	}
}

func TestFactsStripControlCharacters(t *testing.T) {
	fi := scan.Finding{Package: "evil\x1b]0;x\x07/pkg", OSVID: "ID\x1b[2K", InstalledVersion: "1.0.0",
		ManifestRelPath: "a\x1b[2K/composer.lock", Summary: "bad\x1b[31m summary"}
	a := analyze.Analysis{}
	a.Path = analyze.DepPath{Directness: analyze.Transitive, Via: []string{"via\x1b]0;t\x07"}}
	a.Changelog.BreakingLines = []string{"BREAKING\x1b[2K"}
	a.Calls.Sites = []analyze.CallSite{{File: "src/\x1b[2KA.php", Line: 3}}
	f := FactsFrom(fi, a, true)
	b, _ := json.Marshal(f)
	for _, s := range []string{f.Package, f.OSVID, f.ManifestRelPath, f.Summary, f.Via[0], f.BreakingLines[0], f.Example} {
		if strings.ContainsAny(s, "\x1b\x07") {
			t.Errorf("control characters kept: %q", s)
		}
	}
	if strings.Contains(string(b), `\u001b`) {
		t.Errorf("JSON keeps escapes: %s", b)
	}
}

func TestFactsAndAnalysisJSONAreSnakeCase(t *testing.T) {
	b, err := json.Marshal(sampleFacts())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"package", "osv_id", "call_sites_quality", "test_method", "changelog_versions_unread", "fix_level", "certainty", "risk"} {
		if _, ok := m[k]; !ok {
			t.Errorf("facts JSON lacks %q: %s", k, b)
		}
	}
	a := analyze.Analysis{FindingID: "f1"}
	a.Calls.Sites = []analyze.CallSite{{File: "a.php", Line: 1, Snippet: "secret code"}}
	b, _ = json.Marshal(a)
	for _, want := range []string{`"finding_id":"f1"`, `"calls":{"sites":[{"file":"a.php","line":1,"is_test":false}]`, `"inputs_hash"`, `"changelog":{"source"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("analysis JSON lacks %s: %s", want, b)
		}
	}
	if strings.Contains(string(b), "secret code") || strings.Contains(string(b), "FindingID") {
		t.Errorf("analysis JSON leaks a snippet or a Go name: %s", b)
	}
}
