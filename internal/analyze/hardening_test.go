package analyze

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
)

// Tests of the final review wave: heuristics (B*) and untrusted input (C*).

func TestSingleSegmentNamespaceNeedsCodeContext(t *testing.T) {
	cases := []struct {
		line, ns string
		want     bool
	}{
		{`$view = 'x.html.twig';`, "twig", false},
		{`use Twig\Environment;`, "twig", true},
		{`new \Monolog\Logger('app');`, "monolog", true},
		{`// see Monolog docs`, "monolog", false},
		{`$x = Twig::VERSION;`, "twig", true},
		{`class A extends Twig {}`, "twig", true},
		{`$twig->render();`, "twig", false},
		{`use Acme\Vuln\Client;`, `acme\vuln`, true}, // multi-segment rule unchanged
	}
	for _, c := range cases {
		if got := lineHasNamespace(strings.ToLower(c.line), []string{c.ns}); got != c.want {
			t.Errorf("lineHasNamespace(%q, %q) = %v, want %v", c.line, c.ns, got, c.want)
		}
	}
}

func TestPhpSearchSkipsTwigTemplates(t *testing.T) {
	root := writeTree(t, map[string]string{
		"composer.lock":                  "{}",
		"vendor/twig/twig/composer.json": `{"autoload":{"psr-4":{"Twig\\":"src/"}}}`,
		"src/Render.php":                 "<?php\nuse Twig\\Environment;\n$v = 'page.html.twig';\n",
		"templates/page.html.twig":       "{# Twig\\Environment is used by Twig::render #}\n",
		"templates/partials/menu.twig":   "use Twig\\Environment;\n",
	})
	cs, err := FindCallSites(root, "composer.lock", "composer", "twig/twig", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Quality != "psr4" || cs.Count != 1 || cs.Sites[0].File != "src/Render.php" || cs.Sites[0].Line != 2 {
		t.Fatalf("%+v", cs)
	}
}

func TestCallSitesSkipFrameworkCaches(t *testing.T) {
	root := writeTree(t, map[string]string{
		"composer.lock":                      "{}",
		"vendor/acme/vuln/composer.json":     acmeAutoload,
		"src/A.php":                          useClient,
		"var/cache/prod/Container.php":       useClient,
		"storage/framework/views/x.php":      useClient,
		"bootstrap/cache/services.php":       useClient,
		".phpunit.cache/code-coverage/a.php": useClient,
		"lib/var/notcache/B.php":             useClient,
	})
	cs, err := FindCallSites(root, "composer.lock", "composer", "acme/vuln", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Count != 2 {
		t.Fatalf("want src/A.php and lib/var/notcache/B.php only: %+v", cs.Sites)
	}
	for _, s := range cs.Sites {
		if s.File != "src/A.php" && s.File != "lib/var/notcache/B.php" {
			t.Errorf("cache file searched: %s", s.File)
		}
	}
}

func TestPhpInstalledWithoutAutoloadIsNoAutoload(t *testing.T) {
	root := writeTree(t, map[string]string{
		"composer.lock":                  "{}",
		"vendor/acme/vuln/composer.json": `{"name":"acme/vuln","autoload":{"classmap":["lib/"]}}`,
		"src/A.php":                      useClient,
	})
	cs, err := FindCallSites(root, "composer.lock", "composer", "acme/vuln", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Quality != "noautoload" || cs.Count != 0 {
		t.Fatalf("%+v", cs)
	}
	// Not installed at all: the name guess still runs.
	os.RemoveAll(filepath.Join(root, "vendor"))
	cs, _ = FindCallSites(root, "composer.lock", "composer", "acme/vuln", nil)
	if cs.Quality != "name" || cs.Count != 1 {
		t.Fatalf("not installed: %+v", cs)
	}
}

func TestVendorNamespacesRefusesBadNamesAndHugeFiles(t *testing.T) {
	root := writeTree(t, map[string]string{
		"composer.lock":                  "{}",
		"vendor/acme/vuln/composer.json": `{"autoload":{"psr-4":{"Acme\\Vuln\\":"src/"}}}` + strings.Repeat(" ", maxComposerJSON),
	})
	if _, _, st := vendorNamespaces(root, "acme/vuln"); st != vendorMissing {
		t.Errorf("composer.json over 1 MiB must be ignored, state %v", st)
	}
	for _, bad := range []string{"../acme/vuln", `acme\vuln`, "/etc", "c:/x", ""} {
		if _, _, st := vendorNamespaces(root, bad); st != vendorMissing {
			t.Errorf("%q: state %v", bad, st)
		}
	}
}

// symlinkOrSkip creates link -> target, or skips when the OS refuses (Windows
// without the privilege).
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks not permitted here: %v", err)
		}
		t.Fatal(err)
	}
}

func TestVendorSymlinksAreRefused(t *testing.T) {
	outside := writeTree(t, map[string]string{
		"composer.json": `{"autoload":{"psr-4":{"Acme\\Vuln\\":"src/"}}}`,
		"CHANGELOG.md":  "## 2.0.0\n- BREAKING: secret\n",
	})
	root := writeTree(t, map[string]string{"composer.lock": "{}", "src/A.php": useClient})
	symlinkOrSkip(t, outside, filepath.Join(root, "vendor", "acme", "vuln"))

	if _, _, st := vendorNamespaces(root, "acme/vuln"); st != vendorMissing {
		t.Errorf("linked package folder must be refused, state %v", st)
	}
	cl := ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "2.0.0")
	if cl.Available || cl.Excerpt != "" || !strings.Contains(cl.Note, "refused") {
		t.Errorf("linked package folder changelog: %+v", cl)
	}

	// A real folder holding a linked composer.json and changelog.
	root2 := writeTree(t, map[string]string{"composer.lock": "{}", "vendor/acme/vuln/README.md": "x"})
	dir := filepath.Join(root2, "vendor", "acme", "vuln")
	symlinkOrSkip(t, filepath.Join(outside, "composer.json"), filepath.Join(dir, "composer.json"))
	symlinkOrSkip(t, filepath.Join(outside, "CHANGELOG.md"), filepath.Join(dir, "CHANGELOG.md"))
	if _, _, st := vendorNamespaces(root2, "acme/vuln"); st != vendorMissing {
		t.Errorf("linked composer.json must be refused, state %v", st)
	}
	cl = ReadChangelog(root2, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "2.0.0")
	if cl.Available || strings.Contains(cl.Excerpt, "secret") {
		t.Errorf("linked changelog must not be read: %+v", cl)
	}
}

func TestChangelogSetextOnlyIsNotAssessed(t *testing.T) {
	root := setupChangelogBytes(t, []byte("Changelog\n=========\n\n2.0.0\n-----\n\n- Breaking: removed the old API\n\n1.0.0\n-----\n\n- First\n"), "CHANGELOG.md")
	cl := ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "2.0.0")
	if !cl.Available || !cl.VersionsUnread() || cl.Breaking || cl.BreakingLines != nil || !strings.Contains(cl.Excerpt, "removed the old API") {
		t.Fatalf("%+v", cl)
	}
}

func TestChangelogLevel3AndLeadWordHeadings(t *testing.T) {
	level3 := "# Changelog\n\n### 2.0.0\n- Removed the legacy client\n\n### 1.5.0\n- Added a flag\n\n### 1.0.0\n- First\n"
	root := setupChangelogBytes(t, []byte(level3), "CHANGELOG.md")
	cl := ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "2.0.0")
	if cl.VersionsUnread() || !cl.Breaking || !strings.Contains(cl.Excerpt, "Added a flag") || strings.Contains(cl.Excerpt, "First") {
		t.Fatalf("### headings: %+v", cl)
	}

	words := "# Changelog\n\n## Version 2.0.0\n- No longer supports PHP 7\n\n## Release 1.5.0\n- Added\n\n## v. 1.0.0\n- First\n"
	root = setupChangelogBytes(t, []byte(words), "CHANGELOG.md")
	cl = ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "2.0.0")
	if cl.VersionsUnread() || !cl.Breaking || !strings.Contains(cl.Excerpt, "## Release 1.5.0") || strings.Contains(cl.Excerpt, "First") {
		t.Fatalf("## Version headings: %+v", cl)
	}

	// Level 1-2 version headings win: ### stays a sub-heading.
	mixed := "## 2.0.0\n### 1.9.9 notes\n- Fix\n\n## 1.0.0\n- First\n"
	root = setupChangelogBytes(t, []byte(mixed), "CHANGELOG.md")
	cl = ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.5.0", "2.0.0")
	if !strings.Contains(cl.Excerpt, "1.9.9 notes") {
		t.Fatalf("### under ## must stay in the section: %+v", cl)
	}
}

func TestChangelogStripsTerminalControls(t *testing.T) {
	body := "## 2.0.0\n- BREAKING: renamed\x1b]0;owned\x07 the client\x1b[2K\n\n## 1.0.0\n- First\n"
	root := setupChangelogBytes(t, []byte(body), "CHANGELOG.md")
	cl := ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "2.0.0")
	if !cl.Breaking || len(cl.BreakingLines) != 1 {
		t.Fatalf("%+v", cl)
	}
	for _, s := range append([]string{cl.Excerpt}, cl.BreakingLines...) {
		if strings.ContainsAny(s, "\x1b\x07") {
			t.Errorf("control characters kept: %q", s)
		}
	}
}

func TestReferenceCoverageDoesNotCancelNoTests(t *testing.T) {
	ref := ScoreRisk(cfg(), nil, RiskInput{Jump: JumpPatch, TestCount: 2, TestMethod: "reference", HasFix: true})
	if ref.Terms["no_tests"] != 20 || ref.Score != 20 {
		t.Fatalf("reference: %+v", ref)
	}
	use := ScoreRisk(cfg(), nil, RiskInput{Jump: JumpPatch, TestCount: 2, TestMethod: "callsite", HasFix: true})
	if use.Terms["no_tests"] != 0 || use.Score != 0 || use.Recommendation != RecAutoFix {
		t.Fatalf("callsite: %+v", use)
	}
}

func TestUnknownJumpIsHandedOver(t *testing.T) {
	r := ScoreRisk(cfg(), nil, RiskInput{Jump: JumpUnknown, TestCount: 1, TestMethod: "callsite", HasFix: true})
	if r.Score != 0 || r.Recommendation != RecHandoff || r.Terms["jump_unknown_handoff"] != 1 || r.Warning {
		t.Fatalf("got %+v", r)
	}
	if r := ScoreRisk(cfg(), nil, RiskInput{Jump: JumpUnknown, HasFix: false}); r.Recommendation != RecReportOnly {
		t.Errorf("no fix stays report_only: %+v", r)
	}
	if r := ScoreRisk(cfg(), nil, RiskInput{Jump: JumpPatch, TestCount: 1, TestMethod: "callsite", HasFix: true}); r.Terms["jump_unknown_handoff"] != 0 {
		t.Errorf("flag without cause: %v", r.Terms)
	}
}

func TestNpmRootConstraintFirstSourceWins(t *testing.T) {
	g := writeNpm(t, `{"lockfileVersion":3,"packages":{
"":{"devDependencies":{"react":"^18.2.0"},"peerDependencies":{"react":"^17 || ^18"},
    "dependencies":{"lodash":"^4.17.21"},"optionalDependencies":{"lodash":"^4.0.0"}},
"node_modules/react":{"version":"18.2.0"},"node_modules/lodash":{"version":"4.17.21"}}}`)
	if p := g.PathTo("react"); p.Constraint != "^18.2.0" {
		t.Errorf("react constraint %q, want ^18.2.0", p.Constraint)
	}
	if p := g.PathTo("lodash"); p.Constraint != "^4.17.21" {
		t.Errorf("lodash constraint %q, want ^4.17.21", p.Constraint)
	}
}

func TestRunRecomputesWhenSettingsChange(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	fs := []scan.Finding{e.f}
	if r, err := Run(ctx, e.deps, e.p, fs, Options{}); err != nil || r.Analyzed != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	if r, _ := Run(ctx, e.deps, e.p, fs, Options{}); r.Skipped != 1 {
		t.Fatalf("unchanged settings must stay fresh: %+v", r)
	}
	a, ok, err := NewRepo(e.st).Get(ctx, e.f.ID)
	if err != nil || !ok || a.ProjectID != "p1" || len(a.InputsHash) != 64 {
		t.Fatalf("stored: project=%q hash=%q ok=%v err=%v", a.ProjectID, a.InputsHash, ok, err)
	}

	e.p.CorePackages = []string{"acme/vuln"}
	if r, _ := Run(ctx, e.deps, e.p, fs, Options{}); r.Analyzed != 1 {
		t.Fatalf("a new core package must recompute: %+v", r)
	}
	a, _, _ = NewRepo(e.st).Get(ctx, e.f.ID)
	if a.Risk.Terms["core_package"] == 0 {
		t.Errorf("recomputed analysis ignores the core package: %v", a.Risk.Terms)
	}

	e.p.RiskOverrides = map[string]int{"no_tests": 5}
	if r, _ := Run(ctx, e.deps, e.p, fs, Options{}); r.Analyzed != 1 {
		t.Fatalf("a risk override must recompute: %+v", r)
	}
	e.deps.Risk.Direct = 11
	if r, _ := Run(ctx, e.deps, e.p, fs, Options{}); r.Analyzed != 1 {
		t.Fatalf("a policy change must recompute: %+v", r)
	}
	if r, _ := Run(ctx, e.deps, e.p, fs, Options{}); r.Skipped != 1 {
		t.Fatalf("then fresh again: %+v", r)
	}
}

func TestInputsHashIsOrderIndependent(t *testing.T) {
	p1 := project.Project{CorePackages: []string{"b", "a"}}
	p2 := project.Project{CorePackages: []string{"a", "b"}}
	if InputsHash(cfg(), p1, []string{"x", "y"}, false) != InputsHash(cfg(), p2, []string{"y", "x"}, false) {
		t.Error("order of core packages or excludes must not change the hash")
	}
	if InputsHash(cfg(), p1, nil, false) == InputsHash(cfg(), p1, nil, true) {
		t.Error("is_core must change the hash")
	}
}
