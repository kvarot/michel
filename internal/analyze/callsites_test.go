package analyze

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hasSite(cs CallSites, file string, line int) (CallSite, bool) {
	for _, s := range cs.Sites {
		if s.File == file && s.Line == line {
			return s, true
		}
	}
	return CallSite{}, false
}

func TestPhpCallSitesViaPsr4(t *testing.T) {
	root := filepath.Join("testdata", "callsites", "php")
	cs, err := FindCallSites(root, "composer.lock", "composer", "acme/vuln", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Quality != "psr4" || cs.Count != 2 {
		t.Fatalf("quality=%q count=%d sites=%+v", cs.Quality, cs.Count, cs.Sites)
	}
	if s, ok := hasSite(cs, "src/Http.php", 3); !ok || s.Snippet != `use Acme\Vuln\Client;` || s.IsTest {
		t.Errorf("bad src/Http.php:3: %+v", cs.Sites)
	}
	if s, ok := hasSite(cs, "tests/HttpTest.php", 3); !ok || !s.IsTest {
		t.Errorf("tests/HttpTest.php:3 missing or not a test: %+v", cs.Sites)
	}
	for _, s := range cs.Sites {
		if strings.HasPrefix(s.File, "api/") {
			t.Errorf("api/ belongs to another manifest: %s", s.File)
		}
	}
	if len(cs.Namespaces) != 1 || cs.Namespaces[0] != `Acme\Vuln` {
		t.Errorf("namespaces %v", cs.Namespaces)
	}
}

func TestPhpCallSitesWithoutVendorFallsBackToName(t *testing.T) {
	root := filepath.Join("testdata", "callsites", "php")
	cs, err := FindCallSites(root, "composer.lock", "composer", "acme/other-thing", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Quality != "name" || cs.Count != 1 {
		t.Fatalf("quality=%q count=%d", cs.Quality, cs.Count)
	}
	if _, ok := hasSite(cs, "src/Other.php", 3); !ok {
		t.Errorf("%+v", cs.Sites)
	}
	cs, _ = FindCallSites(root, "composer.lock", "composer", "nobody/nothing", nil)
	if cs.Quality != "low" || cs.Count != 0 {
		t.Errorf("want low/0, got %q/%d", cs.Quality, cs.Count)
	}
}

func TestPhpCallSitesSubManifest(t *testing.T) {
	root := filepath.Join("testdata", "callsites", "php")
	cs, err := FindCallSites(root, "api/composer.lock", "composer", "acme/vuln", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hasSite(cs, "api/src/Api.php", 3); !ok || cs.Count != 1 {
		t.Errorf("%+v", cs)
	}
}

func TestJsCallSitesImportForms(t *testing.T) {
	root := filepath.Join("testdata", "callsites", "js")
	cs, err := FindCallSites(root, "package-lock.json", "npm", "vuln-pkg", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Quality != "import" || cs.Count != 5 {
		t.Fatalf("quality=%q count=%d sites=%+v", cs.Quality, cs.Count, cs.Sites)
	}
	for _, w := range []struct {
		f string
		l int
	}{{"src/a.js", 1}, {"src/a.js", 2}, {"src/b.ts", 1}, {"src/b.ts", 2}, {"src/c.vue", 2}} {
		if _, ok := hasSite(cs, w.f, w.l); !ok {
			t.Errorf("missing %s:%d", w.f, w.l)
		}
	}
}

func TestCallSitesCapAt200(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&b, "const x%d = require('vuln-pkg')\r\n", i)
	}
	if err := os.WriteFile(filepath.Join(root, "big.js"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	cs, err := FindCallSites(root, "package-lock.json", "npm", "vuln-pkg", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.Sites) != 200 || cs.Count != 300 {
		t.Fatalf("sites=%d count=%d", len(cs.Sites), cs.Count)
	}
	if cs.Sites[0].Line != 1 || strings.Contains(cs.Sites[0].Snippet, "\r") {
		t.Errorf("%+v", cs.Sites[0])
	}
}

func TestCallSitesSkipNodeModulesAndDist(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	line := []byte("require('vuln-pkg')\n")
	for _, d := range []string{"node_modules/x", "dist", "build", "custom-skip", "src"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, d, "f.js"), line, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cs, err := FindCallSites(root, "package-lock.json", "npm", "vuln-pkg", []string{"custom-skip"})
	if err != nil {
		t.Fatal(err)
	}
	if cs.Count != 1 || cs.Sites[0].File != "src/f.js" {
		t.Fatalf("%+v", cs)
	}
}

func TestIsTestPath(t *testing.T) {
	for p, want := range map[string]bool{
		"tests/a.php": true, "src/test/a.js": true, "x/__tests__/a.js": true,
		"src/FooTest.php": true, "a.test.ts": true, "a.spec.jsx": true,
		"src/a.php": false, "src/latest.js": false, "a.test.mjs": true, "A.SPEC.vue": true, "SRC/Tests/a.php": true,
	} {
		if isTestPath(p) != want {
			t.Errorf("%s: want %v", p, want)
		}
	}
}

func TestCallSitesCapKeepsFirstInSlashOrder(t *testing.T) {
	old := maxSites
	maxSites = 3
	defer func() { maxSites = old }()
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{}"), 0o644)
	content := []byte("require('vuln-pkg')\nrequire('vuln-pkg')\n")
	for _, f := range []string{"src/x.js", "src0/x.js", "src/y.js"} {
		os.MkdirAll(filepath.Dir(filepath.Join(root, f)), 0o755)
		if err := os.WriteFile(filepath.Join(root, f), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cs, err := FindCallSites(root, "package-lock.json", "npm", "vuln-pkg", nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range cs.Sites {
		got = append(got, fmt.Sprintf("%s:%d", s.File, s.Line))
	}
	want := "src/x.js:1 src/x.js:2 src/y.js:1"
	if cs.Count != 6 || strings.Join(got, " ") != want {
		t.Fatalf("count=%d got %v", cs.Count, got)
	}
}

func TestLineHasNamespaceBoundaries(t *testing.T) {
	yes := []string{
		`[Acme\Vuln\Client::class]`, `#[Acme\Vuln\X]`, `?Acme\Vuln\X`, `A|Acme\Vuln\X`,
		`=Acme\Vuln\X`, `'Acme\Vuln\X'`, `\Acme\Vuln\X`, `use Acme\Vuln\X;`, `new Acme\Vuln\X`,
	}
	for _, l := range yes {
		if !lineHasNamespace(strings.ToLower(l), []string{`acme\vuln`}) {
			t.Errorf("should match: %s", l)
		}
	}
	if lineHasNamespace(strings.ToLower(`use App\Twig\Ext;`), []string{"twig"}) {
		t.Error(`App\Twig\Ext must not match Twig`)
	}
	if lineHasNamespace(strings.ToLower(`use Acme\Vulnerable\X;`), []string{`acme\vuln`}) {
		t.Error(`Acme\Vulnerable must not match Acme\Vuln`)
	}
}

func TestPhpPsr0UnderscoreNamespace(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "vendor", "acme", "vuln")
	os.MkdirAll(dir, 0o755)
	os.MkdirAll(filepath.Join(root, "src"), 0o755)
	os.WriteFile(filepath.Join(root, "composer.lock"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{"autoload":{"psr-0":{"Acme_Vuln_":"lib/"}}}`), 0o644)
	os.WriteFile(filepath.Join(root, "src", "a.php"), []byte("<?php\n$x = new Acme_Vuln_Client();\n$y = new Other_Acme_Vuln_Client();\n"), 0o644)
	cs, err := FindCallSites(root, "composer.lock", "composer", "acme/vuln", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Quality != "psr4" || cs.Count != 1 || cs.Sites[0].Line != 2 {
		t.Fatalf("%+v", cs)
	}
	if len(cs.Namespaces) != 1 || cs.Namespaces[0] != "Acme_Vuln" {
		t.Errorf("namespaces %v", cs.Namespaces)
	}
}

func TestCallSitesUnreadableLine(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{}"), 0o644)
	big := "require('vuln-pkg')\n" + strings.Repeat("x", 1<<20+10) + "\n"
	os.WriteFile(filepath.Join(root, "big.js"), []byte(big), 0o644)
	cs, err := FindCallSites(root, "package-lock.json", "npm", "vuln-pkg", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Unreadable != 1 || cs.Count != 1 {
		t.Fatalf("%+v", cs)
	}
}
