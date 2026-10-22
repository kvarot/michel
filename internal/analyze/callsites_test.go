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
	if cs.Quality != "psr4" || cs.Count != 3 {
		t.Fatalf("quality=%q count=%d sites=%+v", cs.Quality, cs.Count, cs.Sites)
	}
	if s, ok := hasSite(cs, "src/Http.php", 3); !ok || s.Snippet != `use Acme\Vuln\Client;` || s.IsTest {
		t.Errorf("bad src/Http.php:3: %+v", cs.Sites)
	}
	if _, ok := hasSite(cs, "src/Http.php", 9); !ok {
		t.Errorf("missing src/Http.php:9: %+v", cs.Sites)
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
		"src/a.php": false, "src/latest.js": false,
	} {
		if isTestPath(p) != want {
			t.Errorf("%s: want %v", p, want)
		}
	}
}
