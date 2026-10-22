package analyze

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func coverageFor(t *testing.T, fixture string) Coverage {
	t.Helper()
	root := filepath.Join("testdata", "callsites", fixture)
	cs, err := FindCallSites(root, "composer.lock", "composer", "acme/vuln", nil)
	if err != nil {
		t.Fatal(err)
	}
	cov, err := FindCoveringTests(root, "composer.lock", cs, "composer", nil)
	if err != nil {
		t.Fatal(err)
	}
	return cov
}

func TestCoverageFromTestCallSite(t *testing.T) {
	cov := coverageFor(t, "php")
	if cov.Method != "callsite" || cov.Count != 1 || !reflect.DeepEqual(cov.TestFiles, []string{"tests/HttpTest.php"}) {
		t.Fatalf("%+v", cov)
	}
}

func TestCoverageByReference(t *testing.T) {
	cov := coverageFor(t, "php-ref")
	if cov.Method != "reference" || cov.Count != 1 || !reflect.DeepEqual(cov.TestFiles, []string{"tests/HttpTest.php"}) {
		t.Fatalf("%+v", cov)
	}
}

func TestCoverageNone(t *testing.T) {
	cov := coverageFor(t, "php-none")
	if cov.Method != "none" || cov.Count != 0 || len(cov.TestFiles) != 0 {
		t.Fatalf("%+v", cov)
	}
}

func TestCoverageSkipsNoisyNames(t *testing.T) {
	root := filepath.Join("testdata", "callsites", "php-ref")
	sites := CallSites{SourceFiles: []string{"src/index.php", "src/ab.php"}}
	cov, err := FindCoveringTests(root, "composer.lock", sites, "composer", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Method != "none" || !reflect.DeepEqual(cov.Skipped, []string{"ab", "index"}) {
		t.Fatalf("%+v", cov)
	}
}

func TestCoverageCapsTestFiles(t *testing.T) {
	cov := capCoverage(makeNames(60))
	if len(cov.TestFiles) != 50 || cov.Count != 60 {
		t.Fatalf("len=%d count=%d", len(cov.TestFiles), cov.Count)
	}
}

func makeNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "tests/t" + string(rune('a'+i/26)) + string(rune('a'+i%26)) + "Test.php"
	}
	return out
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const useClient = `<?php
use Acme\Vuln\Client;
`

// acmeAutoload is the composer.json of an installed acme/vuln: an installed
// package without any autoload namespace is no longer searched by name.
const acmeAutoload = `{"autoload":{"psr-4":{"Acme\\Vuln\\":"src/"}}}`

func TestCoverageSurvivesSitesCap(t *testing.T) {
	old := maxSites
	maxSites = 2
	defer func() { maxSites = old }()
	root := writeTree(t, map[string]string{
		"composer.lock":                  "{}",
		"src/A.php":                      useClient + useClient,
		"src/B.php":                      useClient,
		"tests/ZTest.php":                useClient,
		"vendor/acme/vuln/composer.json": acmeAutoload,
	})
	cs, err := FindCallSites(root, "composer.lock", "composer", "acme/vuln", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range cs.Sites {
		if s.IsTest {
			t.Fatalf("test site should have been cut by the cap: %+v", cs.Sites)
		}
	}
	cov, err := FindCoveringTests(root, "composer.lock", cs, "composer", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Method != "callsite" || cov.Count != 1 || !reflect.DeepEqual(cov.TestFiles, []string{"tests/ZTest.php"}) {
		t.Fatalf("%+v", cov)
	}
}

func TestCoverageCallsitePrecedesReference(t *testing.T) {
	root := writeTree(t, map[string]string{
		"composer.lock":                  "{}",
		"src/Http.php":                   useClient,
		"tests/ATest.php":                useClient,
		"tests/BTest.php":                "<?php\nnew Http();\n",
		"vendor/acme/vuln/composer.json": acmeAutoload,
	})
	cs, _ := FindCallSites(root, "composer.lock", "composer", "acme/vuln", nil)
	cov, err := FindCoveringTests(root, "composer.lock", cs, "composer", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Method != "callsite" || !reflect.DeepEqual(cov.TestFiles, []string{"tests/ATest.php"}) {
		t.Fatalf("%+v", cov)
	}
}

func TestCoverageDedupsReferences(t *testing.T) {
	root := writeTree(t, map[string]string{
		"composer.lock":                  "{}",
		"src/Http.php":                   useClient,
		"src/Client.php":                 useClient,
		"tests/XTest.php":                "<?php\nnew Http(); new Client();\n",
		"vendor/acme/vuln/composer.json": acmeAutoload,
	})
	cs, _ := FindCallSites(root, "composer.lock", "composer", "acme/vuln", nil)
	cov, err := FindCoveringTests(root, "composer.lock", cs, "composer", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Method != "reference" || cov.Count != 1 || !reflect.DeepEqual(cov.TestFiles, []string{"tests/XTest.php"}) {
		t.Fatalf("%+v", cov)
	}
}

func TestCoverageNpmReference(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package-lock.json":  "{}",
		"src/client.js":      "const a = require('vuln-pkg');\n",
		"src/client.test.js": "import './client'; // client\n",
		"src/other.spec.ts":  "// nothing\n",
	})
	cs, err := FindCallSites(root, "package-lock.json", "npm", "vuln-pkg", nil)
	if err != nil {
		t.Fatal(err)
	}
	cov, err := FindCoveringTests(root, "package-lock.json", cs, "npm", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Method != "reference" || !reflect.DeepEqual(cov.TestFiles, []string{"src/client.test.js"}) {
		t.Fatalf("%+v", cov)
	}
}

func TestCoverageUnreadableTestFile(t *testing.T) {
	root := writeTree(t, map[string]string{
		"composer.lock":                  "{}",
		"src/Http.php":                   useClient,
		"tests/BigTest.php":              "<?php\n" + strings.Repeat("x", (1<<20)+10) + "\n",
		"vendor/acme/vuln/composer.json": acmeAutoload,
	})
	cs, _ := FindCallSites(root, "composer.lock", "composer", "acme/vuln", nil)
	cov, err := FindCoveringTests(root, "composer.lock", cs, "composer", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Same file hit by the call-site search and the reference scan: counted once.
	if cov.Method != "none" || cov.Unreadable != 1 {
		t.Fatalf("%+v", cov)
	}
}

func TestCoverageCountBeyondTestFilesCap(t *testing.T) {
	old := maxTestFiles
	maxTestFiles = 2
	defer func() { maxTestFiles = old }()
	root := writeTree(t, map[string]string{
		"composer.lock":                  "{}",
		"tests/ATest.php":                useClient,
		"tests/BTest.php":                useClient,
		"tests/CTest.php":                useClient,
		"vendor/acme/vuln/composer.json": acmeAutoload,
	})
	cs, _ := FindCallSites(root, "composer.lock", "composer", "acme/vuln", nil)
	cov, err := FindCoveringTests(root, "composer.lock", cs, "composer", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Method != "callsite" || cov.Count != 3 || len(cov.TestFiles) != 2 {
		t.Fatalf("%+v", cov)
	}
}

func TestCoverageUnreadableSourceNotCounted(t *testing.T) {
	root := writeTree(t, map[string]string{
		"composer.lock":                  "{}",
		"src/BigSrc.php":                 "<?php\n" + strings.Repeat("x", (1<<20)+10) + "\n",
		"tests/ATest.php":                useClient,
		"vendor/acme/vuln/composer.json": acmeAutoload,
	})
	cs, _ := FindCallSites(root, "composer.lock", "composer", "acme/vuln", nil)
	if cs.Unreadable != 1 {
		t.Fatalf("setup: %+v", cs)
	}
	cov, err := FindCoveringTests(root, "composer.lock", cs, "composer", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Method != "callsite" || cov.Unreadable != 0 {
		t.Fatalf("%+v", cov)
	}
}
