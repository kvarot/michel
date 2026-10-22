package analyze

import (
	"path/filepath"
	"reflect"
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
	sites := CallSites{Sites: []CallSite{{File: "src/index.php"}, {File: "src/ab.php"}}}
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
