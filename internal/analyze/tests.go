package analyze

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const maxTestFiles = 50

// Coverage tells whether tests cover the files that use a vulnerable package.
type Coverage struct {
	TestFiles []string // relative, forward slashes, sorted, at most 50
	Count     int      // total number of covering test files, before the cap
	Method    string   // "callsite" | "reference" | "none"
	// Skipped lists the base names ignored by the reference rule because they
	// are too short or too generic to be meaningful.
	Skipped []string
}

var noisyNames = map[string]bool{
	"index": true, "main": true, "app": true, "test": true, "utils": true, "helpers": true,
}

func testExtensions(ecosystem string) []string {
	switch strings.ToLower(ecosystem) {
	case "composer", "packagist":
		return []string{".php", ".phtml", ".twig"}
	case "npm":
		return []string{".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts", ".vue", ".svelte"}
	}
	return nil
}

// FindCoveringTests looks for test files that cover the call sites: a test
// file that itself uses the package ("callsite"), else a test file of the
// manifest's scope that mentions the base name of a using file ("reference").
// Read-only, no network.
func FindCoveringTests(projectRoot, manifestRelPath string, sites CallSites, ecosystem string, exclude []string) (Coverage, error) {
	cov := Coverage{Method: "none"}

	var direct []string
	seen := map[string]bool{}
	var names []string
	skipped := map[string]bool{}
	for _, s := range sites.Sites {
		if s.IsTest {
			direct = append(direct, s.File)
			continue
		}
		base := path.Base(s.File)
		base = strings.TrimSuffix(base, path.Ext(base))
		if seen[base] {
			continue
		}
		seen[base] = true
		if len([]rune(base)) < 3 || noisyNames[strings.ToLower(base)] {
			skipped[base] = true
			continue
		}
		names = append(names, base)
	}
	for n := range skipped {
		cov.Skipped = append(cov.Skipped, n)
	}
	sort.Strings(cov.Skipped)

	if len(direct) > 0 {
		c := capCoverage(direct)
		c.Method, c.Skipped = "callsite", cov.Skipped
		return c, nil
	}
	exts := testExtensions(ecosystem)
	if len(names) == 0 || exts == nil {
		return cov, nil
	}

	manifestDir := filepath.Dir(filepath.Join(projectRoot, filepath.FromSlash(manifestRelPath)))
	others, err := findOtherManifestDirs(projectRoot, manifestDir, exclude)
	if err != nil {
		return cov, err
	}
	files, err := userFiles(projectRoot, manifestDir, others, exclude, exts)
	if err != nil {
		return cov, err
	}
	res := make([]*regexp.Regexp, len(names))
	for i, n := range names {
		res[i] = regexp.MustCompile(`\b` + regexp.QuoteMeta(n) + `\b`)
	}
	var found []string
	for _, f := range files {
		rel, err := filepath.Rel(projectRoot, f)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		if !isTestPath(rel) {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, re := range res {
			if re.Match(data) {
				found = append(found, rel)
				break
			}
		}
	}
	if len(found) == 0 {
		return cov, nil
	}
	c := capCoverage(found)
	c.Method, c.Skipped = "reference", cov.Skipped
	return c, nil
}

// capCoverage dedups and sorts files, caps the list and sets Count to the
// total before the cap.
func capCoverage(files []string) Coverage {
	set := make(map[string]bool, len(files))
	var out []string
	for _, f := range files {
		if !set[f] {
			set[f] = true
			out = append(out, f)
		}
	}
	sort.Strings(out)
	c := Coverage{Count: len(out), TestFiles: out}
	if len(out) > maxTestFiles {
		c.TestFiles = out[:maxTestFiles]
	}
	return c
}
