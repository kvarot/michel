package analyze

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// maxTestFiles is a variable only so tests can lower it.
var maxTestFiles = 50

// Coverage tells whether tests cover the files that use a vulnerable package.
type Coverage struct {
	TestFiles []string `json:"test_files"` // relative, forward slashes, sorted, at most 50
	Count     int      `json:"count"`      // total number of covering test files, before the cap
	// Method is "callsite" (a test uses the package itself), "reference" (a
	// test only mentions the name of a file that uses it: weak evidence, it
	// does not cancel the no_tests risk term) or "none".
	Method string `json:"method"`
	// Skipped lists the base names ignored by the reference rule because they
	// are too short or too generic to be meaningful.
	Skipped []string `json:"skipped"`
	// Unreadable counts distinct test files that could not be opened or fully
	// read, in the call-site search or the reference scan. Unreadable source
	// files are only in CallSites.Unreadable.
	// Files over 2 MiB are dropped earlier by the shared walk, uncounted.
	Unreadable int `json:"unreadable"`
}

var noisyNames = map[string]bool{
	"index": true, "main": true, "app": true, "test": true, "utils": true, "helpers": true,
}

func testExtensions(ecosystem string) []string {
	switch strings.ToLower(ecosystem) {
	case "composer", "packagist":
		return phpExtensions
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

	seen := map[string]bool{}
	var names []string
	skipped := map[string]bool{}
	for _, file := range sites.SourceFiles {
		base := path.Base(file)
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

	unreadable := map[string]bool{}
	for _, p := range sites.UnreadablePaths {
		if isTestPath(p) {
			unreadable[p] = true
		}
	}

	if sites.TestHitCount > 0 {
		c := capCoverage(sites.TestFiles)
		c.Method, c.Skipped, c.Unreadable = "callsite", cov.Skipped, len(unreadable)
		c.Count = sites.TestFileCount
		return c, nil
	}
	exts := testExtensions(ecosystem)
	if len(names) == 0 || exts == nil {
		cov.Unreadable = len(unreadable)
		return cov, nil
	}

	manifestDir := filepath.Dir(filepath.Join(projectRoot, filepath.FromSlash(manifestRelPath)))
	others, err := findOtherManifestDirs(projectRoot, manifestDir, exclude)
	if err != nil {
		cov.Unreadable = len(unreadable)
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
		hit, ok := referencesAny(f, res)
		if !ok {
			unreadable[rel] = true
		} else if hit {
			found = append(found, rel)
		}
	}
	if len(found) == 0 {
		cov.Unreadable = len(unreadable)
		return cov, nil
	}
	c := capCoverage(found)
	c.Method, c.Skipped, c.Unreadable = "reference", cov.Skipped, len(unreadable)
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

// referencesAny reports whether any line of the file matches one of res; ok is
// false when the file could not be opened or fully read.
func referencesAny(f string, res []*regexp.Regexp) (hit, ok bool) {
	fh, err := os.Open(f)
	if err != nil {
		return false, false
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		for _, re := range res {
			if re.MatchString(line) {
				return true, true
			}
		}
	}
	return false, sc.Err() == nil
}
