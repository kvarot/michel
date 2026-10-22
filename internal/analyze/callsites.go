package analyze

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const maxSnippetLen = 160

const maxSourceFiles = 200

// maxSites caps the kept sites; a variable only so tests can lower it.
var maxSites = 200

// CallSite is one line of the user's code that uses a package.
type CallSite struct {
	File string // relative to the project root, forward slashes
	Line int
	// Snippet is the trimmed line (max 160 chars). Transient: not persisted.
	Snippet string
	IsTest  bool
}

// CallSites is the result of a call-site search.
type CallSites struct {
	Sites      []CallSite // at most 200
	Count      int        // total number of matching lines
	Quality    string     // PHP: "psr4" | "name" | "low"; JS: "import"
	Namespaces []string
	// Unreadable counts files that could not be opened or fully read (e.g. a
	// line over 1 MiB), so "no usage found" differs from "could not read".
	Unreadable int
	// UnreadablePaths lists those files (relative, forward slashes, sorted).
	UnreadablePaths []string
	// Computed from ALL hits, independent of the Sites cap.
	TestFiles     []string // distinct test files with a hit, sorted, at most 50
	TestFileCount int      // distinct test files with a hit, before the TestFiles cap
	TestHitCount  int      // total hits in test files
	SourceFiles   []string // distinct non-test files with a hit, sorted, at most 200
}

// FindCallSites looks for the lines of the user's code, under the manifest's
// directory, that use pkg. It never writes and never touches the network.
//
// Known limitation: for PHP, the `use` line is the site. Unqualified short-name
// usages after an import (`new Client(`) are not tracked.
func FindCallSites(projectRoot, manifestRelPath, ecosystem, pkg string, exclude []string) (CallSites, error) {
	manifestDir := filepath.Dir(filepath.Join(projectRoot, filepath.FromSlash(manifestRelPath)))
	others, err := findOtherManifestDirs(projectRoot, manifestDir, exclude)
	if err != nil {
		return CallSites{}, err
	}
	switch strings.ToLower(ecosystem) {
	case "composer", "packagist":
		return findPHP(projectRoot, manifestDir, others, pkg, exclude)
	case "npm":
		return findJS(projectRoot, manifestDir, others, pkg, exclude)
	}
	return CallSites{Quality: "low"}, nil
}

// scanFiles runs match on every line of files and collects the sites.
func scanFiles(projectRoot string, files []string, match func(line string) bool) (CallSites, error) {
	var res CallSites
	type entry struct{ abs, rel string }
	entries := make([]entry, 0, len(files))
	for _, f := range files {
		rel, err := filepath.Rel(projectRoot, f)
		if err != nil {
			res.Unreadable++
			continue
		}
		entries = append(entries, entry{f, filepath.ToSlash(rel)})
	}
	// Slash order, so the kept sites are the same on every OS.
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	for _, e := range entries {
		hits := 0
		f, rel := e.abs, e.rel
		fh, err := os.Open(f)
		if err != nil {
			res.Unreadable++
			res.UnreadablePaths = append(res.UnreadablePaths, rel)
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		n := 0
		for sc.Scan() {
			n++
			line := strings.TrimRight(sc.Text(), "\r")
			if !match(line) {
				continue
			}
			res.Count++
			hits++
			if len(res.Sites) < maxSites {
				res.Sites = append(res.Sites, CallSite{
					File: rel, Line: n, Snippet: snippet(line), IsTest: isTestPath(rel),
				})
			}
		}
		if sc.Err() != nil {
			res.Unreadable++
			res.UnreadablePaths = append(res.UnreadablePaths, rel)
		}
		fh.Close()
		if hits > 0 {
			if isTestPath(rel) {
				res.TestFileCount++
				res.TestHitCount += hits
				if len(res.TestFiles) < maxTestFiles {
					res.TestFiles = append(res.TestFiles, rel)
				}
			} else if len(res.SourceFiles) < maxSourceFiles {
				res.SourceFiles = append(res.SourceFiles, rel)
			}
		}
	}
	return res, nil
}

func snippet(line string) string {
	s := strings.TrimSpace(line)
	if r := []rune(s); len(r) > maxSnippetLen {
		s = string(r[:maxSnippetLen])
	}
	return s
}

func isTestPath(rel string) bool {
	lower := strings.ToLower(rel)
	p := "/" + lower
	for _, d := range []string{"/tests/", "/test/", "/__tests__/"} {
		if strings.Contains(p, d) {
			return true
		}
	}
	if strings.HasSuffix(rel, "Test.php") || strings.HasSuffix(lower, "_test.php") {
		return true
	}
	for _, kind := range []string{".test", ".spec"} {
		for _, ext := range []string{".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue"} {
			if strings.HasSuffix(lower, kind+ext) {
				return true
			}
		}
	}
	return false
}
