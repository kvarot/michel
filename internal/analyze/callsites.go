package analyze

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxSites      = 200
	maxSnippetLen = 160
)

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
}

// FindCallSites looks for the lines of the user's code, under the manifest's
// directory, that use pkg. It never writes and never touches the network.
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
	for _, f := range files {
		rel, err := filepath.Rel(projectRoot, f)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		fh, err := os.Open(f)
		if err != nil {
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
			if len(res.Sites) < maxSites {
				res.Sites = append(res.Sites, CallSite{
					File: rel, Line: n, Snippet: snippet(line), IsTest: isTestPath(rel),
				})
			}
		}
		fh.Close()
	}
	sort.SliceStable(res.Sites, func(i, j int) bool {
		if res.Sites[i].File != res.Sites[j].File {
			return res.Sites[i].File < res.Sites[j].File
		}
		return res.Sites[i].Line < res.Sites[j].Line
	})
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
	p := "/" + rel
	for _, d := range []string{"/tests/", "/test/", "/__tests__/"} {
		if strings.Contains(p, d) {
			return true
		}
	}
	if strings.HasSuffix(rel, "Test.php") {
		return true
	}
	for _, kind := range []string{".test", ".spec"} {
		for _, ext := range []string{".js", ".ts", ".jsx", ".tsx"} {
			if strings.HasSuffix(rel, kind+ext) {
				return true
			}
		}
	}
	return false
}
