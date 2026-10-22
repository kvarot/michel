// Package hygiene holds repository-wide checks that are not about one package.
package hygiene

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoPrivateProjectTraces fails when a committed file mentions the author's
// private projects or machine. Michel scans real code on its author's machine
// during development; nothing from those projects may land in this repository
// (names, paths, lockfile names, vulnerable packages of a real product).
//
// The check is case-insensitive and token-based: `demo` matches as a whole word
// only, so identifiers such as `mclean` are not false positives.
func TestNoPrivateProjectTraces(t *testing.T) {
	root := moduleRoot(t)

	forbiddenSubstrings := []string{
		"<redacted>",
		"service-a", "example",
		"c:\\users\\", "c:/users/", "/users/kevin", "d:/projets", "d:\\projets",
	}
	forbiddenWords := []string{"demo"}

	skipDirs := map[string]bool{".git": true, ".superpowers": true, "node_modules": true, "vendor": true, "bin": true, "dist": true}
	skipFiles := map[string]bool{"go.mod": true, "go.sum": true}

	var violations []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if skipDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}
		if skipFiles[name] || name == "hygiene_test.go" {
			return nil
		}
		if isBinaryExt(name) {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		line := 0
		for sc.Scan() {
			line++
			lower := strings.ToLower(sc.Text())
			for _, s := range forbiddenSubstrings {
				if strings.Contains(lower, s) {
					violations = append(violations, rel+":"+itoa(line)+": contains "+s)
				}
			}
			for _, w := range forbiddenWords {
				if containsWord(lower, w) {
					violations = append(violations, rel+":"+itoa(line)+": contains word "+w)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("private project traces found:\n  %s", strings.Join(violations, "\n  "))
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above test directory")
		}
		dir = parent
	}
}

func isBinaryExt(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".zip", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".exe", ".db":
		return true
	}
	return false
}

func containsWord(s, w string) bool {
	idx := 0
	for {
		i := strings.Index(s[idx:], w)
		if i < 0 {
			return false
		}
		start := idx + i
		end := start + len(w)
		before := start == 0 || !isWordByte(s[start-1])
		after := end == len(s) || !isWordByte(s[end])
		if before && after {
			return true
		}
		idx = start + 1
	}
}

func isWordByte(b byte) bool {
	return b == '_' || b == '-' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
