// Package hygiene holds repository-wide checks that are not about one package.
package hygiene

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenDigests are the SHA-256 (hex) of the lowercased forbidden tokens:
// names, hosts and machine paths of the author's private projects. The list
// is hashed on purpose: a clear-text list would itself be the trace this test
// forbids. A token is a run of [a-z0-9_] (other ASCII bytes, including / \ .
// - : and spaces, separate tokens); multi-word names are hashed as their
// tokens joined without separator, so "x-y", "x y" and "xy" are one entry.
// To add an entry, hash the lowercased joined tokens (for example with
// `printf '%s' xy | sha256sum`) and never write the clear form in the repo.
var forbiddenDigests = map[string]bool{
	"6dffae26731fe3857b7358b5f8e2bf102b21486c7a507cc4685db7934813278d": true,
	"c7dd70fb276f6b02fbe7061bffb01047326eb3193eeccbe70c0aa267b4e3d928": true,
	"f6f03eae36fb78f6feed2a84648e7751d293eb3625e8845ca1d57e4ad75aa07c": true,
	"fb1384e07038a3d1f113d5e1238aad4d71e14617ff71ac8f2a0b59795b854628": true,
	"83f87fcace70088e68504e4254329268e2a7d906edbe8f8f6f07ef84e2f12200": true,
	"08a2829738b61a7dab623c64a475b5d5976c8079bc3b539c873e726dd2202ddb": true,
	"2961d3065307038214244d221ece9feb1ebe7ad40b297a0009866dbc490138f4": true,
	"64a19348509e818eb08a44258996e2704a5de4a34a8d678260f76c220b77ffc6": true,
}

// maxJoin is the longest run of adjacent tokens hashed as one candidate.
const maxJoin = 4

// TestNoPrivateProjectTraces fails when a committed file mentions the author's
// private projects or machine. Michel scans real code on its author's machine
// during development; nothing from those projects may land in this repository
// (names, paths, lockfile names, vulnerable packages of a real product).
//
// The check is case-insensitive and token-based, so a short name matches as a
// whole token only (an identifier that merely starts with it is not a hit).
// It cannot judge meaning: sentences about the private project's makeup or
// counts are reviewed by hand.
func TestNoPrivateProjectTraces(t *testing.T) {
	violations, err := scanTree(moduleRoot(t))
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("private project traces found:\n  %s", strings.Join(violations, "\n  "))
	}
}

// TestHygieneCatchesForbiddenTokens proves the hashed list still matches the
// forbidden forms. The samples are stored rot13-encoded so that this file holds
// no clear trace either; they are decoded into a temporary tree.
func TestHygieneCatchesForbiddenTokens(t *testing.T) {
	bad := []string{
		"frr uggcf://example.invalid/k",
		"Example Team grnz",
		"ncv/service-a/ebhgrf",
		"znvy: fbzrbar@example.pbz",
		`cngu P:\Hfref\fbzrbar\k`,
		"pq /Hfref/someone/fep",
		"bcra <projects>/guvat",
		"gur reference ncc",
	}
	good := []string{"zpyrna naq zpy_k fgnl", "n qrcraqrapl jngpure"}
	root := t.TempDir()
	write := func(name string, lines []string) {
		dec := make([]string, len(lines))
		for i, l := range lines {
			dec[i] = rot13(l)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(strings.Join(dec, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("bad.md", bad)
	write("good.md", good)
	violations, err := scanTree(root)
	if err != nil {
		t.Fatal(err)
	}
	hits := map[string]bool{}
	for _, v := range violations {
		if strings.HasPrefix(v, "good.md:") {
			t.Errorf("false positive: %s", v)
		}
		hits[strings.SplitN(v, ": ", 2)[0]] = true
	}
	for i := range bad {
		if loc := "bad.md:" + itoa(i+1); !hits[loc] {
			t.Errorf("sample line %d (%q once decoded) is not caught", i+1, bad[i])
		}
	}
}

// scanTree walks root and reports every line holding a forbidden token, as
// "path:line: forbidden token". The token itself is never printed.
func scanTree(root string) ([]string, error) {
	skipDirs := map[string]bool{".git": true, ".superpowers": true, "node_modules": true, "vendor": true, "bin": true, "dist": true}
	skipFiles := map[string]bool{"go.mod": true, "go.sum": true}

	var violations []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if skipDirs[name] && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if skipFiles[name] || isBinaryExt(name) {
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
			if lineIsForbidden(strings.ToLower(sc.Text())) {
				violations = append(violations, rel+":"+itoa(line)+": forbidden token")
			}
		}
		return sc.Err()
	})
	return violations, err
}

// lineIsForbidden hashes every token of the lowercased line and every join of
// 2 to maxJoin adjacent tokens.
func lineIsForbidden(lower string) bool {
	toks := tokens(lower)
	for i := range toks {
		joined := ""
		for j := i; j < len(toks) && j < i+maxJoin; j++ {
			joined += toks[j]
			sum := sha256.Sum256([]byte(joined))
			if forbiddenDigests[hex.EncodeToString(sum[:])] {
				return true
			}
		}
	}
	return false
}

func tokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return !isWordRune(r) })
}

// isWordRune: ASCII letters, digits and underscore; non-ASCII letters stay
// inside their word.
func isWordRune(r rune) bool {
	return r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || r >= 0x80
}

func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
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
