package i18n

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// vouvoiement matches the formal "you" that Michel never uses in French.
var vouvoiement = regexp.MustCompile(`(?i)\b(vous|votre|vos|veuillez)\b`)

// moduleRoot walks up from the package directory to the folder holding go.mod.
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
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// frenchTexts lists the French files the guard reads, relative to root.
// The sovereignty policy is a legal document and is excluded on purpose.
func frenchTexts(root string) ([]string, error) {
	var files []string
	for _, pattern := range []string{"internal/i18n/catalog/fr.json", "internal/i18n/templates/fr/*.tmpl", "internal/digest/templates/fr/*.tmpl", "web/src/i18n/fr.json", "README.fr.md"} {
		m, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
		if err != nil {
			return nil, err
		}
		files = append(files, m...)
	}
	docs := filepath.Join(root, "docs")
	err := filepath.WalkDir(docs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".fr.md") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	excluded := filepath.Join(root, "docs", "security", "sovereignty-policy.md")
	kept := files[:0]
	for _, f := range files {
		if f != excluded {
			kept = append(kept, f)
		}
	}
	return kept, nil
}

// scanTutoiement reports every formal "you" as "path:line", path relative
// to root. Quotation lines (">") and fenced code blocks are skipped.
func scanTutoiement(root string) ([]string, error) {
	files, err := frenchTexts(root)
	if err != nil {
		return nil, err
	}
	var hits []string
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		rel, _ := filepath.Rel(root, f)
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		inFence := false
		for n := 1; sc.Scan(); n++ {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "```") {
				inFence = !inFence
				continue
			}
			if inFence || strings.HasPrefix(line, ">") {
				continue
			}
			if vouvoiement.MatchString(line) {
				hits = append(hits, filepath.ToSlash(rel)+":"+strconv.Itoa(n))
			}
		}
		err = sc.Err()
		fh.Close()
		if err != nil {
			return nil, err
		}
	}
	return hits, nil
}

func TestFrenchUsesTutoiement(t *testing.T) {
	tmp := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(tmp, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("internal/i18n/catalog/fr.json", "{\n  \"a.b\": \"Lance la commande\",\n  \"a.c\": \"Vous pouvez relancer\"\n}\n")
	write("README.fr.md", "> vous, en citation\n```\nvous dans du code\n```\nTon projet.\n")
	write("docs/guide/x.fr.md", "Veuillez patienter.\n")
	write("docs/security/sovereignty-policy.md", "Vous acceptez.\n")
	hits, err := scanTutoiement(tmp)
	if err != nil {
		t.Fatal(err)
	}
	want := "internal/i18n/catalog/fr.json:3,docs/guide/x.fr.md:1"
	if got := strings.Join(hits, ","); got != want {
		t.Errorf("planted hits = %q, want %q", got, want)
	}

	hits, err = scanTutoiement(moduleRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) > 0 {
		t.Errorf("French text must use tutoiement (tu/ton/ta/tes), found:\n  %s", strings.Join(hits, "\n  "))
	}
}
