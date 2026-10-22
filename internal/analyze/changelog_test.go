package analyze

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// setupChangelog builds a temp project with the fixture installed as
// vendor/acme/vuln/<name> and returns its root.
func setupChangelog(t *testing.T, fixture, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "changelog", fixture))
	if err != nil {
		t.Fatal(err)
	}
	return setupChangelogBytes(t, data, name)
}

func setupChangelogBytes(t *testing.T, data []byte, name string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "vendor", "acme", "vuln")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestChangelogExcerptBetweenVersions(t *testing.T) {
	root := setupChangelog(t, "keepachangelog.md", "CHANGELOG.md")
	cl := ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "1.2.0")
	if !cl.Available || cl.Source != "vendor/acme/vuln/CHANGELOG.md" {
		t.Fatalf("%+v", cl)
	}
	for _, want := range []string{"## [1.1.0]", "## [1.2.0]"} {
		if !strings.Contains(cl.Excerpt, want) {
			t.Errorf("missing %q in %q", want, cl.Excerpt)
		}
	}
	for _, no := range []string{"## [1.0.0]", "## [1.3.0]", "Unreleased"} {
		if strings.Contains(cl.Excerpt, no) {
			t.Errorf("unexpected %q in %q", no, cl.Excerpt)
		}
	}
}

func TestChangelogDetectsBreaking(t *testing.T) {
	root := setupChangelog(t, "breaking.md", "CHANGES.md")
	cl := ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "2.0.0")
	if !cl.Breaking || len(cl.BreakingLines) == 0 || cl.BreakingLines[0] != "### Removed" {
		t.Fatalf("%+v", cl)
	}
	// Breaking is evaluated on the kept excerpt only.
	cl = ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "1.9.0")
	if cl.Breaking || !strings.Contains(cl.Excerpt, "Minor stuff") {
		t.Fatalf("%+v", cl)
	}
}

func TestChangelogUnavailableWithoutVendor(t *testing.T) {
	cl := ReadChangelog(t.TempDir(), "composer.lock", "Packagist", "acme/vuln", "1.0.0", "1.2.0")
	if cl.Available || cl.Excerpt != "" || cl.Note != "not installed locally" {
		t.Fatalf("%+v", cl)
	}
}

func TestChangelogNoFileAndNoTarget(t *testing.T) {
	root := setupChangelogBytes(t, []byte("x"), "README.md")
	cl := ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "1.2.0")
	if cl.Available || cl.Note != "no changelog file" {
		t.Fatalf("%+v", cl)
	}
	root = setupChangelog(t, "keepachangelog.md", "CHANGELOG.md")
	cl = ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "")
	if !cl.Available || cl.Excerpt != "" || cl.Note != "no target version" {
		t.Fatalf("%+v", cl)
	}
}

func TestChangelogNoVersionHeadings(t *testing.T) {
	root := setupChangelog(t, "plain.md", "changelog.txt")
	cl := ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "2.0.0")
	if !cl.Available || cl.Note != "no version headings" || !strings.Contains(cl.Excerpt, "v1.5.0") || !cl.Breaking {
		t.Fatalf("%+v", cl)
	}
}

func TestChangelogCapAt4096(t *testing.T) {
	var b strings.Builder
	b.WriteString("## 1.1.0\n\n")
	for i := 0; i < 600; i++ {
		b.WriteString("- ligne é removed ok\n")
	}
	root := setupChangelogBytes(t, []byte(b.String()), "CHANGELOG.md")
	cl := ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "1.1.0")
	if len(cl.Excerpt) == 0 || len(cl.Excerpt) > 4096 || !utf8.ValidString(cl.Excerpt) {
		t.Fatalf("len=%d", len(cl.Excerpt))
	}
	if !strings.HasSuffix(cl.Excerpt, "ok") {
		t.Errorf("not cut on a line boundary: %q", cl.Excerpt[len(cl.Excerpt)-10:])
	}
	if len(cl.BreakingLines) != 20 {
		t.Errorf("breaking lines = %d", len(cl.BreakingLines))
	}
	// No version headings: first 4096 bytes, one giant multibyte line cut on a rune.
	root = setupChangelogBytes(t, []byte(strings.Repeat("é", 5000)), "CHANGELOG.md")
	cl = ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "1.1.0")
	if len(cl.Excerpt) > 4096 || !utf8.ValidString(cl.Excerpt) {
		t.Fatalf("len=%d valid=%v", len(cl.Excerpt), utf8.ValidString(cl.Excerpt))
	}
}

func TestChangelogCRLFNpmScopedAndLarge(t *testing.T) {
	data, _ := os.ReadFile(filepath.Join("testdata", "changelog", "keepachangelog.md"))
	crlf := strings.ReplaceAll(string(data), "\n", "\r\n")
	root := t.TempDir()
	dir := filepath.Join(root, "web", "node_modules", "@acme", "vuln")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "History.md"), []byte(crlf), 0o644)
	cl := ReadChangelog(root, "web/package-lock.json", "npm", "@acme/vuln", "1.0.0", "1.1.0")
	if !cl.Available || cl.Source != "web/node_modules/@acme/vuln/History.md" ||
		strings.Contains(cl.Excerpt, "\r") || !strings.Contains(cl.Excerpt, "## [1.1.0]") {
		t.Fatalf("%+v", cl)
	}
	os.WriteFile(filepath.Join(dir, "CHANGELOG.md"), make([]byte, 2<<20+1), 0o644)
	cl = ReadChangelog(root, "web/package-lock.json", "npm", "@acme/vuln", "1.0.0", "1.1.0")
	if cl.Available || cl.Note != "changelog too large" || cl.Source == "" {
		t.Fatalf("%+v", cl)
	}
}
