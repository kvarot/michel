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
	if !cl.Available || cl.Note != NoteNoVersionHeadings || !cl.VersionsUnread() ||
		!strings.Contains(cl.Excerpt, "v1.5.0") || cl.Breaking || cl.BreakingLines != nil {
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

func TestChangelogSubHeadingsAndCodeDoNotSplitSections(t *testing.T) {
	doc := "# Changelog\n\n## 2.0.0\n\n### Dropped support for PHP 7.4\n\n### Next steps\n\n```sh\n# comment 2.0\n## 1.0.0\n```\n\n~~~\n## Unreleased\n~~~\n\nend of two\n\n## 1.0.0\n\n- first\n"
	root := setupChangelogBytes(t, []byte(doc), "CHANGELOG.md")
	cl := ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "2.0.0")
	for _, want := range []string{"### Dropped support for PHP 7.4", "### Next steps", "# comment 2.0", "## Unreleased", "end of two"} {
		if !strings.Contains(cl.Excerpt, want) {
			t.Errorf("missing %q in %q", want, cl.Excerpt)
		}
	}
	if strings.Contains(cl.Excerpt, "- first") {
		t.Errorf("1.0.0 section leaked: %q", cl.Excerpt)
	}
	if !cl.Breaking || cl.BreakingLines[0] != "### Dropped support for PHP 7.4" {
		t.Errorf("%+v", cl)
	}
}

func TestChangelogUnreleasedExactAndPrerelease(t *testing.T) {
	doc := "## [Unreleased]\n\n- wip\n\n## v2.0.0-rc.1 (2024)\n\n- rc\n\n## 1.5.0\n\n- old\n"
	root := setupChangelogBytes(t, []byte(doc), "CHANGELOG.md")
	cl := ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.5.0", "2.0.0")
	if !strings.Contains(cl.Excerpt, "v2.0.0-rc.1") || strings.Contains(cl.Excerpt, "wip") || strings.Contains(cl.Excerpt, "old") {
		t.Fatalf("%q", cl.Excerpt)
	}
}

func TestChangelogRejectsDotDotPackage(t *testing.T) {
	root := setupChangelog(t, "keepachangelog.md", "CHANGELOG.md")
	cl := ReadChangelog(root, "composer.lock", "Packagist", "acme/../acme/vuln", "1.0.0", "1.2.0")
	if cl.Available || cl.Note != "invalid package name" {
		t.Fatalf("%+v", cl)
	}
}

func TestChangelogBreakingWordBoundariesAndTruncNote(t *testing.T) {
	root := setupChangelogBytes(t, []byte("## 1.1.0\n\n- unremoved things, nonbreaking\n"), "CHANGELOG.md")
	cl := ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "1.1.0")
	if cl.Breaking {
		t.Fatalf("%+v", cl)
	}
	// The 4097th byte is a newline: the full 4096-byte line is kept.
	doc := "## 1.1.0\n" + strings.Repeat("a", 4087) + "\nbbbb\n"
	root = setupChangelogBytes(t, []byte(doc), "CHANGELOG.md")
	cl = ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "1.1.0")
	if len(cl.Excerpt) != 4096 || strings.Contains(cl.Excerpt, "bbbb") || cl.Note != "excerpt truncated" {
		t.Fatalf("len=%d note=%q", len(cl.Excerpt), cl.Note)
	}
	// Mid-rune cut: "a" + é×N leaves byte 4096 inside a rune.
	root = setupChangelogBytes(t, []byte("a"+strings.Repeat("é", 5000)), "CHANGELOG.md")
	cl = ReadChangelog(root, "composer.lock", "Packagist", "acme/vuln", "1.0.0", "1.1.0")
	if len(cl.Excerpt) != 4095 || !utf8.ValidString(cl.Excerpt) {
		t.Fatalf("len=%d", len(cl.Excerpt))
	}
}
