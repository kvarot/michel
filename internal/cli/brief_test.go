package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/gitrepo"
)

func TestBriefCommandPrints(t *testing.T) {
	dir, list := scannedDemo(t, true)
	skills := t.TempDir()
	t.Setenv(gitrepo.SkillsDirEnv, skills)

	_, out, _, err := run(t, dir, "brief", list[0].ID, "--lang", "en")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"michel_brief: 1", "## Find", "## Understand", "## Fix", "## Done when"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// Printing alone writes nothing.
	if entries, _ := os.ReadDir(skills); len(entries) != 0 {
		t.Errorf("skills folder not empty: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(dir, "briefs")); err == nil {
		t.Error("briefs folder created by a plain print")
	}

	_, out, _, err = run(t, dir, "brief", list[0].ID, "--write-skill", "--lang", "fr")
	if err != nil || !strings.Contains(out, "Skill créé") {
		t.Fatalf("write-skill: %v\n%s", err, out)
	}
	matches, _ := filepath.Glob(filepath.Join(skills, "michel-fix-*", "SKILL.md"))
	if len(matches) != 1 {
		t.Fatalf("skill files = %v", matches)
	}
	raw, _ := os.ReadFile(matches[0])
	if !strings.Contains(string(raw), "propose_fix") || !strings.Contains(string(raw), "## Trouver") {
		t.Errorf("skill content:\n%s", raw)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(matches[0]), gitrepo.MarkerFile)); err != nil {
		t.Errorf("no marker: %v", err)
	}

	_, out, _, err = run(t, dir, "brief", list[0].ID, "--remove-skill", "--lang", "en")
	if err != nil || !strings.Contains(out, "Skill removed") {
		t.Fatalf("remove-skill: %v\n%s", err, out)
	}
	if m, _ := filepath.Glob(filepath.Join(skills, "michel-fix-*")); len(m) != 0 {
		t.Errorf("skill left: %v", m)
	}
}

func TestBriefCommandWriteKeepsFileInDataDir(t *testing.T) {
	dir, list := scannedDemo(t, true)
	_, out, _, err := run(t, dir, "brief", list[0].ID, "--write", "--lang", "en")
	if err != nil || !strings.Contains(out, "Brief written: ") {
		t.Fatalf("write: %v\n%s", err, out)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "briefs", "*", list[0].ID+".md"))
	if len(files) != 1 {
		t.Fatalf("brief files = %v", files)
	}
	raw, _ := os.ReadFile(files[0])
	if !strings.HasPrefix(string(raw), "---\nmichel_brief: 1\n") {
		t.Errorf("brief file:\n%s", raw)
	}
}

func TestBriefCommandRefusesBothSkillFlags(t *testing.T) {
	dir, list := scannedDemo(t, false)
	if _, _, _, err := run(t, dir, "brief", list[0].ID, "--write-skill", "--remove-skill"); err == nil {
		t.Error("both flags accepted")
	}
	if _, _, _, err := run(t, dir, "brief", "zzzz"); err == nil {
		t.Error("unknown finding accepted")
	}
}
