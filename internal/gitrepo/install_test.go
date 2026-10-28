package gitrepo

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/source"
)

const demoSkill = "---\nname: demo\ndescription: an example skill\n---\n\n# Demo\n\nline\x1b[31m with a control character\n"

func TestPreviewShowsHeadLicenseAndTarget(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.archives[shaA] = skillArchive(t, demoSkill)
	d := testDeps(t)
	e := addEntry(t, d, source.KindSkill, "skill", "skills/demo", nil)
	e.Status = map[string]any{"stars": float64(12), "pushed_at": "2026-10-01T00:00:00Z", "archived": false}
	p, err := PreviewInstall(context.Background(), d, e, shaA)
	if err != nil {
		t.Fatal(err)
	}
	if p.SHA != shaA || p.Repo != "example/skill" || p.Key != e.Key {
		t.Errorf("identity = %+v", p)
	}
	if p.License.SPDX != "MIT" {
		t.Errorf("license = %+v", p.License)
	}
	if len(p.Head) < 3 || p.Head[0] != "---" || p.Head[1] != "name: demo" {
		t.Errorf("head = %q", p.Head)
	}
	for _, l := range p.Head {
		if strings.ContainsRune(l, '\x1b') {
			t.Errorf("head keeps a control character: %q", l)
		}
	}
	if p.WillWrite != filepath.Join(d.SkillsDir, "demo") {
		t.Errorf("will write = %q", p.WillWrite)
	}
	if len(p.Files) != 2 || p.Files[0].Path != "SKILL.md" || p.Files[1].Path != "run.sh" {
		t.Errorf("files = %+v", p.Files)
	}
	if p.Trust.Stars != 12 || p.Trust.PushedAt != "2026-10-01T00:00:00Z" || p.Trust.Archived != "no" || p.Trust.InCatalog {
		t.Errorf("trust = %+v", p.Trust)
	}
	if p.Launch != "" {
		t.Errorf("a skill has no launch line: %q", p.Launch)
	}
	// The archive is kept: a second preview does not download again.
	n := gh.count()
	if _, err := PreviewInstall(context.Background(), d, e, shaA); err != nil || gh.count() != n {
		t.Errorf("second preview: err %v, requests %d -> %d", err, n, gh.count())
	}
}

func TestMCPPreviewPrintsClaudeMCPAddLine(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.archives[shaA] = skillArchive(t, demoSkill)
	d := testDeps(t)
	e := addEntry(t, d, source.KindMCP, "demo", "", map[string]any{"launch": map[string]any{"command": "demo-server", "args": []any{"mcp", "--stdio"}}})
	p, err := PreviewInstall(context.Background(), d, e, shaA)
	if err != nil {
		t.Fatal(err)
	}
	if want := "claude mcp add --scope user demo -- demo-server mcp --stdio"; p.Launch != want {
		t.Errorf("launch = %q, want %q", p.Launch, want)
	}
	if p.WillWrite != "" {
		t.Errorf("an MCP server writes nothing outside the data folder: %q", p.WillWrite)
	}
	if len(p.Head) == 0 || p.Head[0] != "# example/skill" {
		t.Errorf("head = %q", p.Head)
	}
	e = addEntry(t, d, source.KindMCP, "bare", "", nil)
	if p, err := PreviewInstall(context.Background(), d, e, shaA); err != nil || p.Launch != "" {
		t.Errorf("no launch: %q %v", p.Launch, err)
	}
}

func readMarkerT(t *testing.T, dir string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, MarkerFile))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestInstallWritesMarkerAndRefusesForeignDir(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.archives[shaA] = skillArchive(t, demoSkill)
	d := testDeps(t)
	ctx := context.Background()
	e := addEntry(t, d, source.KindSkill, "skill", "skills/demo", nil)
	to, err := Install(ctx, d, e, shaA)
	if err != nil {
		t.Fatal(err)
	}
	if to != filepath.Join(d.SkillsDir, "demo") {
		t.Errorf("installed to %q", to)
	}
	if b, err := os.ReadFile(filepath.Join(to, "SKILL.md")); err != nil || string(b) != demoSkill {
		t.Errorf("SKILL.md: %q %v", b, err)
	}
	if m := readMarkerT(t, to); m["key"] != e.Key || m["sha"] != shaA || m["installed_at"] == "" {
		t.Errorf("marker = %v", m)
	}
	if _, err := os.Stat(filepath.Join(to, "..", "notes.md")); err == nil {
		t.Error("a file from outside the skill folder was installed")
	}
	got, err := d.Repo.Get(ctx, e.Key)
	if err != nil {
		t.Fatal(err)
	}
	if got.Config.Str("installed_sha") != shaA || got.Config.Str("install_dir") != to {
		t.Errorf("config = %+v", got.Config.User)
	}
	// Installing again over its own folder is fine.
	if _, err := Install(ctx, d, got, shaA); err != nil {
		t.Errorf("reinstall: %v", err)
	}

	// A folder of the same name without Michel's marker is never touched.
	d2 := d
	d2.SkillsDir = t.TempDir()
	foreign := filepath.Join(d2.SkillsDir, "demo")
	os.MkdirAll(foreign, 0o755)
	os.WriteFile(filepath.Join(foreign, "SKILL.md"), []byte("mine"), 0o644)
	if _, err := Install(ctx, d2, e, shaA); !errors.Is(err, ErrForeignDir) {
		t.Fatalf("foreign folder: err = %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(foreign, "SKILL.md")); string(b) != "mine" {
		t.Errorf("the foreign folder was changed: %q", b)
	}
	// Nor is one installed for another source.
	os.WriteFile(filepath.Join(foreign, MarkerFile), []byte(`{"key":"skill.other","sha":"x"}`), 0o644)
	if _, err := Install(ctx, d2, e, shaA); !errors.Is(err, ErrForeignDir) {
		t.Errorf("other source's folder: err = %v", err)
	}
}

func TestInstallRefusesABadSkillName(t *testing.T) {
	gh := newFakeGitHub(t)
	d := testDeps(t)
	for _, name := range []string{"..", "a/b", `a\b`, ".", "...", ""} {
		gh.archives[shaA] = skillArchive(t, "---\nname: \""+strings.ReplaceAll(name, `\`, `\\`)+"\"\n---\n")
		os.RemoveAll(filepath.Join(d.DataDir, "sources"))
		e := addEntry(t, d, source.KindSkill, "skill", "skills/demo", nil)
		_, err := Install(context.Background(), d, e, shaA)
		if name == "" {
			// No name: the folder's own name is used.
			if err != nil {
				t.Errorf("empty name: %v", err)
			}
			continue
		}
		if !errors.Is(err, ErrBadName) {
			t.Errorf("name %q: err = %v", name, err)
		}
	}
}

func TestInstallWritesNothingOnBadArchive(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.archives[shaA] = buildTarGz(t, file("skills/demo/SKILL.md", demoSkill), tarEntry{name: "skill-" + shaA + "/../../evil", body: "x"})
	d := testDeps(t)
	e := addEntry(t, d, source.KindSkill, "skill", "skills/demo", nil)
	if _, err := Install(context.Background(), d, e, shaA); !errors.Is(err, ErrTraversal) {
		t.Fatalf("err = %v", err)
	}
	if list, _ := os.ReadDir(d.SkillsDir); len(list) != 0 {
		t.Errorf("skills folder not empty: %v", list)
	}
	if _, err := os.Stat(filepath.Join(d.DataDir, "sources", "repos", e.Key, shaA)); err == nil {
		t.Error("the bad archive was kept")
	}
	if list, _ := os.ReadDir(filepath.Join(d.DataDir, "sources", "repos", e.Key)); len(list) != 0 {
		t.Errorf("leftovers: %v", list)
	}
}

func TestInstallRefusesASkillsDirInsideAProject(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.archives[shaA] = skillArchive(t, demoSkill)
	d := testDeps(t)
	project := t.TempDir()
	d.SkillsDir = filepath.Join(project, ".claude", "skills")
	d.Forbidden = []string{project}
	e := addEntry(t, d, source.KindSkill, "skill", "skills/demo", nil)
	if _, err := Install(context.Background(), d, e, shaA); !errors.Is(err, ErrInsideProject) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(project, ".claude")); err == nil {
		t.Error("something was written in the project")
	}
}

func TestUninstallOnlyWithMatchingMarker(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.archives[shaA] = skillArchive(t, demoSkill)
	d := testDeps(t)
	ctx := context.Background()
	e := addEntry(t, d, source.KindSkill, "skill", "skills/demo", nil)
	to, err := Install(ctx, d, e, shaA)
	if err != nil {
		t.Fatal(err)
	}
	e, _ = d.Repo.Get(ctx, e.Key)
	// Someone else's marker: refused, nothing removed.
	os.WriteFile(filepath.Join(to, MarkerFile), []byte(`{"key":"skill.other","sha":"`+shaA+`"}`), 0o644)
	if err := Uninstall(ctx, d, e); !errors.Is(err, ErrForeignDir) {
		t.Fatalf("other marker: err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(to, "SKILL.md")); err != nil {
		t.Fatal("the folder was removed")
	}
	os.WriteFile(filepath.Join(to, MarkerFile), []byte(`{"key":"`+e.Key+`","sha":"`+shaA+`"}`), 0o644)
	if err := Uninstall(ctx, d, e); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(to); !os.IsNotExist(err) {
		t.Errorf("folder still there: %v", err)
	}
	got, _ := d.Repo.Get(ctx, e.Key)
	if got.Config.Str("installed_sha") != "" || got.Config.Str("install_dir") != "" {
		t.Errorf("config = %+v", got.Config.User)
	}
}

func TestUpgradeDiffListsChanges(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.archives[shaA] = skillArchive(t, demoSkill)
	gh.archives[shaB] = buildTarGz(t, file("LICENSE", "Permission is hereby granted, free of charge"),
		file("skills/demo/SKILL.md", strings.Replace(demoSkill, "# Demo", "# Demo 2", 1)), file("skills/demo/new.md", "new"))
	d := testDeps(t)
	ctx := context.Background()
	e := addEntry(t, d, source.KindSkill, "skill", "skills/demo", nil)
	if _, err := Install(ctx, d, e, shaA); err != nil {
		t.Fatal(err)
	}
	e, _ = d.Repo.Get(ctx, e.Key)
	diff, err := Upgrade(ctx, d, e, shaB)
	if err != nil {
		t.Fatal(err)
	}
	if diff.From != shaA || diff.To != shaB {
		t.Errorf("from/to = %s %s", diff.From, diff.To)
	}
	if strings.Join(diff.Added, ",") != "new.md" || strings.Join(diff.Changed, ",") != "SKILL.md" || strings.Join(diff.Removed, ",") != "run.sh" {
		t.Errorf("diff = %+v", diff)
	}
	if !strings.Contains(diff.SkillMDDiff, "-# Demo\n") || !strings.Contains(diff.SkillMDDiff, "+# Demo 2\n") {
		t.Errorf("SKILL.md diff:\n%s", diff.SkillMDDiff)
	}
	// Upgrade only shows: the installed version is unchanged until Install.
	if b, _ := os.ReadFile(filepath.Join(d.SkillsDir, "demo", "SKILL.md")); string(b) != demoSkill {
		t.Error("upgrade changed the installed skill")
	}
	to, err := Install(ctx, d, e, shaB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(to, "run.sh")); err == nil {
		t.Error("a removed file is still installed")
	}
	got, _ := d.Repo.Get(ctx, e.Key)
	if got.Config.Str("pinned") != shaB || got.Config.Str("installed_sha") != shaB {
		t.Errorf("not pinned again: %+v", got.Config.User)
	}
}

func TestUpgradeKeepsAnUnmarkedOldFolder(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.archives[shaA] = skillArchive(t, demoSkill)
	gh.archives[shaB] = buildTarGz(t, file("skills/demo/SKILL.md", demoSkill+"more\n"))
	d := testDeps(t)
	ctx := context.Background()
	e := addEntry(t, d, source.KindSkill, "skill", "skills/demo", nil)
	if _, err := Install(ctx, d, e, shaA); err != nil {
		t.Fatal(err)
	}
	// A folder with the name the old code used for its aside copy.
	mine := filepath.Join(d.SkillsDir, "demo.michel-old")
	os.MkdirAll(mine, 0o755)
	os.WriteFile(filepath.Join(mine, "SKILL.md"), []byte("mine"), 0o644)
	e, _ = d.Repo.Get(ctx, e.Key)
	if _, err := Install(ctx, d, e, shaB); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(mine, "SKILL.md")); err != nil || string(b) != "mine" {
		t.Errorf("the unmarked folder was touched: %q %v", b, err)
	}
	list, _ := os.ReadDir(d.SkillsDir)
	for _, f := range list {
		if strings.HasPrefix(f.Name(), ".michel-") {
			t.Errorf("leftover %s", f.Name())
		}
	}
}

func TestUpgradeRefusesARenamedSkill(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.archives[shaA] = skillArchive(t, demoSkill)
	gh.archives[shaB] = buildTarGz(t, file("skills/demo/SKILL.md", strings.Replace(demoSkill, "name: demo", "name: renamed", 1)))
	d := testDeps(t)
	ctx := context.Background()
	e := addEntry(t, d, source.KindSkill, "skill", "skills/demo", nil)
	if _, err := Install(ctx, d, e, shaA); err != nil {
		t.Fatal(err)
	}
	e, _ = d.Repo.Get(ctx, e.Key)
	if _, err := Upgrade(ctx, d, e, shaB); !errors.Is(err, ErrSkillRenamed) {
		t.Fatalf("upgrade: err = %v", err)
	}
	if _, err := Install(ctx, d, e, shaB); !errors.Is(err, ErrSkillRenamed) {
		t.Fatalf("install: err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(d.SkillsDir, "renamed")); err == nil {
		t.Error("the new folder was written")
	}
	if b, _ := os.ReadFile(filepath.Join(d.SkillsDir, "demo", "SKILL.md")); string(b) != demoSkill {
		t.Error("the installed skill changed")
	}
	if got, _ := d.Repo.Get(ctx, e.Key); got.Config.Str("installed_sha") != shaA {
		t.Errorf("config = %+v", got.Config.User)
	}
}

func TestSkillNameRefusesReservedNames(t *testing.T) {
	for _, n := range []string{"CON", "con", "Nul.txt", "aux.md", "PRN", "com1", "LPT9.x", "demo.", "demo..", "a b"} {
		if validSkillName(n) {
			t.Errorf("%q accepted", n)
		}
	}
	for _, n := range []string{"demo", "console", "com10", "lpt0", "nul-check", "owasp-security", "a.b"} {
		if !validSkillName(n) {
			t.Errorf("%q refused", n)
		}
	}
}

func TestUninstallRevalidatesInstallDir(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.archives[shaA] = skillArchive(t, demoSkill)
	d := testDeps(t)
	ctx := context.Background()
	e := addEntry(t, d, source.KindSkill, "skill", "skills/demo", nil)
	if _, err := Install(ctx, d, e, shaA); err != nil {
		t.Fatal(err)
	}
	// A folder outside the skills folder, even carrying the right marker.
	elsewhere := filepath.Join(t.TempDir(), "demo")
	os.MkdirAll(elsewhere, 0o755)
	os.WriteFile(filepath.Join(elsewhere, MarkerFile), []byte(`{"key":"`+e.Key+`","sha":"`+shaA+`"}`), 0o644)
	e, _ = d.Repo.Get(ctx, e.Key)
	user := e.Config.User
	user["install_dir"] = elsewhere
	if err := d.Repo.SetUserConfig(ctx, e.Key, user); err != nil {
		t.Fatal(err)
	}
	e, _ = d.Repo.Get(ctx, e.Key)
	if err := Uninstall(ctx, d, e); !errors.Is(err, ErrForeignDir) {
		t.Fatalf("outside: err = %v", err)
	}
	if _, err := os.Stat(elsewhere); err != nil {
		t.Error("a folder outside the skills folder was removed")
	}
	// A reserved base name inside the skills folder is refused too.
	user["install_dir"] = filepath.Join(d.SkillsDir, "NUL")
	d.Repo.SetUserConfig(ctx, e.Key, user)
	e, _ = d.Repo.Get(ctx, e.Key)
	if err := Uninstall(ctx, d, e); !errors.Is(err, ErrForeignDir) {
		t.Errorf("reserved name: err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(d.SkillsDir, "demo", "SKILL.md")); err != nil {
		t.Error("the installed skill was removed")
	}
}
