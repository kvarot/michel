package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/gitrepo"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

const demoPin = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"

// demoSkillArchive is the archive of example/skill: a skill under
// skills/demo and a licence at the root.
func demoSkillArchive(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{
		"LICENSE":              "MIT License\n\nPermission is hereby granted, free of charge, to any person",
		"skills/demo/SKILL.md": "---\nname: demo\ndescription: an example skill\n---\n\n# Demo\n",
	} {
		if err := tw.WriteHeader(&tar.Header{Name: "skill-" + demoPin + "/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	return b.Bytes()
}

// setupSkill serves the archive, points the skills folder at a temporary
// folder, writes the network rules and adds and enables skill.demo. It
// returns the data folder and the skills folder.
func setupSkill(t *testing.T) (dir, skills string) {
	t.Helper()
	arch := demoSkillArchive(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/example/skill/tar.gz/"+demoPin {
			http.NotFound(w, r)
			return
		}
		w.Write(arch)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(gitrepo.SetBaseURLsForTest(srv.URL, srv.URL))
	skills = filepath.Join(t.TempDir(), "skills")
	t.Setenv(gitrepo.SkillsDirEnv, skills)
	dir = t.TempDir()
	cfg := "sovereignty:\n  network:\n    default_egress: deny\n    allow:\n" +
		"      - {host: api.github.com, purpose: source.repo}\n      - {host: codeload.github.com, purpose: source.repo}\n" +
		"      - {host: 127.0.0.1, purpose: source.repo}\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, out, _, err := run(t, dir, "source", "add", "--kind", "skill", "--repo", "example/skill", "--pin", demoPin, "--path", "skills/demo", "--name", "demo"); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if _, out, _, err := run(t, dir, "source", "enable", "skill.demo", "--yes"); err != nil {
		t.Fatalf("enable: %v\n%s", err, out)
	}
	return dir, skills
}

func TestSourceInstallNeedsYes(t *testing.T) {
	dir, skills := setupSkill(t)
	_, _, errOut, err := run(t, dir, "--lang", "en", "source", "install", "skill.demo")
	if err == nil || ExitCode(err) != ExitCodePolicy || !strings.Contains(err.Error(), "michel source install skill.demo --yes") {
		t.Fatalf("err = %v (code %d)", err, ExitCode(err))
	}
	for _, want := range []string{"Before installing skill.demo", "Licence: MIT", "| name: demo", filepath.Join(skills, "demo"), "never runs anything"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("preview lacks %q:\n%s", want, errOut)
		}
	}
	if _, err := os.Stat(skills); !os.IsNotExist(err) {
		t.Errorf("something was written in the skills folder: %v", err)
	}
	if e, _ := sourceEntry(t, dir, "skill.demo"); e.Config.Str("installed_sha") != "" {
		t.Error("marked installed without consent")
	}
}

func TestSourceInstallYesCopiesSkill(t *testing.T) {
	dir, skills := setupSkill(t)
	_, out, _, err := run(t, dir, "--lang", "en", "source", "install", "skill.demo", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "skill.demo is installed in "+filepath.Join(skills, "demo")) {
		t.Errorf("out = %s", out)
	}
	if b, err := os.ReadFile(filepath.Join(skills, "demo", "SKILL.md")); err != nil || !strings.Contains(string(b), "# Demo") {
		t.Errorf("SKILL.md: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(skills, "demo", gitrepo.MarkerFile)); err != nil {
		t.Errorf("marker: %v", err)
	}
	e, _ := sourceEntry(t, dir, "skill.demo")
	if e.Config.Str("installed_sha") != demoPin {
		t.Errorf("config = %+v", e.Config.User)
	}
	if acts := auditActions(t, dir); indexOf(acts, "source.install") < 0 {
		t.Errorf("no source.install event: %v", acts)
	}
}

func TestSourceRemoveUninstallsSkill(t *testing.T) {
	dir, skills := setupSkill(t)
	if _, out, _, err := run(t, dir, "source", "install", "skill.demo", "--yes"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// Without --yes and without a terminal: refused, nothing removed.
	if _, _, _, err := run(t, dir, "source", "remove", "skill.demo"); err == nil || ExitCode(err) != ExitCodePolicy {
		t.Fatalf("remove without --yes: %v", err)
	}
	if _, err := os.Stat(filepath.Join(skills, "demo", "SKILL.md")); err != nil {
		t.Fatal("removed without consent")
	}
	_, out, _, err := run(t, dir, "--lang", "en", "source", "remove", "skill.demo", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "skill.demo is uninstalled.") || !strings.Contains(out, "Removed skill.demo.") {
		t.Errorf("out = %s", out)
	}
	if _, err := os.Stat(filepath.Join(skills, "demo")); !os.IsNotExist(err) {
		t.Errorf("skill folder still there: %v", err)
	}
	if _, err := sourceEntry(t, dir, "skill.demo"); err == nil {
		t.Error("the entry is still there")
	}
}

func TestSourceInstallRefusesAForeignFolder(t *testing.T) {
	dir, skills := setupSkill(t)
	os.MkdirAll(filepath.Join(skills, "demo"), 0o755)
	os.WriteFile(filepath.Join(skills, "demo", "SKILL.md"), []byte("mine"), 0o644)
	_, _, _, err := run(t, dir, "--lang", "en", "source", "install", "skill.demo", "--yes")
	if err == nil || !strings.Contains(err.Error(), "Michel did not install it") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(skills, "demo", "SKILL.md")); string(b) != "mine" {
		t.Error("the foreign folder was changed")
	}
}

func TestSourceDiscoverAddsAndIgnores(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := run(t, dir, "noop"); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, dir)
	if _, err := s.DB().Exec(`INSERT INTO discovery (repo, topic, stars, description, html_url, first_seen_at, state) VALUES
		('example/mcp', 'mcp-security', 7, 'an MCP server', 'https://github.com/example/mcp', '2026-10-28T00:00:00Z', 'new'),
		('example/other', 'claude-skills', 3, 'other', '', '2026-10-28T00:00:00Z', 'new')`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, out, _, err := run(t, dir, "--lang", "en", "source", "discover")
	if err != nil || !strings.Contains(out, "example/mcp") || !strings.Contains(out, "example/other") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if _, out, _, err := run(t, dir, "source", "discover", "--add", "example/mcp", "--kind", "mcp", "--pin", demoPin); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	e, err := sourceEntry(t, dir, "mcp.mcp")
	if err != nil || e.Config.Str("repo") != "example/mcp" || e.Config.Str("pinned") != demoPin || e.Enabled {
		t.Errorf("entry = %+v %v", e, err)
	}
	if _, _, _, err := run(t, dir, "source", "discover", "--ignore", "example/other"); err != nil {
		t.Fatal(err)
	}
	_, out, _, _ = run(t, dir, "--lang", "en", "source", "discover")
	if !strings.Contains(out, "Nothing new to discover") {
		t.Errorf("after add and ignore:\n%s", out)
	}
	if _, _, _, err := run(t, dir, "source", "discover", "--ignore", "example/none"); err == nil {
		t.Error("unknown repository accepted")
	}
}

// openStore opens the database of the data folder dir.
func openStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSourceUpgradeShowsAndAppliesARename(t *testing.T) {
	dir, skills := setupSkill(t)
	const newPin = "1234512345123451234512345123451234512345"
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	body := "---\nname: renamed\n---\n\n# Demo 2\n"
	tw.WriteHeader(&tar.Header{Name: "skill-" + newPin + "/skills/demo/SKILL.md", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write([]byte(body))
	tw.Close()
	gz.Close()
	old := demoSkillArchive(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/example/skill/tar.gz/" + demoPin:
			w.Write(old)
		case "/example/skill/tar.gz/" + newPin:
			w.Write(b.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	defer gitrepo.SetBaseURLsForTest(srv.URL, srv.URL)()
	if _, out, _, err := run(t, dir, "source", "install", "skill.demo", "--yes"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	s := openStore(t, dir)
	if err := source.NewRepo(s).SetStatus(context.Background(), "skill.demo", map[string]any{"new_version": map[string]any{"from": demoPin, "to": newPin}}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, out, errOut, err := run(t, dir, "--lang", "en", "source", "upgrade", "skill.demo", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s\n%s", err, out, errOut)
	}
	want := "its folder moves from " + filepath.Join(skills, "demo") + " to " + filepath.Join(skills, "renamed")
	if !strings.Contains(errOut, want) {
		t.Errorf("preview lacks the move:\n%s", errOut)
	}
	if _, err := os.Stat(filepath.Join(skills, "renamed", gitrepo.MarkerFile)); err != nil {
		t.Errorf("new folder not marked: %v", err)
	}
	if _, err := os.Stat(filepath.Join(skills, "demo")); !os.IsNotExist(err) {
		t.Errorf("old folder still there: %v", err)
	}
}
