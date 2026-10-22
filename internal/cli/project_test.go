package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/store"
)

type auditRow struct {
	action, target, result string
	evidence               map[string]any
}

func auditRows(t *testing.T, dir, action string) []auditRow {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.DB().Query(`SELECT action, target, result, evidence FROM audit_event WHERE action=? ORDER BY rowid`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		var ev string
		if err := rows.Scan(&r.action, &r.target, &r.result, &ev); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal([]byte(ev), &r.evidence)
		out = append(out, r)
	}
	return out
}

func countProjects(t *testing.T, dir string) int {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM project`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestProjectAddDeniedIsAudited(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(t.TempDir(), "nope")
	_, _, _, err := run(t, dir, "project", "add", missing, "--name", "shop", "--test-cmd", "TOKEN=abc make test")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"Cannot add project", "is not a directory", "composer.lock"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	ev := auditRows(t, dir, "project.add")
	if len(ev) != 1 || ev[0].result != "denied" || ev[0].target != "shop" {
		t.Fatalf("events = %+v", ev)
	}
	if r, _ := ev[0].evidence["reason"].(string); !strings.Contains(r, "is not a directory") {
		t.Errorf("reason = %v", ev[0].evidence)
	}
	if n := countProjects(t, dir); n != 0 {
		t.Errorf("project rows = %d", n)
	}
}

func TestProjectAddOKAuditHasNoCommands(t *testing.T) {
	dir, proj := t.TempDir(), t.TempDir()
	_, out, _, err := run(t, dir, "project", "add", proj, "--name", "shop", "--fix-level", "2",
		"--classification", "internal", "--test-cmd", "TOKEN=abc make test", "--install-cmd", "npm ci")
	if err != nil {
		t.Fatal(err)
	}
	want := "Added project shop (" + filepath.Clean(proj) + "), classification internal, fix level 2.\n"
	if out != want {
		t.Errorf("out = %q, want %q", out, want)
	}
	ev := auditRows(t, dir, "project.add")
	if len(ev) != 1 || ev[0].result != "ok" || ev[0].evidence["classification"] != "internal" || ev[0].evidence["fix_level"] != float64(2) {
		t.Fatalf("events = %+v", ev)
	}
	if _, has := ev[0].evidence["test_cmd"]; has {
		t.Error("test_cmd leaked into audit evidence")
	}
	for k, v := range ev[0].evidence {
		if s, ok := v.(string); ok && strings.Contains(s, "TOKEN") {
			t.Errorf("evidence %s leaks command: %q", k, s)
		}
	}
}

func TestProjectAddDefaultsFromPolicyAndFixLevelZero(t *testing.T) {
	dir, proj := t.TempDir(), t.TempDir()
	_, out, _, err := run(t, dir, "project", "add", proj, "--name", "a")
	if err != nil || !strings.Contains(out, "classification sensitive, fix level 1.") {
		t.Fatalf("out=%q err=%v", out, err)
	}
	_, out, _, err = run(t, dir, "project", "add", proj, "--name", "b", "--fix-level", "0")
	if err != nil || !strings.Contains(out, "fix level 0.") {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestProjectAddRejectsDuplicateAndBadValues(t *testing.T) {
	dir, proj := t.TempDir(), t.TempDir()
	if _, _, _, err := run(t, dir, "project", "add", proj, "--name", "a"); err != nil {
		t.Fatal(err)
	}
	cases := [][]string{
		{"--name", "a"},
		{"--name", "b", "--fix-level", "9"},
		{"--name", "b", "--classification", "secret"},
		{"--name", " "},
	}
	for _, c := range cases {
		_, _, _, err := run(t, dir, append([]string{"project", "add", proj}, c...)...)
		if err == nil || !strings.HasPrefix(err.Error(), "Cannot add project") {
			t.Errorf("%v: err = %v", c, err)
		}
	}
	ev := auditRows(t, dir, "project.add")
	if len(ev) != 5 || ev[4].result != "denied" {
		t.Errorf("events = %d", len(ev))
	}
	if n := countProjects(t, dir); n != 1 {
		t.Errorf("project rows = %d", n)
	}
}

func TestProjectListTable(t *testing.T) {
	dir, proj := t.TempDir(), t.TempDir()
	run(t, dir, "project", "add", proj, "--name", "zeta")
	run(t, dir, "project", "add", proj, "--name", "alpha", "--classification", "health", "--fix-level", "3")
	_, out, _, err := run(t, dir, "project", "list")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("out = %q", out)
	}
	if f := strings.Fields(lines[0]); strings.Join(f, " ") != "name classification fix_level active path" {
		t.Errorf("header = %q", lines[0])
	}
	if f := strings.Fields(lines[1]); len(f) < 5 || f[0] != "alpha" || f[1] != "health" || f[2] != "3" || f[3] != "true" || f[4] != filepath.Clean(proj) {
		t.Errorf("row = %q", lines[1])
	}
	if !strings.HasPrefix(lines[2], "zeta") {
		t.Errorf("row 2 = %q", lines[2])
	}

	_, out, _, err = run(t, dir, "--json", "project", "list")
	var j []map[string]any
	if err != nil || json.Unmarshal([]byte(out), &j) != nil || len(j) != 2 || j[0]["name"] != "alpha" {
		t.Errorf("json out=%q err=%v", out, err)
	}
	if n := len(auditRows(t, dir, "project.list")); n != 0 {
		t.Errorf("list should not be audited, got %d", n)
	}
}

func TestProjectListEmpty(t *testing.T) {
	_, out, _, err := run(t, t.TempDir(), "--json", "project", "list")
	if err != nil || strings.TrimSpace(out) != "[]" {
		t.Errorf("out=%q err=%v", out, err)
	}
}

func TestProjectRemove(t *testing.T) {
	dir, proj := t.TempDir(), t.TempDir()
	run(t, dir, "project", "add", proj, "--name", "shop")
	_, out, _, err := run(t, dir, "project", "remove", "shop")
	if err != nil || out != "Removed project shop.\n" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	_, _, _, err = run(t, dir, "project", "remove", "shop")
	if err == nil || !strings.Contains(err.Error(), "Cannot remove project shop") {
		t.Errorf("err = %v", err)
	}
	ev := auditRows(t, dir, "project.remove")
	if len(ev) != 2 || ev[0].result != "ok" || ev[1].result != "not_found" || ev[1].target != "shop" {
		t.Errorf("events = %+v", ev)
	}
}
