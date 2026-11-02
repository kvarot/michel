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
	if err != nil || !strings.HasPrefix(out, "Removed project shop: Michel no longer scans it") {
		t.Fatalf("out=%q err=%v", out, err)
	}
	// A second remove is a no-op on an inactive project (behavior changed
	// with the soft delete: it used to be not_found).
	_, out, _, err = run(t, dir, "project", "remove", "shop")
	if err != nil || !strings.Contains(out, "already inactive") {
		t.Errorf("second remove: out=%q err=%v", out, err)
	}
	_, _, _, err = run(t, dir, "project", "remove", "nope")
	if err == nil || !strings.Contains(err.Error(), "Cannot remove project nope") {
		t.Errorf("err = %v", err)
	}
	ev := auditRows(t, dir, "project.remove")
	if len(ev) != 3 || ev[0].result != "ok" || ev[0].evidence["mode"] != "deactivate" ||
		ev[2].result != "not_found" || ev[2].target != "nope" {
		t.Errorf("events = %+v", ev)
	}
}

func scanCount(t *testing.T, dir, table string) int {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestProjectRemoveAfterScanKeepsHistory(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "scan", "--project", "demo", "--osv-db", db); err != nil {
		t.Fatal(err)
	}
	scans, manifests, findings := scanCount(t, dir, "scan"), scanCount(t, dir, "scan_manifest"), scanCount(t, dir, "finding")
	if scans == 0 || manifests == 0 || findings == 0 {
		t.Fatalf("scan left no history: %d %d %d", scans, manifests, findings)
	}
	if _, _, _, err := run(t, dir, "project", "remove", "demo"); err != nil {
		t.Fatalf("remove after scan: %v", err)
	}
	ev := auditRows(t, dir, "project.remove")
	if len(ev) != 1 || ev[0].result != "ok" || ev[0].evidence["mode"] != "deactivate" {
		t.Errorf("events = %+v", ev)
	}
	if scanCount(t, dir, "scan") != scans || scanCount(t, dir, "scan_manifest") != manifests || scanCount(t, dir, "finding") != findings {
		t.Error("soft remove deleted history")
	}
	_, out, _, err := run(t, dir, "--json", "project", "list")
	var list []map[string]any
	if err != nil || json.Unmarshal([]byte(out), &list) != nil || len(list) != 1 || list[0]["active"] != false {
		t.Errorf("list: %v %s", err, out)
	}
	// scan --all skips the inactive project; scanning it by name is refused.
	if _, _, _, err := run(t, dir, "scan", "--all", "--osv-db", db); err == nil || !strings.Contains(err.Error(), "no active project") {
		t.Errorf("scan --all: %v", err)
	}
	if _, _, _, err := run(t, dir, "scan", "--project", "demo", "--osv-db", db); err == nil || !strings.Contains(err.Error(), "was removed") {
		t.Errorf("scan --project: %v", err)
	}
	if scanCount(t, dir, "scan") != scans {
		t.Error("an inactive project was scanned")
	}

	_, out, _, err = run(t, dir, "project", "remove", "demo", "--purge")
	if err != nil || !strings.Contains(out, "cannot be recovered") {
		t.Fatalf("purge: out=%q err=%v", out, err)
	}
	if scanCount(t, dir, "project") != 0 || scanCount(t, dir, "scan") != 0 || scanCount(t, dir, "scan_manifest") != 0 || scanCount(t, dir, "finding") != 0 {
		t.Error("purge left rows behind")
	}
	ev = auditRows(t, dir, "project.remove")
	if len(ev) != 2 || ev[1].result != "ok" || ev[1].evidence["mode"] != "purge" {
		t.Errorf("events = %+v", ev)
	}
}

func TestProjectRemoveFailureIsAuditedAsError(t *testing.T) {
	dir, proj := t.TempDir(), t.TempDir()
	if _, _, _, err := run(t, dir, "project", "add", proj, "--name", "shop"); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.DB().Exec(`CREATE TRIGGER fail_update BEFORE UPDATE ON project BEGIN SELECT RAISE(ABORT, 'disk on fire'); END;
		CREATE TRIGGER fail_delete BEFORE DELETE ON project BEGIN SELECT RAISE(ABORT, 'disk on fire'); END;`)
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"project", "remove", "shop"}, {"project", "remove", "shop", "--purge"}} {
		if _, _, _, err := run(t, dir, args...); err == nil || !strings.Contains(err.Error(), "disk on fire") {
			t.Fatalf("%v: err = %v", args, err)
		}
	}
	ev := auditRows(t, dir, "project.remove")
	if len(ev) != 2 || ev[0].result != "error" || ev[0].evidence["mode"] != "deactivate" ||
		ev[1].result != "error" || ev[1].evidence["mode"] != "purge" {
		t.Fatalf("events = %+v", ev)
	}
	if countProjects(t, dir) != 1 {
		t.Error("project lost after failed removals")
	}
}

func TestProjectAddStorageFailureIsErrorNotDenied(t *testing.T) {
	dir, proj := t.TempDir(), t.TempDir()
	if _, _, _, err := run(t, dir, "noop"); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.DB().Exec(`CREATE TRIGGER fail_insert BEFORE INSERT ON project BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`)
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = run(t, dir, "project", "add", proj, "--name", "shop", "--test-cmd", "TOKEN=abc")
	if err == nil || !strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("err = %v", err)
	}
	ev := auditRows(t, dir, "project.add")
	if len(ev) != 1 || ev[0].result != "error" {
		t.Fatalf("events = %+v", ev)
	}
	if r, _ := ev[0].evidence["reason"].(string); !strings.Contains(r, "disk on fire") || strings.Contains(r, "TOKEN") {
		t.Errorf("reason = %q", r)
	}
}

func TestProjectSetUpdatesAndAudits(t *testing.T) {
	dir, proj := t.TempDir(), t.TempDir()
	if _, _, _, err := run(t, dir, "project", "add", proj, "--name", "shop", "--core-package", "Symfony/Http-Kernel", "--core-package", "x"); err != nil {
		t.Fatal(err)
	}
	_, out, _, err := run(t, dir, "project", "set", "shop", "--core-package", "laravel/framework",
		"--risk", "major_jump=10", "--risk", "no_tests=5", "--fix-level", "2", "--test-cmd", "TOKEN=abc make test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Updated project shop") {
		t.Errorf("out = %q", out)
	}
	_, list, _, err := run(t, dir, "project", "list", "--json")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"core_packages":["laravel/framework"]`, `"major_jump":10`, `"fix_level":2`} {
		if !strings.Contains(list, want) {
			t.Errorf("list lacks %s: %s", want, list)
		}
	}
	ev := auditRows(t, dir, "project.set")
	if len(ev) != 1 || ev[0].result != "ok" || ev[0].target != "shop" {
		t.Fatalf("events = %+v", ev)
	}
	b, _ := json.Marshal(ev[0].evidence)
	if strings.Contains(string(b), "TOKEN") || ev[0].evidence["fields"] == nil {
		t.Errorf("evidence = %s", b)
	}
}

func TestProjectSetRejectsBadInput(t *testing.T) {
	dir, proj := t.TempDir(), t.TempDir()
	if _, _, _, err := run(t, dir, "project", "add", proj, "--name", "shop"); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"set", "shop", "--risk", "bogus=1"},
		{"set", "shop", "--risk", "major_jump"},
		{"set", "shop", "--risk", "major_jump=abc"},
		{"set", "shop", "--risk", "major_jump=500"},
		{"set", "ghost", "--fix-level", "1"},
		{"set", "shop"},
	} {
		_, _, _, err := run(t, dir, append([]string{"project"}, args...)...)
		if err == nil || !strings.HasPrefix(err.Error(), "Cannot update project") {
			t.Errorf("%v: err = %v", args, err)
		}
	}
	if n := len(auditRows(t, dir, "project.set")); n != 6 {
		t.Errorf("audit rows = %d", n)
	}
}

func TestProjectSetRefusesInconsistentThresholds(t *testing.T) {
	dir, proj := t.TempDir(), t.TempDir()
	if _, _, _, err := run(t, dir, "project", "add", proj, "--name", "shop"); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := run(t, dir, "project", "set", "shop", "--risk", "auto_fix_below=70")
	if err == nil || !strings.Contains(err.Error(), "auto_fix_below=70") || !strings.Contains(err.Error(), "handoff_up_to=60") {
		t.Fatalf("err = %v", err)
	}
	ev := auditRows(t, dir, "project.set")
	if len(ev) != 1 || ev[0].result != "denied" {
		t.Fatalf("events = %+v", ev)
	}
	if _, _, _, err := run(t, dir, "project", "set", "shop", "--risk", "auto_fix_below=70", "--risk", "handoff_up_to=90"); err != nil {
		t.Fatalf("consistent pair refused: %v", err)
	}
}

func TestProjectSetExclude(t *testing.T) {
	dir, proj := t.TempDir(), t.TempDir()
	if _, _, _, err := run(t, dir, "project", "add", proj, "--name", "demo", "--exclude", "tmp"); err != nil {
		t.Fatal(err)
	}
	if _, list, _, err := run(t, dir, "project", "list", "--json"); err != nil || !strings.Contains(list, `"exclude":["tmp"]`) {
		t.Fatalf("after add: %v %s", err, list)
	}
	_, out, _, err := run(t, dir, "project", "set", "demo", "--exclude", "dist", "--exclude", "build")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Analysis will be recomputed") {
		t.Errorf("out = %q", out)
	}
	if _, list, _, err := run(t, dir, "project", "list", "--json"); err != nil || !strings.Contains(list, `"exclude":["build","dist"]`) {
		t.Errorf("after set: %v %s", err, list)
	}
	ev := auditRows(t, dir, "project.set")
	if len(ev) != 1 || ev[0].result != "ok" {
		t.Fatalf("events = %+v", ev)
	}
	if b, _ := json.Marshal(ev[0].evidence); !strings.Contains(string(b), "exclude") {
		t.Errorf("evidence = %s", b)
	}
	if _, _, _, err := run(t, dir, "project", "set", "demo", "--exclude", ""); err != nil {
		t.Fatal(err)
	}
	if _, list, _, err := run(t, dir, "project", "list", "--json"); err != nil || !strings.Contains(list, `"exclude":[]`) {
		t.Errorf("after clearing: %v %s", err, list)
	}
	_, _, _, err = run(t, dir, "project", "set", "demo", "--exclude", "src/generated")
	if err == nil || !strings.HasPrefix(err.Error(), "Cannot update project") || !strings.Contains(err.Error(), "folder name") {
		t.Errorf("path refused? err = %v", err)
	}
	if rows := auditRows(t, dir, "project.set"); len(rows) != 3 || rows[2].result != "denied" {
		t.Errorf("events = %+v", rows)
	}
}

func TestProjectSetAutoFixMinor(t *testing.T) {
	dir, proj := t.TempDir(), t.TempDir()
	if _, _, _, err := run(t, dir, "project", "add", proj, "--name", "shop", "--auto-fix-minor"); err != nil {
		t.Fatal(err)
	}
	_, list, _, err := run(t, dir, "project", "list", "--json")
	if err != nil || !strings.Contains(list, `"auto_fix_minor":true`) {
		t.Fatalf("list = %s, %v", list, err)
	}
	if _, _, _, err := run(t, dir, "project", "set", "shop", "--auto-fix-minor=false"); err != nil {
		t.Fatal(err)
	}
	_, list, _, _ = run(t, dir, "project", "list", "--json")
	if !strings.Contains(list, `"auto_fix_minor":false`) {
		t.Errorf("list = %s", list)
	}
	if _, _, _, err := run(t, dir, "project", "set", "shop", "--fix-level", "4"); err == nil || !strings.HasPrefix(err.Error(), "Cannot update project") {
		t.Errorf("level 4: err = %v", err)
	}
}
