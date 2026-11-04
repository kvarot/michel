package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/store"
)

// The purge gives back the rule Michel wrote for the project's Git service, and
// stops, saying why, if it cannot.
func TestProjectPurgeReleasesTheGitRule(t *testing.T) {
	setup := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		for _, name := range []string{"shop", "other"} {
			if _, _, _, err := run(t, dir, "project", "add", t.TempDir(), "--name", name); err != nil {
				t.Fatal(err)
			}
		}
		rule := policy.AllowRule{Host: "example.test", Purpose: policy.PurposeProjectGit}
		if _, err := policy.AddAllowRules(filepath.Join(dir, "config.yaml"), rule); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	sql := func(t *testing.T, dir, stmt string) {
		t.Helper()
		s, err := store.Open(filepath.Join(dir, "michel.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if _, err := s.DB().Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	row := func(name string, written int) string {
		return `INSERT INTO project_remote (project_id, answer, remote_name, url, host, provider, rule_written, answered_at)
			SELECT id, 'yes', 'origin', 'https://example.test/a/b.git', 'example.test', 'other', ` + strconv.Itoa(written) +
			`, '2026-11-04T00:00:00Z' FROM project WHERE name = '` + name + `'`
	}
	t.Run("removed with the project", func(t *testing.T) {
		dir := setup(t)
		sql(t, dir, row("shop", 1))
		if _, _, _, err := run(t, dir, "project", "remove", "shop", "--purge"); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "example.test") {
			t.Errorf("the rule stayed:\n%s", b)
		}
	})
	t.Run("a failure stops the purge", func(t *testing.T) {
		dir := setup(t)
		sql(t, dir, row("shop", 1))
		sql(t, dir, row("other", 0))
		sql(t, dir, `CREATE TRIGGER boom BEFORE UPDATE ON project_remote BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`)
		_, _, _, err := run(t, dir, "project", "remove", "shop", "--purge")
		if err == nil || !strings.Contains(err.Error(), "network rule") || !strings.Contains(err.Error(), "shop") {
			t.Fatalf("err = %v", err)
		}
		if countProjects(t, dir) != 2 {
			t.Error("the project was purged all the same")
		}
		ev := auditRows(t, dir, "project.remove")
		if len(ev) != 1 || ev[0].result != "error" || ev[0].evidence["mode"] != "purge" {
			t.Errorf("events = %+v", ev)
		}
	})
}
