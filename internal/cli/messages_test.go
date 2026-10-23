package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scannedTwice registers demo, scans it once (3 new findings) and returns
// the data folder and the database, so the next scan finds nothing new.
func scannedTwice(t *testing.T) (string, string) {
	t.Helper()
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "scan", "--project", "demo", "--osv-db", db, "--no-analyze"); err != nil {
		t.Fatal(err)
	}
	return dir, db
}

func wantAll(t *testing.T, what, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("%s lacks %q:\n%s", what, w, got)
		}
	}
}

func TestScanSummaryInFrench(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	_, out, _, err := run(t, dir, "--lang", "fr", "scan", "--project", "demo", "--osv-db", db)
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, "first scan", out, "Michel a trouvé 3 nouvelles failles dans demo, dont 1 critique, 3 failles analysées.",
		"Ensuite : michel findings --project demo --severity critical")

	_, out, _, err = run(t, dir, "--lang", "fr", "scan", "--project", "demo", "--osv-db", db)
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, "second scan", out, "Michel n'a trouvé aucune nouvelle faille dans demo", "Ensuite : michel findings --project demo")
	if strings.Contains(out, "Michel found") || strings.Contains(out, "Next:") {
		t.Errorf("English left in the French summary:\n%s", out)
	}
}

func TestFindingsEmptyInFrench(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	_, out, _, err := run(t, dir, "--lang", "fr", "findings", "--project", "demo")
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, "findings", out, "Aucune faille à montrer pour demo", "michel scan --project demo")
}

func TestProjectAddDeniedInFrench(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(t.TempDir(), "nope")
	_, _, _, err := run(t, dir, "--lang", "fr", "project", "add", missing, "--name", "shop")
	if err == nil {
		t.Fatal("expected an error")
	}
	wantAll(t, "error", err.Error(), "n'est pas un dossier", "composer.lock")
	// The audit log keeps the English reason: stored text is never translated.
	ev := auditRows(t, dir, "project.add")
	if r, _ := ev[0].evidence["reason"].(string); len(ev) != 1 || !strings.Contains(r, "is not a directory") {
		t.Errorf("stored reason = %v", ev[0].evidence)
	}
}

func TestUsageErrorsInFrench(t *testing.T) {
	_, _, _, err := run(t, t.TempDir(), "--lang", "fr", "scan")
	if err == nil {
		t.Fatal("expected an error")
	}
	wantAll(t, "scan error", err.Error(), "Michel a besoin de savoir quoi scanner", "--project", "--all")

	_, _, _, err = run(t, t.TempDir(), "--lang", "fr", "findings")
	if err == nil || strings.Contains(err.Error(), "Michel needs") {
		t.Errorf("findings error = %v", err)
	}
	// The language flag is read before the policy: a broken policy is
	// reported in French too.
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("sovereignty:\n  ai:\n    external_providers_enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = run(t, dir, "--lang", "fr", "noop")
	if err == nil || ExitCode(err) != ExitCodePolicy || !strings.Contains(err.Error(), "Michel refuse de démarrer") {
		t.Errorf("policy error = %v", err)
	}
}

func TestEnglishOutputUnchanged(t *testing.T) {
	dir, db := scannedTwice(t)
	_, out, _, err := run(t, dir, "scan", "--project", "demo", "--osv-db", db, "--no-analyze")
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, "scan", out, "Michel found no new findings in demo, analysis skipped. Next: michel findings --project demo\n")

	empty := t.TempDir()
	if _, _, _, err := run(t, empty, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	_, out, _, err = run(t, empty, "findings", "--project", "demo")
	if err != nil || out != "No findings to show for demo. Run 'michel scan --project demo' to refresh them.\n" {
		t.Errorf("findings: %v %q", err, out)
	}

	_, _, _, err = run(t, t.TempDir(), "project", "add", filepath.Join(t.TempDir(), "nope"), "--name", "shop")
	if err == nil || !strings.HasPrefix(err.Error(), "Cannot add project: ") || !strings.Contains(err.Error(), " is not a directory. Michel scans a project folder on this machine.") {
		t.Errorf("project add: %v", err)
	}

	_, _, _, err = run(t, t.TempDir(), "scan")
	want := "Michel needs to know what to scan. Pass --project <name> for one project, or --all for every active project. 'michel project list' shows the names."
	if err == nil || err.Error() != want {
		t.Errorf("scan usage: %v", err)
	}
}
