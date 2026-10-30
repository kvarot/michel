package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/sourceupdate"
	"github.com/kvarot/michel/internal/store"
)

// auditActions lists every audit action in write order.
func auditActions(t *testing.T, dir string) []string {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.DB().Query(`SELECT action FROM audit_event ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func indexOf(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}

func TestScanAllUpdateRunsSourceUpdateFirst(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	// No allow rule: the enabled OSV sources wait for consent, so the
	// update reads nothing and never touches the test databases.
	_, out, _, err := run(t, dir, "--lang", "en", "scan", "--all", "--update", "--no-analyze", "--osv-db", db)
	if err != nil {
		t.Fatalf("scan --all --update: %v\n%s", err, out)
	}
	acts := auditActions(t, dir)
	read, start := indexOf(acts, "source.read"), indexOf(acts, "scan.start")
	if read < 0 || start < 0 || read > start {
		t.Fatalf("audit order: %v", acts)
	}
	if !strings.Contains(out, "osv.npm waits for your consent") {
		t.Errorf("update lines missing:\n%s", out)
	}
}

func TestScanUpdateFailureDoesNotStopTheScan(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	defer osvdb.SetBaseURLForTest(srv.URL)()
	dir, db := t.TempDir(), buildTestOSVDB(t)
	writeCfg(t, dir, osvdb.Host, "127.0.0.1")
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	_, out, _, err := run(t, dir, "--lang", "en", "scan", "--all", "--update", "--no-analyze", "--osv-db", db)
	if err == nil || ExitCode(err) != 1 {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(out, "✗ osv.npm") || indexOf(auditActions(t, dir), "scan.start") < 0 {
		t.Errorf("the scan did not run after the failed update:\n%s", out)
	}
}

func TestSourceUpdateExitOneOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	defer osvdb.SetBaseURLForTest(srv.URL)()
	dir := t.TempDir()
	writeCfg(t, dir, osvdb.Host, "127.0.0.1")
	_, out, _, err := run(t, dir, "--lang", "en", "source", "update", "--osv-db", t.TempDir())
	if err == nil || ExitCode(err) != 1 {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{"✗ osv.packagist: ", "✗ osv.npm: ", "404"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if rows := auditRows(t, dir, "source.read"); len(rows) != 2 || rows[0].result != "error" {
		t.Errorf("source.read = %+v", rows)
	}
	_, out, _, err = run(t, dir, "source", "update", "osv.npm", "--json", "--osv-db", t.TempDir())
	var rep struct {
		Failed []string          `json:"failed"`
		Errors map[string]string `json:"errors"`
	}
	if ExitCode(err) != 1 || json.Unmarshal([]byte(out), &rep) != nil || len(rep.Failed) != 1 || rep.Failed[0] != "osv.npm" || rep.Errors["osv.npm"] == "" {
		t.Errorf("--json: %v %q", err, out)
	}
	if _, _, _, err = run(t, dir, "--lang", "en", "source", "update", "feed.nope"); err == nil || !strings.Contains(err.Error(), "feed.nope") {
		t.Errorf("unknown key: %v", err)
	}
}

func TestSourceUpdateOK(t *testing.T) {
	z := zipBytes(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(z) }))
	defer srv.Close()
	defer osvdb.SetBaseURLForTest(srv.URL)()
	dir := t.TempDir()
	writeCfg(t, dir, osvdb.Host, "127.0.0.1")
	_, out, _, err := run(t, dir, "--lang", "fr", "source", "update", "--kind", "osv", "--osv-db", t.TempDir())
	if err != nil || !strings.Contains(out, "✓ osv.npm") || strings.Contains(out, "enrich.") {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestPrintSourceUpdatePartial(t *testing.T) {
	for lang, want := range map[i18n.Lang]string{
		i18n.EN: "· enrich.nvd: 44 items read, the time of this update ran out before the rest; the next update goes on",
		i18n.FR: "· enrich.nvd : 44 éléments lus, le temps de cette mise à jour s'est écoulé avant la suite ; la prochaine mise à jour continuera",
	} {
		var out bytes.Buffer
		deps := &Deps{Stdout: &out, Stderr: &bytes.Buffer{}, Now: time.Now, Lang: lang}
		printSourceUpdate(deps, sourceupdate.Report{Order: []string{"enrich.nvd"}, Skipped: []string{"enrich.nvd"},
			SkipReasons: map[string]string{"enrich.nvd": sourceupdate.SkipPartial}, Items: map[string]int{"enrich.nvd": 44}})
		if got := strings.TrimSpace(out.String()); got != want {
			t.Errorf("%s: got %q", lang, got)
		}
	}
}
