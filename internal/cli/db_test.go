package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/osvdb"
)

func zipBytes(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, _ := w.Create("x.json")
	f.Write([]byte("{}"))
	w.Close()
	return b.Bytes()
}

func writeCfg(t *testing.T, dir string, hosts ...string) {
	t.Helper()
	cfg := "sovereignty:\n  network:\n    default_egress: deny\n    allow:\n"
	for _, h := range hosts {
		cfg += "      - {host: " + h + ", purpose: osv.db}\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDBUpdateNeedsAllowRule(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(t.TempDir(), "osv")
	_, _, _, err := run(t, dir, "db", "update", "--osv-db", root)
	if err == nil || ExitCode(err) != ExitCodePolicy {
		t.Fatalf("err = %v code %d", err, ExitCode(err))
	}
	for _, want := range []string{
		"db update requires network.allow entry {host: osv-vulnerabilities.storage.googleapis.com, purpose: osv.db}",
		"never downloads anything that is not listed in your policy", "config.yaml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	ev := auditRows(t, dir, "osv.db.update")
	if len(ev) != 1 || ev[0].result != "denied" || ev[0].target != root {
		t.Fatalf("events = %+v", ev)
	}
	if _, err := os.Stat(root); err == nil {
		t.Error("directory created")
	}
}

func TestDBUpdateOKAndStatus(t *testing.T) {
	z := zipBytes(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(z) }))
	defer srv.Close()
	defer osvdb.SetBaseURLForTest(srv.URL)()
	dir := t.TempDir()
	// The real host passes the pre-check; the test server host is what the
	// gateway sees on the wire.
	writeCfg(t, dir, osvdb.Host, "127.0.0.1")
	root := filepath.Join(t.TempDir(), "osv")
	_, out, _, err := run(t, dir, "db", "update", "--osv-db", root)
	if err != nil {
		t.Fatal(err)
	}
	for _, eco := range osvdb.Ecosystems {
		if !strings.Contains(out, "Updated "+eco+": ") || !strings.Contains(out, " bytes") {
			t.Errorf("out = %q", out)
		}
	}
	ev := auditRows(t, dir, "osv.db.update")
	if len(ev) != 1 || ev[0].result != "ok" || ev[0].evidence["sizes"] == nil {
		t.Fatalf("events = %+v", ev)
	}
	_, out, _, err = run(t, dir, "db", "status", "--osv-db", root, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var st []osvdb.Status
	if err := json.Unmarshal([]byte(out), &st); err != nil || len(st) != 2 || !st[0].Present {
		t.Fatalf("status = %q %v", out, err)
	}
}

func TestDBUpdateServerErrorIsAuditedAsError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	defer osvdb.SetBaseURLForTest(srv.URL)()
	dir := t.TempDir()
	writeCfg(t, dir, osvdb.Host, "127.0.0.1")
	_, _, _, err := run(t, dir, "db", "update", "--osv-db", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "run 'michel db update' again") {
		t.Fatalf("err = %v", err)
	}
	ev := auditRows(t, dir, "osv.db.update")
	if len(ev) != 1 || ev[0].result != "error" {
		t.Fatalf("events = %+v", ev)
	}
}

func TestDBStatusStates(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()
	put := func(eco, at string) {
		p := osvdb.ZipPath(root, eco)
		os.MkdirAll(filepath.Dir(p), 0o750)
		os.WriteFile(p, []byte("data"), 0o640)
		os.WriteFile(filepath.Join(filepath.Dir(p), "fetched_at"), []byte(at), 0o640)
	}
	put("npm", time.Now().UTC().Add(-10*24*time.Hour).Format(time.RFC3339))
	_, out, _, err := run(t, dir, "db", "status", "--osv-db", root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Packagist") || !strings.Contains(out, "MISSING") || !strings.Contains(out, "STALE") {
		t.Errorf("out = %q", out)
	}
	put("npm", time.Now().UTC().Format(time.RFC3339))
	_, out, _, _ = run(t, dir, "db", "status", "--osv-db", root)
	if strings.Contains(out, "STALE") || !strings.Contains(out, "OK") {
		t.Errorf("out = %q", out)
	}
}
