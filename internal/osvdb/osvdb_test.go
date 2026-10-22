package osvdb

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
)

func makeZip(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, _ := w.Create("GHSA-test.json")
	f.Write([]byte(`{"id":"GHSA-test"}`))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func gateway(t *testing.T, srvURL string, allow bool) *egress.Gateway {
	t.Helper()
	p := policy.Defaults()
	if allow {
		u, _ := url.Parse(srvURL)
		p.Sovereignty.Network.Allow = []policy.AllowRule{{Host: u.Hostname(), Purpose: "osv.db"}}
	}
	return egress.New(p, nil)
}

func setBase(t *testing.T, u string) {
	old := baseURL
	baseURL = u
	t.Cleanup(func() { baseURL = old })
}

var fixed = func() time.Time { return time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC) }

func TestUpdateWritesZipViaGateway(t *testing.T) {
	body := makeZip(t)
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Write(body)
	}))
	defer srv.Close()
	setBase(t, srv.URL)
	root := t.TempDir()
	st, err := Update(context.Background(), root, gateway(t, srv.URL, true).Client("osv.db"), Ecosystems, fixed)
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 2 || !st[0].Present || st[0].SizeBytes != int64(len(body)) {
		t.Fatalf("statuses = %+v", st)
	}
	if paths[0] != "/Packagist/all.zip" || paths[1] != "/npm/all.zip" {
		t.Errorf("paths = %v", paths)
	}
	for _, eco := range Ecosystems {
		if _, err := os.Stat(ZipPath(root, eco)); err != nil {
			t.Error(err)
		}
		if _, err := os.Stat(ZipPath(root, eco) + ".tmp"); err == nil {
			t.Error("temp file left behind")
		}
		b, _ := os.ReadFile(filepath.Join(root, "osv-scalibr", eco, "fetched_at"))
		if string(bytes.TrimSpace(b)) != "2026-10-22T08:00:00Z" {
			t.Errorf("fetched_at = %q", b)
		}
	}
	// A second update replaces the existing file.
	if _, err := Update(context.Background(), root, gateway(t, srv.URL, true).Client("osv.db"), []string{"npm"}, fixed); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateDeniedWhenNotAllowlisted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached the network")
	}))
	defer srv.Close()
	setBase(t, srv.URL)
	root := t.TempDir()
	_, err := Update(context.Background(), root, gateway(t, srv.URL, false).Client("osv.db"), Ecosystems, fixed)
	if !errors.Is(err, egress.ErrEgressDenied) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(ZipPath(root, "npm")); err == nil {
		t.Error("file written")
	}
	if _, err := os.Stat(ZipPath(root, "Packagist") + ".tmp"); err == nil {
		t.Error("temp file written")
	}
}

func TestUpdateRejectsNonZipKeepsOldFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>not a zip</html>"))
	}))
	defer srv.Close()
	setBase(t, srv.URL)
	root := t.TempDir()
	zp := ZipPath(root, "npm")
	os.MkdirAll(filepath.Dir(zp), 0o750)
	os.WriteFile(zp, []byte("old"), 0o640)
	_, err := Update(context.Background(), root, gateway(t, srv.URL, true).Client("osv.db"), []string{"npm"}, fixed)
	if err == nil {
		t.Fatal("expected error")
	}
	if b, _ := os.ReadFile(zp); string(b) != "old" {
		t.Errorf("old file replaced: %q", b)
	}
	if _, err := os.Stat(zp + ".tmp"); err == nil {
		t.Error("temp left")
	}
}

func TestUpdateRejectsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	setBase(t, srv.URL)
	root := t.TempDir()
	if _, err := Update(context.Background(), root, gateway(t, srv.URL, true).Client("osv.db"), []string{"npm"}, fixed); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(ZipPath(root, "npm")); err == nil {
		t.Error("file written")
	}
}

func TestRequireNamesMissingEcosystem(t *testing.T) {
	root := t.TempDir()
	zp := ZipPath(root, "Packagist")
	os.MkdirAll(filepath.Dir(zp), 0o750)
	os.WriteFile(zp, makeZip(t), 0o640)
	err := Require(root, Ecosystems)
	if !errors.Is(err, ErrDatabaseMissing) {
		t.Fatalf("err = %v", err)
	}
	if err.Error() != `offline database missing for npm: run "michel db update"` {
		t.Errorf("msg = %q", err)
	}
	if err := Require(root, []string{"Packagist"}); err != nil {
		t.Error(err)
	}
	// An empty file does not count.
	os.MkdirAll(filepath.Dir(ZipPath(root, "npm")), 0o750)
	os.WriteFile(ZipPath(root, "npm"), nil, 0o640)
	if Require(root, Ecosystems) == nil {
		t.Error("empty file accepted")
	}
}

func TestStatusesReportsFetchedAt(t *testing.T) {
	root := t.TempDir()
	zp := ZipPath(root, "npm")
	os.MkdirAll(filepath.Dir(zp), 0o750)
	os.WriteFile(zp, []byte("12345"), 0o640)
	os.WriteFile(filepath.Join(filepath.Dir(zp), "fetched_at"), []byte("2026-10-01T10:00:00Z\n"), 0o640)
	st, err := Statuses(root)
	if err != nil {
		t.Fatal(err)
	}
	if st[0].Ecosystem != "Packagist" || st[0].Present || !st[0].FetchedAt.IsZero() {
		t.Errorf("Packagist = %+v", st[0])
	}
	n := st[1]
	if !n.Present || n.SizeBytes != 5 || !n.FetchedAt.Equal(time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("npm = %+v", n)
	}
}

func TestUpdateRejectsOversizedDownload(t *testing.T) {
	body := makeZip(t)
	for _, announce := range []bool{true, false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !announce {
				w.Header().Set("Transfer-Encoding", "chunked")
				w.(http.Flusher).Flush()
			}
			w.Write(body)
		}))
		setBase(t, srv.URL)
		restore := SetLimitsForTest(int64(len(body)-1), 10, 1<<20)
		root := t.TempDir()
		_, err := Update(context.Background(), root, gateway(t, srv.URL, true).Client("osv.db"), []string{"npm"}, fixed)
		restore()
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("announce=%v err = %v", announce, err)
		}
		if _, err := os.Stat(ZipPath(root, "npm")); err == nil {
			t.Error("file installed")
		}
		if _, err := os.Stat(ZipPath(root, "npm") + ".tmp"); err == nil {
			t.Error("temp left")
		}
	}
}

func TestUpdateRejectsZipBomb(t *testing.T) {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, _ := w.Create("a.json")
	f.Write(bytes.Repeat([]byte("a"), 5000))
	w.Create("b.json")
	w.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { rw.Write(b.Bytes()) }))
	defer srv.Close()
	setBase(t, srv.URL)
	root := t.TempDir()
	zp := ZipPath(root, "npm")
	os.MkdirAll(filepath.Dir(zp), 0o750)
	os.WriteFile(zp, []byte("old"), 0o640)
	for _, lim := range []struct {
		entries int
		size    uint64
	}{{10, 1000}, {1, 1 << 20}} {
		restore := SetLimitsForTest(1<<20, lim.entries, lim.size)
		_, err := Update(context.Background(), root, gateway(t, srv.URL, true).Client("osv.db"), []string{"npm"}, fixed)
		restore()
		if err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("limits %+v err = %v", lim, err)
		}
		if got, _ := os.ReadFile(zp); string(got) != "old" {
			t.Errorf("old database lost: %q", got)
		}
		if _, err := os.Stat(zp + ".tmp"); err == nil {
			t.Error("temp left")
		}
	}
}

func TestInstallKeepsOldFileWhenReplaceFails(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "all.zip")
	tmp := dst + ".tmp"
	os.WriteFile(dst, []byte("old"), 0o640)
	// Missing source: every rename fails.
	if err := install(tmp, dst); err == nil {
		t.Fatal("expected error")
	}
	if got, _ := os.ReadFile(dst); string(got) != "old" {
		t.Errorf("old database lost: %q", got)
	}
	os.WriteFile(tmp, []byte("new"), 0o640)
	if err := install(tmp, dst); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "new" {
		t.Errorf("got %q", got)
	}
	if _, err := os.Stat(dst + ".old"); err == nil {
		t.Error(".old left")
	}
}
