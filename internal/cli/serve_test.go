package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/serverlog"
)

func TestServeRefusesNonLoopback(t *testing.T) {
	dir := t.TempDir()
	refused := i18n.T(i18n.EN, "cli.serve.loopback_only")
	refused = refused[:strings.Index(refused, "%")]
	for _, addr := range []string{"0.0.0.0:7331", "192.168.1.10:7331", "example.com:7331", ":7331", "[::]:7331", "10.0.0.1:0"} {
		_, out, _, err := run(t, dir, "--lang", "en", "serve", "--listen", addr)
		if err == nil || !strings.HasPrefix(err.Error(), refused) {
			t.Errorf("%s: err = %v", addr, err)
		}
		if strings.Contains(out, "token=") {
			t.Errorf("%s: printed %q", addr, out)
		}
	}
	for _, addr := range []string{"nonsense", "127.0.0.1", "127.0.0.1:99999", "127.0.0.1:http"} {
		_, _, _, err := run(t, dir, "--lang", "en", "serve", "--listen", addr)
		if err == nil || strings.HasPrefix(err.Error(), refused) {
			t.Errorf("%s: err = %v", addr, err)
		}
	}
	_, _, _, err := run(t, dir, "--lang", "fr", "serve", "--listen", "0.0.0.0:7331")
	frRefused := i18n.T(i18n.FR, "cli.serve.loopback_only")
	if err == nil || !strings.HasPrefix(err.Error(), frRefused[:strings.Index(frRefused, "%")]) {
		t.Errorf("fr: %v", err)
	}
	if rows := auditRows(t, dir, "api.start"); len(rows) != 0 {
		t.Errorf("api.start = %+v", rows)
	}
}

// runServe runs 'michel serve' on a free loopback port, calls use with the
// printed URL while it serves, then stops it as Ctrl+C would.
func runServe(t *testing.T, dir string, use func(base *url.URL, token string)) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	deps := &Deps{Stdout: &out, Stderr: &errOut, Now: time.Now}
	t.Cleanup(func() { deps.Close() })
	ready := make(chan string, 1)
	serveReady = func(u string) { ready <- u }
	t.Cleanup(func() { serveReady = nil })
	cmd := NewRootCmd(deps)
	cmd.SetArgs([]string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", dir, "--lang", "en", "serve", "--listen", "127.0.0.1:0"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()
	select {
	case u := <-ready:
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		token := parsed.Query().Get("token")
		parsed.RawQuery = ""
		use(parsed, token)
	case err := <-done:
		t.Fatalf("serve stopped early: %v\n%s", err, errOut.String())
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not start")
	}
	cancel()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not stop")
	}
	return "", nil
}

func TestServeNeverWritesUnderProject(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	path := copyProject(t, "project-a")
	if _, _, _, err := run(t, dir, "project", "add", path, "--name", "demo", "--test-cmd", "phpunit-secret-marker"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "scan", "--project", "demo", "--osv-db", db); err != nil {
		t.Fatal(err)
	}
	before := cliTreeDigest(t, path)
	id := findingByOSV(t, dir, "ACME-2026-0001")
	var printedToken string
	out, err := runServe(t, dir, func(base *url.URL, token string) {
		printedToken = token
		if base.Hostname() != "127.0.0.1" || len(token) != 64 {
			t.Errorf("url %s token %q", base, token)
		}
		call := func(method, p, body string) (int, string) {
			t.Helper()
			var rd io.Reader
			if body != "" {
				rd = strings.NewReader(body)
			}
			req, _ := http.NewRequest(method, base.String()+strings.TrimPrefix(p, "/"), rd)
			req.Header.Set("Authorization", "Bearer "+token)
			if body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(b)
		}
		for _, c := range []struct{ method, path, body string }{
			{"GET", "/api/v1/meta", ""}, {"GET", "/api/v1/today", ""}, {"GET", "/api/v1/projects", ""},
			{"GET", "/api/v1/projects/demo/findings?status=all", ""}, {"GET", "/api/v1/findings/" + id, ""},
			{"POST", "/api/v1/findings/" + id + "/decision", `{"action":"ignore","why":"only used by a dev tool"}`},
			{"GET", "/api/v1/digests", ""}, {"GET", "/", ""},
		} {
			code, body := call(c.method, c.path, c.body)
			if code != http.StatusOK {
				t.Errorf("%s %s = %d %s", c.method, c.path, code, body)
			}
			for _, banned := range []string{path, filepath.ToSlash(path), strings.ReplaceAll(path, `\`, `\\`), "phpunit-secret-marker"} {
				if strings.Contains(body, banned) {
					t.Errorf("%s %s contains %q", c.method, c.path, banned)
				}
			}
		}
	})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	if strings.Count(out, "token="+printedToken) != 1 {
		t.Errorf("the URL is not printed once:\n%s", out)
	}
	if after := cliTreeDigest(t, path); after != before {
		t.Error("serve wrote under the project folder")
	}
	start, stop := auditRows(t, dir, "api.start"), auditRows(t, dir, "api.stop")
	if len(start) != 1 || len(stop) != 1 || !strings.HasPrefix(start[0].evidence["listen"].(string), "127.0.0.1:") {
		t.Errorf("api.start = %+v, api.stop = %+v", start, stop)
	}
	for _, r := range append(start, stop...) {
		for _, v := range r.evidence {
			if s, ok := v.(string); ok && strings.Contains(s, printedToken) {
				t.Errorf("audit holds the token: %+v", r)
			}
		}
	}
	set := auditRows(t, dir, "decision.set")
	if len(set) != 1 || set[0].evidence["author"] != "web" {
		t.Errorf("decision.set = %+v", set)
	}
	if s := findingStatusIn(t, dir, id); s != "decided" {
		t.Errorf("status = %s", s)
	}

	// A second serve keeps the same token.
	out2, err := runServe(t, dir, func(base *url.URL, token string) {
		if token != printedToken {
			t.Errorf("token changed: %q -> %q", printedToken, token)
		}
	})
	if err != nil || !strings.Contains(out2, printedToken) {
		t.Errorf("second serve: %v %q", err, out2)
	}
}

func TestServeStartsAndStopsLogScheduler(t *testing.T) {
	var started, stopped atomic.Int32
	var gotDeps atomic.Pointer[serverlog.Deps]
	ctxEnded := make(chan struct{})
	old := runLogScheduler
	runLogScheduler = func(ctx context.Context, d serverlog.Deps, every time.Duration) {
		started.Add(1)
		gotDeps.Store(&d)
		if every <= 0 || every > time.Minute {
			t.Errorf("the scheduler looks for due servers every %v: more than the shortest interval, 1 minute", every)
		}
		<-ctx.Done()
		close(ctxEnded)
		stopped.Add(1)
	}
	t.Cleanup(func() { runLogScheduler = old })

	dir := t.TempDir()
	_, err := runServe(t, dir, func(*url.URL, string) {
		// While serve runs the scheduler is running, and has what it needs.
		deadline := time.Now().Add(10 * time.Second)
		for started.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if started.Load() != 1 || stopped.Load() != 0 {
			t.Errorf("while serving: started %d, stopped %d", started.Load(), stopped.Load())
		}
		if d := gotDeps.Load(); d == nil || d.Repo == nil || d.Targets == nil || d.Audit == nil || d.Now == nil || d.Alert == nil {
			t.Errorf("deps = %+v", d)
		}
	})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	// serve returned: the scheduler has been told to stop, and waited for.
	select {
	case <-ctxEnded:
	default:
		t.Error("the scheduler's context did not end")
	}
	if started.Load() != 1 || stopped.Load() != 1 {
		t.Errorf("after serve: started %d, stopped %d", started.Load(), stopped.Load())
	}
}

// The real michel serve, its real scan and real folders: no fake here, the
// API tests hold one.
func TestServeGivesScanProject(t *testing.T) {
	dir := t.TempDir()
	path, empty := copyProject(t, "project-a"), t.TempDir()
	before := treeContent(t, path)
	_, err := runServe(t, dir, func(base *url.URL, token string) {
		call := func(method, p, body string) (int, string) {
			t.Helper()
			var rd io.Reader
			if body != "" {
				rd = strings.NewReader(body)
			}
			req, _ := http.NewRequest(method, base.String()+strings.TrimPrefix(p, "/"), rd)
			req.Header.Set("Authorization", "Bearer "+token)
			if body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(b)
		}
		add := func(folder, name string) {
			t.Helper()
			body, _ := json.Marshal(map[string]string{"path": folder, "name": name})
			if code, b := call("POST", "/api/v1/projects", string(body)); code != http.StatusCreated {
				t.Fatalf("add %s = %d %s", name, code, b)
			}
		}
		type view struct {
			Name        string         `json:"name"`
			Total       int            `json:"total"`
			Scanning    bool           `json:"scanning"`
			Status      string         `json:"last_scan_status"`
			LastFailure map[string]any `json:"last_failure"`
		}
		// check starts a scan and returns the project once it ended.
		check := func(name string) view {
			t.Helper()
			if code, b := call("POST", "/api/v1/projects/"+name+"/scan", ""); code != http.StatusAccepted {
				t.Fatalf("scan %s = %d %s", name, code, b)
			}
			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				_, b := call("GET", "/api/v1/projects", "")
				var list []view
				if err := json.Unmarshal([]byte(b), &list); err != nil {
					t.Fatalf("%v: %s", err, b)
				}
				for _, v := range list {
					if v.Name == name && !v.Scanning {
						return v
					}
				}
				time.Sleep(20 * time.Millisecond)
			}
			t.Fatalf("the scan of %s did not end", name)
			return view{}
		}
		add(path, "demo")
		add(empty, "nothing")
		if v := check("demo"); v.LastFailure["code"] != "api.project.no_database" {
			t.Errorf("no database: %+v", v)
		}
		if err := os.CopyFS(filepath.Join(dir, "osv"), os.DirFS(buildTestOSVDB(t))); err != nil {
			t.Fatal(err)
		}
		if v := check("nothing"); v.LastFailure["code"] != "api.project.nothing_to_scan" || v.Status != "empty" {
			t.Errorf("nothing to scan: %+v", v)
		}
		v := check("demo")
		if v.LastFailure != nil || v.Status != "ok" || v.Total != 3 {
			t.Errorf("scan: %+v", v)
		}
		// The analysis ran, as with michel scan.
		_, b := call("GET", "/api/v1/projects/demo/findings", "")
		var findings []map[string]any
		if err := json.Unmarshal([]byte(b), &findings); err != nil || len(findings) != 3 {
			t.Fatalf("findings = %v %s", err, b)
		}
		_, b = call("GET", "/api/v1/findings/"+findings[0]["id"].(string), "")
		var one map[string]any
		if err := json.Unmarshal([]byte(b), &one); err != nil || one["analysis"] == nil {
			t.Errorf("no analysis: %v %s", err, b)
		}
		// The page's list of projects holds it too.
		_, b = call("GET", "/api/v1/today", "")
		if !strings.Contains(b, `"name":"demo"`) {
			t.Errorf("today: %s", b)
		}
	})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	compareTrees(t, before, treeContent(t, path))
	if rows := auditRows(t, dir, "project.add"); len(rows) != 2 || rows[0].result != "ok" {
		t.Errorf("project.add = %+v", rows)
	}
	if rows := auditRows(t, dir, "scan.finish"); len(rows) != 2 {
		t.Errorf("scan.finish = %+v", rows)
	}
}
