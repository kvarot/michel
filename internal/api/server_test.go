package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

var now = time.Date(2026, 10, 23, 6, 30, 0, 0, time.UTC)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// Markers of the declared commands: they must never leave the server.
const (
	testCmdMarker    = "phpunit-secret-marker --filter acme"
	installCmdMarker = "composer-install-secret-marker"
)

type fixture struct {
	t      *testing.T
	st     *store.Store
	log    *audit.Logger
	proj   project.Project
	deps   Deps
	srv    *httptest.Server
	ids    map[string]string // osv id -> finding id
	gone   string
	nItems int
	// dir is the data folder; policyPath the policy file enable writes to;
	// gw the gateway the server checks the network rules with.
	dir        string
	policyPath string
	gw         *egress.Gateway
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// newFixture builds a store with the project demo (declared commands set),
// three findings (one analysed, one gone) and a server on loopback. web nil
// means no front was built.
func newFixture(t *testing.T, web fs.FS) *fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &fixture{t: t, st: st, ids: map[string]string{}, dir: dir, policyPath: filepath.Join(dir, "config.yaml")}
	f.log = audit.NewLogger(st, func() time.Time { return now })
	if _, _, err := source.Sync(context.Background(), source.NewRepo(st)); err != nil {
		t.Fatal(err)
	}
	f.gw = egress.New(policy.Defaults(), f.log.EgressSink())
	projDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projDir, "composer.lock"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.proj, err = project.NewRepo(st).Add(context.Background(), project.Project{Name: "demo", Path: projDir,
		TestCmd: testCmdMarker, InstallCmd: installCmdMarker, FixLevel: 2, FixLevelSet: true})
	if err != nil {
		t.Fatal(err)
	}
	f.ids["ACME-2026-0001"] = f.seed("acme/vuln", "ACME-2026-0001", "critical", "new", now.Add(-2*time.Hour))
	f.ids["ACME-2026-0002"] = f.seed("vuln-pkg", "ACME-2026-0002", "high", "new", now.Add(-3*time.Hour))
	f.gone = f.seed("acme/old", "ACME-2026-0003", "medium", "gone", now.Add(-48*time.Hour))
	f.scanRow("ok", now.Add(-time.Hour))
	if err := analyze.NewRepo(st).Save(context.Background(), analyze.Analysis{
		FindingID: f.ids["ACME-2026-0001"], ProjectID: f.proj.ID, ComputedAt: now, MichelVersion: "test",
		Path:    analyze.DepPath{Directness: analyze.Transitive, Via: []string{"acme/framework"}},
		Upgrade: analyze.Upgrade{Target: "1.2.5", Jump: "patch"},
		Calls:   analyze.CallSites{Sites: []analyze.CallSite{{File: "src/Billing/Invoice.php", Line: 42}}, Count: 1, Quality: "psr4"},
		Changelog: analyze.Changelog{Source: "CHANGELOG.md", Available: true, Breaking: true,
			BreakingLines: []string{"BREAKING: drop the legacy api"}, Excerpt: "## 1.2.5\n- BREAKING: drop the legacy api"},
		Risk: analyze.Risk{Score: 40, Recommendation: "manual", Terms: map[string]int{"breaking": 30}},
	}); err != nil {
		t.Fatal(err)
	}
	sec, err := secret.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.deps = Deps{Store: st, Audit: f.log, Policy: policy.Defaults(), Secrets: sec, Now: func() time.Time { return now },
		Version: "test-version", Lang: i18n.EN, Web: web, PolicyPath: f.policyPath,
		Reload: func() (policy.Policy, error) {
			p, _, err := policy.Load(f.policyPath, dir)
			if err == nil {
				err = policy.Validate(p)
			}
			return p, err
		},
		Sources: Sources{Gateway: f.gw, DataDir: dir}}
	f.srv = httptest.NewServer(New(f.deps, testToken))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) seed(pkg, osv, severity, status string, first time.Time) string {
	f.t.Helper()
	f.nItems++
	id := fmt.Sprintf("f%015d", f.nItems)
	eco := "Packagist"
	if !strings.Contains(pkg, "/") {
		eco = "npm"
	}
	if _, err := f.st.DB().Exec(`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, severity_label,
		installed_version, fixed_versions, status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, status_changed_at, summary)
		VALUES (?, ?, 'composer.lock', ?, ?, ?, ?, '1.0.0', '["1.2.5"]', ?, 's1', 's1', ?, ?, ?, 'Remote code execution')`,
		id, f.proj.ID, eco, pkg, osv, severity, status, ts(first), ts(first), ts(first)); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) scanRow(status string, started time.Time) {
	f.t.Helper()
	f.nItems++
	if _, err := f.st.DB().Exec(`INSERT INTO scan (id, project_id, started_at, status) VALUES (?,?,?,?)`,
		fmt.Sprintf("S%03d", f.nItems), f.proj.ID, ts(started), status); err != nil {
		f.t.Fatal(err)
	}
}

// do sends a request; token "" sends no Authorization header. hdr is
// name/value pairs; "Host" sets the request host.
func (f *fixture) do(method, path, token, body string, hdr ...string) (*http.Response, string) {
	f.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rd)
	if err != nil {
		f.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if strings.EqualFold(hdr[i], "Host") {
			req.Host = hdr[i+1]
			continue
		}
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// get is an authenticated GET that must answer 200; it decodes into v.
func (f *fixture) get(path string, v any) string {
	f.t.Helper()
	resp, body := f.do("GET", path, testToken, "")
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("GET %s = %d %s", path, resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
		f.t.Errorf("GET %s content type %q", path, ct)
	}
	if v != nil {
		if err := json.Unmarshal([]byte(body), v); err != nil {
			f.t.Fatalf("GET %s: %v\n%s", path, err, body)
		}
	}
	return body
}

// apiRoutes lists one URL of every GET route, then an unknown one.
func apiRoutes(f *fixture) []string {
	id := f.ids["ACME-2026-0001"]
	return []string{"/api/v1/meta", "/api/v1/today", "/api/v1/projects", "/api/v1/projects/demo/findings",
		"/api/v1/findings/" + id, "/api/v1/digests", "/api/v1/sources", "/api/v1/sources?all=1", "/api/v1/sources/osv.npm",
		"/api/v1/sources/items", "/api/v1/sources/discoveries", "/api/v1/tech", "/api/v1/plugin-runs/nope", "/api/v1/nowhere"}
}

func TestAPIRejectsMissingToken(t *testing.T) {
	f := newFixture(t, nil)
	for _, path := range apiRoutes(f) {
		for _, tok := range []string{"", "wrong", testToken[:63], testToken + "0"} {
			resp, body := f.do("GET", path, tok, "")
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("GET %s token %q = %d", path, tok, resp.StatusCode)
				continue
			}
			var eb map[string]any
			if err := json.Unmarshal([]byte(body), &eb); err != nil || eb["error"] == nil || eb["error"] == "" {
				t.Errorf("GET %s: body %q", path, body)
			}
			for k := range eb {
				if k != "error" && k != "hint" {
					t.Errorf("GET %s: 401 body has %q: %s", path, k, body)
				}
			}
			for _, leak := range []string{"acme", "demo", "ACME-", "Remote code"} {
				if strings.Contains(body, leak) {
					t.Errorf("GET %s: 401 body leaks %q: %s", path, leak, body)
				}
			}
		}
	}
	// A POST without token changes nothing.
	resp, _ := f.do("POST", "/api/v1/findings/"+f.ids["ACME-2026-0001"]+"/decision", "", `{"action":"fix"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST without token = %d", resp.StatusCode)
	}
	var n int
	_ = f.st.DB().QueryRow(`SELECT COUNT(*) FROM decision`).Scan(&n)
	if n != 0 {
		t.Errorf("decisions = %d", n)
	}
	// Another scheme, or an empty bearer, is refused.
	resp, _ = f.do("GET", "/api/v1/meta", "", "", "Authorization", "Basic "+testToken)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Basic = %d", resp.StatusCode)
	}
	resp, _ = f.do("GET", "/api/v1/meta", "", "", "Authorization", "Bearer")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("empty Bearer = %d", resp.StatusCode)
	}
}

func TestAPIAcceptsBearerAndQueryOnRootOnly(t *testing.T) {
	f := newFixture(t, nil)
	for _, path := range apiRoutes(f)[:6] {
		if resp, body := f.do("GET", path, testToken, ""); resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s with Bearer = %d %s", path, resp.StatusCode, body)
		}
		// ?token= is ignored on the API.
		if resp, _ := f.do("GET", path+"?token="+testToken, "", ""); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s with ?token= = %d, want 401", path, resp.StatusCode)
		}
	}
	if resp, _ := f.do("GET", "/api/v1/nowhere", testToken, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown API route = %d", resp.StatusCode)
	}
	// The page takes ?token= on its first load; a wrong one is refused.
	if resp, _ := f.do("GET", "/?token="+testToken, "", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("GET /?token=good = %d", resp.StatusCode)
	}
	if resp, body := f.do("GET", "/?token=wrong", "", ""); resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, `"error"`) {
		t.Errorf("GET /?token=wrong = %d %s", resp.StatusCode, body)
	}
	// The page itself holds no data: it opens without token.
	if resp, _ := f.do("GET", "/", "", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("GET / = %d", resp.StatusCode)
	}
}

func TestSecurityHeadersAndNoCORS(t *testing.T) {
	f := newFixture(t, nil)
	wantCSP := "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	check := func(name string, resp *http.Response, api bool) {
		t.Helper()
		h := resp.Header
		if h.Get("Content-Security-Policy") != wantCSP {
			t.Errorf("%s: CSP %q", name, h.Get("Content-Security-Policy"))
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: headers %v", name, h)
		}
		for k := range h {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Errorf("%s: CORS header %s", name, k)
			}
		}
		if api && h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", name, h.Get("Cache-Control"))
		}
	}
	resp, _ := f.do("GET", "/api/v1/meta", testToken, "", "Origin", f.srv.URL)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("same origin = %d", resp.StatusCode)
	}
	check("meta", resp, true)
	resp, _ = f.do("GET", "/api/v1/meta", "", "")
	check("401", resp, true)
	resp, _ = f.do("GET", "/", "", "")
	check("root", resp, false)
	resp, _ = f.do("OPTIONS", "/api/v1/meta", "", "", "Origin", "http://evil.example", "Access-Control-Request-Method", "GET")
	check("preflight", resp, true)
	if resp.StatusCode < 400 {
		t.Errorf("preflight = %d", resp.StatusCode)
	}

	// Cross-origin and DNS-rebinding requests are refused, even with the token.
	resp, body := f.do("GET", "/api/v1/meta", testToken, "", "Origin", "http://evil.example")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, `"error"`) {
		t.Errorf("foreign origin = %d %s", resp.StatusCode, body)
	}
	check("foreign origin", resp, true)
	port := f.srv.URL[strings.LastIndex(f.srv.URL, ":")+1:]
	for _, host := range []string{"evil.example:" + port, "evil.example", "127.0.0.2:" + port, "10.0.0.1:" + port} {
		resp, _ := f.do("GET", "/api/v1/meta", testToken, "", "Host", host)
		if resp.StatusCode != http.StatusMisdirectedRequest {
			t.Errorf("Host %s = %d", host, resp.StatusCode)
		}
	}
	for _, host := range []string{"localhost:" + port, "127.0.0.1:" + port} {
		if resp, _ := f.do("GET", "/api/v1/meta", testToken, "", "Host", host); resp.StatusCode != http.StatusOK {
			t.Errorf("Host %s = %d", host, resp.StatusCode)
		}
	}
	// With an explicit list, only those hosts pass.
	d := f.deps
	d.AllowedHosts = []string{"127.0.0.1:7331", "localhost:7331", "[::1]:7331"}
	h := New(d, testToken)
	for host, want := range map[string]int{"127.0.0.1:7331": 200, "localhost:7331": 200, "[::1]:7331": 200, "127.0.0.1:7332": 421, "evil.example:7331": 421} {
		req := httptest.NewRequest("GET", "/api/v1/meta", nil)
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+testToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("AllowedHosts, Host %s = %d, want %d", host, rec.Code, want)
		}
	}

	// POST bodies: JSON only, 64 KiB at most, one document, no unknown field.
	id := f.ids["ACME-2026-0002"]
	req, _ := http.NewRequest("POST", f.srv.URL+"/api/v1/findings/"+id+"/decision", strings.NewReader(`{"action":"fix"}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "text/plain")
	r2, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain = %d", r2.StatusCode)
	}
	big := `{"action":"ignore","why":"` + strings.Repeat("a", 70<<10) + `"}`
	if resp, _ := f.do("POST", "/api/v1/findings/"+id+"/decision", testToken, big); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("big body = %d", resp.StatusCode)
	}
	if resp, _ := f.do("POST", "/api/v1/findings/"+id+"/decision", testToken, `{"action":"fix","for":"7d"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown field = %d", resp.StatusCode)
	}
	if resp, _ := f.do("POST", "/api/v1/findings/"+id+"/decision", testToken, `{"action":"fix"}{"action":"ignore"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("two documents = %d", resp.StatusCode)
	}
	if resp, _ := f.do("POST", "/api/v1/findings/"+id+"/decision", testToken, `{"action":"fix"}`, "Origin", "http://evil.example"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin POST = %d", resp.StatusCode)
	}
	var n int
	_ = f.st.DB().QueryRow(`SELECT COUNT(*) FROM decision`).Scan(&n)
	if n != 0 {
		t.Errorf("decisions = %d", n)
	}
}

func TestServeWithoutDistServesPlaceholder(t *testing.T) {
	f := newFixture(t, nil)
	resp, body := f.do("GET", "/", "", "")
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("GET / = %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(body, html.EscapeString(i18n.T(i18n.EN, "api.no_ui"))) || !strings.Contains(body, `lang="en"`) {
		t.Errorf("placeholder:\n%s", body)
	}
	if _, body = f.do("GET", "/?lang=fr", "", ""); !strings.Contains(body, html.EscapeString(i18n.T(i18n.FR, "api.no_ui"))) || !strings.Contains(body, `lang="fr"`) {
		t.Errorf("placeholder fr:\n%s", body)
	}
	if _, body = f.do("GET", "/", "", "", "Accept-Language", "fr-FR,fr;q=0.9"); !strings.Contains(body, html.EscapeString(i18n.T(i18n.FR, "api.no_ui"))) {
		t.Errorf("placeholder Accept-Language fr:\n%s", body)
	}
	for _, p := range []string{"/assets/app.js", "/sw.js", "/manifest.webmanifest", "/sw-manifest.json", "/icons/192.png", "/nowhere"} {
		if resp, _ := f.do("GET", p, "", ""); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d", p, resp.StatusCode)
		}
	}
	// The API works without the front.
	f.get("/api/v1/meta", nil)

	// With a front: index.html on /, static files without token, no listing.
	g := newFixture(t, fstest.MapFS{
		"index.html":           {Data: []byte("<!doctype html><title>Michel</title><div id=app></div>")},
		"assets/app-1234.js":   {Data: []byte("console.log(1)")},
		"sw.js":                {Data: []byte("self.addEventListener('fetch',()=>{})")},
		"manifest.webmanifest": {Data: []byte(`{"name":"Michel"}`)},
		"sw-manifest.json":     {Data: []byte(`{"files":["/"]}`)},
		"icons/192.png":        {Data: []byte("png")},
	})
	resp, body = g.do("GET", "/?token="+testToken, "", "")
	if resp.StatusCode != 200 || !strings.Contains(body, "<div id=app>") || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("index = %d %s", resp.StatusCode, body)
	}
	for p, want := range map[string]string{"/assets/app-1234.js": "console.log", "/sw.js": "addEventListener",
		"/manifest.webmanifest": `"Michel"`, "/icons/192.png": "png", "/sw-manifest.json": `"files"`} {
		resp, body := g.do("GET", p, "", "")
		if resp.StatusCode != 200 || !strings.Contains(body, want) {
			t.Errorf("GET %s = %d %q", p, resp.StatusCode, body)
		}
	}
	if resp, _ := g.do("GET", "/manifest.webmanifest", "", ""); resp.Header.Get("Content-Type") != "application/manifest+json" {
		t.Errorf("manifest Content-Type = %q", resp.Header.Get("Content-Type"))
	}
	for _, p := range []string{"/assets/", "/icons/", "/index.html", "/assets/missing.js"} {
		if resp, _ := g.do("GET", p, "", ""); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d", p, resp.StatusCode)
		}
	}
}

// memSecrets is an in-memory secret store.
type memSecrets map[string][]byte

func (m memSecrets) Set(n string, v []byte) error { m[n] = append([]byte{}, v...); return nil }
func (m memSecrets) Get(n string) ([]byte, error) {
	v, ok := m[n]
	if !ok {
		return nil, secret.ErrNotFound
	}
	return v, nil
}
func (m memSecrets) Delete(n string) error { delete(m, n); return nil }
func (m memSecrets) List() ([]string, error) {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out, nil
}

func TestLoadOrCreateTokenIsStable(t *testing.T) {
	st, err := secret.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, err := LoadOrCreateToken(st)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := hex.DecodeString(a); err != nil || len(b) != 32 {
		t.Errorf("token %q is not 32 hex bytes", a)
	}
	b, err := LoadOrCreateToken(st)
	if err != nil || b != a {
		t.Errorf("second call = %q %v, want %q", b, err, a)
	}
	stored, err := st.Get(secret.ReservedAPIToken)
	if err != nil || string(stored) != a {
		t.Errorf("stored = %q %v", stored, err)
	}
	// Two stores never share a token.
	if other, _ := LoadOrCreateToken(memSecrets{}); other == a || len(other) != 64 {
		t.Errorf("other token %q", other)
	}
	// An empty stored value is replaced.
	m := memSecrets{secret.ReservedAPIToken: []byte("")}
	c, err := LoadOrCreateToken(m)
	if err != nil || len(c) != 64 || string(m[secret.ReservedAPIToken]) != c {
		t.Errorf("empty value: %q %v", c, err)
	}
	// A server built with an empty token refuses everything.
	h := New(Deps{Now: time.Now, Lang: i18n.EN, Policy: policy.Defaults()}, "")
	req := httptest.NewRequest("GET", "/api/v1/meta", nil)
	req.Host = "127.0.0.1:7331"
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("empty token server = %d", rec.Code)
	}
}
