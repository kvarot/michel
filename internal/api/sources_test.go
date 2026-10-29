package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/feed"
	"github.com/kvarot/michel/internal/gitrepo"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sourceupdate"
)

const (
	demoPin  = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
	otherPin = "0123456789012345678901234567890123456789"
)

// Paths an error text may carry: they must never leave the server.
const (
	winPathMarker   = `D:\Data\example\michel\osv\npm.zip`
	posixPathMarker = `/home/demo/.config/michel/osv/npm.zip`
)

// send is an authenticated request with a JSON body; it returns the status
// and the body.
func (f *fixture) send(method, path, body string) (int, string) {
	f.t.Helper()
	resp, b := f.do(method, path, testToken, body)
	return resp.StatusCode, b
}

// sourceViews reads GET path as a list of sources.
func (f *fixture) sourceViews(path string) map[string]SourceView {
	f.t.Helper()
	var list []SourceView
	f.get(path, &list)
	out := map[string]SourceView{}
	for _, v := range list {
		out[v.Key] = v
	}
	return out
}

// setRules writes the policy file with these allow rules and hands them to
// the gateway, as a reload would.
func (f *fixture) setRules(rules ...policy.AllowRule) {
	f.t.Helper()
	for _, r := range rules {
		if _, err := policy.AddAllowRule(f.policyPath, r); err != nil {
			f.t.Fatal(err)
		}
	}
	p, _, err := policy.Load(f.policyPath, f.dir)
	if err != nil {
		f.t.Fatal(err)
	}
	f.gw.SetRules(p.Sovereignty.Network.Allow)
}

func TestSourcesListHidesSecretsAndPaths(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	r := source.NewRepo(f.st)
	readErr := "open " + winPathMarker + ": Access is denied.; open " + posixPathMarker + `: permission denied; Get "https://www.cisa.gov/x": EOF; file:///home/demo/x`
	if err := r.RecordRead(ctx, "osv.npm", now, "error", readErr, 0, ""); err != nil {
		t.Fatal(err)
	}
	installDir := filepath.Join(t.TempDir(), "skills", "demo")
	if _, err := r.Upsert(ctx, source.Entry{Key: "skill.demo", Kind: source.KindSkill, Origin: source.OriginUser, Name: "demo",
		URL: "https://github.com/example/skill", Hosts: []string{"api.github.com", "codeload.github.com"}, Purpose: policy.PurposeRepo,
		Config: source.Config{User: map[string]any{"repo": "example/skill", "pinned": demoPin, "installed_sha": demoPin, "install_dir": installDir}},
		Status: map[string]any{"archived": true, "stars": 3, "new_version": map[string]any{"from": demoPin, "to": otherPin}}}); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "report.sarif")
	if _, err := r.Upsert(ctx, source.Entry{Key: "plugin.demo-sarif", Kind: source.KindPlugin, Origin: source.OriginUser, Name: "Demo SARIF",
		Enabled: true, Config: source.Config{User: map[string]any{"format": "sarif", "tool": "generic", "run": false, "input": report}}}); err != nil {
		t.Fatal(err)
	}
	if err := r.SetEnabled(ctx, "discover.github", true); err != nil {
		t.Fatal(err)
	}
	if err := source.AddTech(ctx, f.st, "nginx"); err != nil {
		t.Fatal(err)
	}

	body := f.get("/api/v1/sources", nil)
	for _, leak := range []string{`D:\\Data`, "/home/demo", installDir, strings.ReplaceAll(installDir, `\`, `\\`), report,
		strings.ReplaceAll(report, `\`, `\\`), "_secret", "install_dir", `"input"`, f.dir, strings.ReplaceAll(f.dir, `\`, `\\`)} {
		if strings.Contains(body, leak) {
			t.Errorf("list leaks %q", leak)
		}
	}
	var list []SourceView
	f.get("/api/v1/sources", &list)
	last := -1
	for _, v := range list {
		i := slices.Index(source.Kinds, source.Kind(v.Kind))
		if i < last {
			t.Errorf("%s (%s) out of kind order", v.Key, v.Kind)
		}
		last = i
	}
	views := f.sourceViews("/api/v1/sources")
	npm := views["osv.npm"]
	if npm.State != "waiting_consent" || !npm.Enabled || npm.LastRead.Result != "error" || npm.LastRead.At != ts(now) {
		t.Errorf("osv.npm = %+v", npm)
	}
	if !strings.Contains(npm.LastRead.Error, "<path>") || !strings.Contains(npm.LastRead.Error, "https://www.cisa.gov/x") || strings.Contains(npm.LastRead.Error, "example") {
		t.Errorf("last read error = %q", npm.LastRead.Error)
	}
	if npm.Note != i18n.T(i18n.EN, "source.note.osv.npm") || npm.Origin != "catalog" || len(npm.Hosts) != 1 {
		t.Errorf("osv.npm note %q origin %q hosts %v", npm.Note, npm.Origin, npm.Hosts)
	}
	if v := views["enrich.nvd"]; len(v.Config) == 0 || v.Config["api_key_secret"] != nil || v.Config["format"] != "nvd" {
		t.Errorf("enrich.nvd config = %+v", v.Config)
	}
	if v := views["osv.pypi"]; v.State != "off" {
		t.Errorf("osv.pypi state %q", v.State)
	}
	// A plugin is never waiting for consent; a reference with hosts is,
	// like the digest's catalog line says.
	if v := views["plugin.demo-sarif"]; v.State != "on" || v.Config["has_input"] != true {
		t.Errorf("plugin = %+v", v)
	}
	if v := views["discover.github"]; v.State != "waiting_consent" {
		t.Errorf("discover.github state %q", v.State)
	}
	if err := r.RecordRead(ctx, "discover.github", now, "ok", "", 0, ""); err != nil {
		t.Fatal(err)
	}
	var tv TodayView
	f.get("/api/v1/today", &tv)
	if !slices.Contains(tv.Catalog.WaitingConsent, "discover.github") {
		t.Errorf("catalog waiting = %v", tv.Catalog.WaitingConsent)
	}
	f.setRules(policy.AllowRule{Host: "api.github.com", Purpose: policy.PurposeDiscover})
	if v := f.sourceViews("/api/v1/sources")["discover.github"]; v.State != "on" {
		t.Errorf("discover.github with its rule: %q", v.State)
	}
	f.get("/api/v1/today", &tv)
	if slices.Contains(tv.Catalog.WaitingConsent, "discover.github") {
		t.Errorf("catalog still waiting = %v", tv.Catalog.WaitingConsent)
	}
	sk := views["skill.demo"]
	if sk.State != "off" || !slices.Contains(sk.Badges, "new_version") || !slices.Contains(sk.Badges, "archived") ||
		sk.Config["installed"] != true || sk.Config["installed_sha"] != demoPin || sk.Note != "" {
		t.Errorf("skill = %+v", sk)
	}
	if v := views["feed.nginx"]; !slices.Contains(v.Badges, "suggested") || v.State != "off" {
		t.Errorf("feed.nginx = %+v", v)
	}
	if v := views["feed.apple"]; slices.Contains(v.Badges, "suggested") {
		t.Errorf("feed.apple suggested: %+v", v)
	}
	for _, v := range list {
		if v.Badges == nil || v.Hosts == nil || v.Tech == nil || v.Config == nil {
			t.Errorf("%s has a null list: %+v", v.Key, v)
		}
	}

	// Filters: by kind, hidden only with all=1.
	feeds := f.sourceViews("/api/v1/sources?kind=feed")
	for k, v := range feeds {
		if v.Kind != "feed" {
			t.Errorf("kind=feed lists %s", k)
		}
	}
	if len(feeds) == 0 {
		t.Error("no feed listed")
	}
	if code, b := f.send("GET", "/api/v1/sources?kind=bogus", ""); code != http.StatusBadRequest || !strings.Contains(b, `"hint"`) {
		t.Errorf("kind=bogus = %d %s", code, b)
	}
	if err := r.SetHidden(ctx, "feed.apple", true); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.sourceViews("/api/v1/sources")["feed.apple"]; ok {
		t.Error("hidden entry listed")
	}
	if v, ok := f.sourceViews("/api/v1/sources?all=1")["feed.apple"]; !ok || v.State != "hidden" || !v.Hidden {
		t.Errorf("all=1: %+v %v", v, ok)
	}

	// Detail: the rules, in the request's language.
	var d SourceDetailView
	body = f.get("/api/v1/sources/osv.npm?lang=fr", &d)
	if d.Key != "osv.npm" || len(d.Rules) != 1 || d.Rules[0].Host != "osv-vulnerabilities.storage.googleapis.com" || d.Rules[0].Allowed ||
		d.Rules[0].Purpose != policy.PurposeOSV || d.Note != i18n.T(i18n.FR, "source.note.osv.npm") || d.Items == nil {
		t.Errorf("detail = %+v", d)
	}
	if strings.Contains(body, "npm.zip") || strings.Contains(body, "/home/demo") {
		t.Errorf("detail leaks a path: %s", body)
	}
	if code, b := f.send("GET", "/api/v1/sources/nope.none", ""); code != http.StatusNotFound || !strings.Contains(b, `"error"`) {
		t.Errorf("unknown key = %d %s", code, b)
	}
}

func TestEnableWithoutConsentIs409WithText(t *testing.T) {
	f := newFixture(t, nil)
	for _, c := range []struct {
		query string
		lang  i18n.Lang
	}{{"", i18n.EN}, {"?lang=fr", i18n.FR}} {
		for _, body := range []string{`{}`, `{"consent":false}`} {
			code, b := f.send("POST", "/api/v1/sources/enrich.kev/enable"+c.query, body)
			var cb ConsentBody
			if code != http.StatusConflict || json.Unmarshal([]byte(b), &cb) != nil {
				t.Fatalf("%s %s = %d %s", c.query, body, code, b)
			}
			if cb.Error == "" || cb.Hint == "" || len(cb.Consent) != 1 {
				t.Fatalf("body = %+v", cb)
			}
			cv := cb.Consent[0]
			if cv.Host != "www.cisa.gov" || cv.Purpose != policy.PurposeEnrich || cv.What != i18n.T(c.lang, "source.consent.enrichment", "www.cisa.gov") ||
				cv.Rule != "{host: www.cisa.gov, purpose: source.enrich}" {
				t.Errorf("%s consent = %+v", c.lang, cv)
			}
		}
	}
	if _, err := os.Stat(f.policyPath); !os.IsNotExist(err) {
		t.Errorf("policy file written without consent: %v", err)
	}
	if v := f.sourceViews("/api/v1/sources")["enrich.kev"]; v.Enabled || v.State != "off" {
		t.Errorf("enabled without consent: %+v", v)
	}
	if rows := f.auditRows("source.consent"); len(rows) != 0 {
		t.Errorf("consent recorded: %+v", rows)
	}
	if code, _ := f.send("POST", "/api/v1/sources/nope.none/enable", `{"consent":true}`); code != http.StatusNotFound {
		t.Errorf("unknown key = %d", code)
	}
	if code, _ := f.send("POST", "/api/v1/sources/enrich.kev/enable", `{"consent":true,"yes":1}`); code != http.StatusBadRequest {
		t.Errorf("unknown field = %d", code)
	}
}

func TestEnableWithConsentWritesRuleAndReloadsGateway(t *testing.T) {
	f := newFixture(t, nil)
	if ok, _ := f.gw.Allowed("www.cisa.gov", policy.PurposeEnrich); ok {
		t.Fatal("allowed before consent")
	}
	code, b := f.send("POST", "/api/v1/sources/enrich.kev/enable", `{"consent":true}`)
	if code != http.StatusOK {
		t.Fatalf("enable = %d %s", code, b)
	}
	var v SourceView
	if err := json.Unmarshal([]byte(b), &v); err != nil || v.Key != "enrich.kev" || v.State != "on" || !v.Enabled {
		t.Errorf("view = %+v %v", v, err)
	}
	if ok, _ := f.gw.Allowed("www.cisa.gov", policy.PurposeEnrich); !ok {
		t.Error("the gateway did not learn the rule")
	}
	if raw, err := os.ReadFile(f.policyPath); err != nil || !strings.Contains(string(raw), "www.cisa.gov") {
		t.Errorf("policy file: %q %v", raw, err)
	}
	if strings.Contains(b, f.dir) || strings.Contains(b, strings.ReplaceAll(f.dir, `\`, `\\`)) {
		t.Errorf("answer names the data folder: %s", b)
	}
	rows := f.auditRows("source.consent")
	if len(rows) != 1 || rows[0].actor != "api" || rows[0].target != "enrich.kev" {
		t.Errorf("source.consent = %+v", rows)
	}
	// The server's own copy of the policy follows the reload.
	var m MetaView
	f.get("/api/v1/meta", &m)
	if m.Assistant != "Michel" {
		t.Errorf("meta = %+v", m)
	}

	// Disable keeps the rule; forget removes it.
	if code, b := f.send("POST", "/api/v1/sources/enrich.kev/disable", `{}`); code != http.StatusOK || !strings.Contains(b, `"state":"off"`) {
		t.Errorf("disable = %d %s", code, b)
	}
	if ok, _ := f.gw.Allowed("www.cisa.gov", policy.PurposeEnrich); !ok {
		t.Error("disable removed the rule")
	}
	if code, b := f.send("POST", "/api/v1/sources/enrich.kev/disable", `{"forget":true}`); code != http.StatusOK {
		t.Errorf("forget = %d %s", code, b)
	}
	if ok, _ := f.gw.Allowed("www.cisa.gov", policy.PurposeEnrich); ok {
		t.Error("forget kept the rule")
	}
	// A rule another enabled source needs is not forgotten.
	f.setRules(policy.AllowRule{Host: "osv-vulnerabilities.storage.googleapis.com", Purpose: policy.PurposeOSV})
	code, b = f.send("POST", "/api/v1/sources/osv.npm/disable", `{"forget":true}`)
	if code != http.StatusConflict || !strings.Contains(b, "osv.packagist") {
		t.Errorf("shared forget = %d %s", code, b)
	}
}

func TestAddSourceValidates(t *testing.T) {
	f := newFixture(t, nil)
	refused := i18n.T(i18n.EN, "api.source.add.refused")
	for _, body := range []string{
		`{"kind":"feed","name":"Demo","url":"http://example.org/feed"}`,
		`{"kind":"feed","name":"Demo","url":"https://example.org/feed","format":"json"}`,
		`{"kind":"feed","name":"Demo"}`,
		`{"kind":"feed","repo":"not a repo","format":"github_advisories"}`,
		`{"kind":"osv"}`,
		`{"kind":"osv","ecosystem":"../etc"}`,
		`{"kind":"plugin","name":"Demo","format":"xml"}`,
		`{"kind":"plugin","format":"sarif"}`,
		`{"kind":"plugin","name":"Demo","format":"sarif","tool":"nmap"}`,
		`{"kind":"plugin","name":"Demo","format":"sarif","input":"report.sarif"}`,
		`{"kind":"skill","repo":"example/skill"}`,
		`{"kind":"skill","repo":"example/skill","pin":"main"}`,
		`{"kind":"skill","repo":"example/skill","pin":"` + demoPin + `","path":"../up"}`,
		`{"kind":"reference","name":"Demo"}`,
		`{"kind":"feed","name":"Demo","url":"https://example.org/feed","tech":["Not A Tag"]}`,
	} {
		code, b := f.send("POST", "/api/v1/sources", body)
		var eb ErrorBody
		if code != http.StatusBadRequest || json.Unmarshal([]byte(b), &eb) != nil || eb.Error != refused || eb.Hint == "" {
			t.Errorf("%s = %d %s", body, code, b)
		}
	}
	if code, _ := f.send("POST", "/api/v1/sources", `{"kind":"feed","command":"rm"}`); code != http.StatusBadRequest {
		t.Errorf("unknown field = %d", code)
	}
	if rows := f.auditRows("source.add"); len(rows) != 0 {
		t.Fatalf("refused additions audited: %+v", rows)
	}

	code, b := f.send("POST", "/api/v1/sources", `{"kind":"feed","name":"Demo feed","url":"https://example.org/feed.xml","tech":["nginx"]}`)
	var v SourceView
	if code != http.StatusCreated || json.Unmarshal([]byte(b), &v) != nil {
		t.Fatalf("add feed = %d %s", code, b)
	}
	if v.Key != "feed.demo-feed" || v.Origin != "user" || v.State != "off" || v.Hosts[0] != "example.org" || v.Purpose != policy.PurposeFeed ||
		v.Config["format"] != "auto" || !slices.Equal(v.Tech, []string{"nginx"}) {
		t.Errorf("feed = %+v", v)
	}
	if code, b := f.send("POST", "/api/v1/sources", `{"kind":"feed","name":"Demo feed","url":"https://example.org/other.xml"}`); code != http.StatusConflict {
		t.Errorf("duplicate = %d %s", code, b)
	}
	code, b = f.send("POST", "/api/v1/sources", `{"kind":"skill","repo":"example/skill","pin":"`+demoPin+`","path":"skills/demo"}`)
	if code != http.StatusCreated || !strings.Contains(b, `"key":"skill.skill"`) || !strings.Contains(b, `"installed":false`) {
		t.Errorf("add skill = %d %s", code, b)
	}
	code, b = f.send("POST", "/api/v1/sources", `{"kind":"osv","ecosystem":"Hackage"}`)
	if code != http.StatusCreated || !strings.Contains(b, `"key":"osv.hackage"`) {
		t.Errorf("add osv = %d %s", code, b)
	}
	if code, _ := f.send("POST", "/api/v1/sources", `{"kind":"osv","ecosystem":"PyPI"}`); code != http.StatusConflict {
		t.Errorf("catalog ecosystem = %d", code)
	}
	report := filepath.Join(t.TempDir(), "report.sarif")
	body, _ := json.Marshal(map[string]any{"kind": "plugin", "name": "Demo SARIF", "format": "sarif", "input": report})
	code, b = f.send("POST", "/api/v1/sources", string(body))
	if code != http.StatusCreated || strings.Contains(b, "report.sarif") || !strings.Contains(b, `"has_input":true`) {
		t.Errorf("add plugin = %d %s", code, b)
	}
	if rows := f.auditRows("source.add"); len(rows) != 4 || rows[0].actor != "api" {
		t.Errorf("source.add = %+v", rows)
	}
}

func TestDeleteCatalogHidesUserDeletes(t *testing.T) {
	f := newFixture(t, nil)
	code, b := f.send("DELETE", "/api/v1/sources/feed.apple", "")
	if code != http.StatusOK || !strings.Contains(b, `"mode":"hidden"`) {
		t.Fatalf("delete catalog = %d %s", code, b)
	}
	if _, ok := f.sourceViews("/api/v1/sources")["feed.apple"]; ok {
		t.Error("hidden entry still listed")
	}
	if v := f.sourceViews("/api/v1/sources?all=1")["feed.apple"]; v.State != "hidden" {
		t.Errorf("all=1 = %+v", v)
	}
	// Reset brings it back.
	if code, b := f.send("POST", "/api/v1/sources/reset", `{"key":"feed.apple"}`); code != http.StatusOK || !strings.Contains(b, `"count":1`) {
		t.Errorf("reset = %d %s", code, b)
	}
	if _, ok := f.sourceViews("/api/v1/sources")["feed.apple"]; !ok {
		t.Error("reset did not show it again")
	}
	if code, _ := f.send("POST", "/api/v1/sources/reset", `{}`); code != http.StatusBadRequest {
		t.Errorf("reset without key = %d", code)
	}
	if code, _ := f.send("POST", "/api/v1/sources/reset", `{"key":"feed.apple","all":true}`); code != http.StatusBadRequest {
		t.Errorf("reset key and all = %d", code)
	}

	if code, b := f.send("POST", "/api/v1/sources", `{"kind":"feed","name":"Mine","url":"https://example.org/feed"}`); code != http.StatusCreated {
		t.Fatalf("add = %d %s", code, b)
	}
	if code, _ := f.send("POST", "/api/v1/sources/reset", `{"key":"feed.mine"}`); code != http.StatusBadRequest {
		t.Errorf("reset of a user entry = %d", code)
	}
	code, b = f.send("DELETE", "/api/v1/sources/feed.mine", "")
	if code != http.StatusOK || !strings.Contains(b, `"mode":"deleted"`) {
		t.Errorf("delete user = %d %s", code, b)
	}
	if code, _ := f.send("GET", "/api/v1/sources/feed.mine", ""); code != http.StatusNotFound {
		t.Errorf("deleted entry = %d", code)
	}
	if code, _ := f.send("DELETE", "/api/v1/sources/feed.mine", ""); code != http.StatusNotFound {
		t.Errorf("delete again = %d", code)
	}
	rows := f.auditRows("source.remove")
	if len(rows) != 2 || rows[0].evidence["mode"] != "hidden" || rows[1].evidence["mode"] != "deleted" || rows[1].actor != "api" {
		t.Errorf("source.remove = %+v", rows)
	}
	if rows := f.auditRows("source.reset"); len(rows) != 1 {
		t.Errorf("source.reset = %+v", rows)
	}
}

// skillArchive is the archive of example/skill: a skill under skills/demo
// and a licence at the root.
func skillArchive(t *testing.T) []byte {
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

// newPin is the commit of the second version of example/skill, whose
// front matter names the skill "renamed".
const newPin = "1234512345123451234512345123451234512345"

// renamedArchive is the archive of example/skill at newPin.
func renamedArchive(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	body := "---\nname: renamed\n---\n\n# Demo 2\n"
	if err := tw.WriteHeader(&tar.Header{Name: "skill-" + newPin + "/skills/demo/SKILL.md", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte(body))
	tw.Close()
	gz.Close()
	return b.Bytes()
}

// serveSkill serves example/skill at demoPin and newPin, points the skills
// folder at a temporary folder, writes the repository rules and adds
// skill.demo (off). It returns the skills folder.
func (f *fixture) serveSkill() string {
	t := f.t
	t.Helper()
	old, renamed := skillArchive(t), renamedArchive(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/example/skill/tar.gz/" + demoPin:
			w.Write(old)
		case "/example/skill/tar.gz/" + newPin:
			w.Write(renamed)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(gitrepo.SetBaseURLsForTest(srv.URL, srv.URL))
	skills := filepath.Join(t.TempDir(), "skills")
	t.Setenv(gitrepo.SkillsDirEnv, skills)
	f.setRules(policy.AllowRule{Host: "api.github.com", Purpose: policy.PurposeRepo}, policy.AllowRule{Host: "codeload.github.com", Purpose: policy.PurposeRepo},
		policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeRepo})
	if code, b := f.send("POST", "/api/v1/sources", `{"kind":"skill","repo":"example/skill","pin":"`+demoPin+`","path":"skills/demo","name":"demo"}`); code != http.StatusCreated {
		t.Fatalf("add = %d %s", code, b)
	}
	return skills
}

// markNewVersion records newPin as the new version of skill.demo.
func (f *fixture) markNewVersion() {
	f.t.Helper()
	if err := source.NewRepo(f.st).SetStatus(context.Background(), "skill.demo", map[string]any{"stars": 3,
		"new_version": map[string]any{"from": demoPin, "to": newPin}}); err != nil {
		f.t.Fatal(err)
	}
}

func TestPreviewAndInstallSkill(t *testing.T) {
	f := newFixture(t, nil)
	skills := f.serveSkill()
	// Off: no preview yet.
	if code, _ := f.send("GET", "/api/v1/sources/skill.demo/preview", ""); code != http.StatusConflict {
		t.Errorf("preview while off = %d", code)
	}
	if code, b := f.send("POST", "/api/v1/sources/skill.demo/enable", `{}`); code != http.StatusOK {
		t.Fatalf("enable = %d %s", code, b)
	}
	var p PreviewView
	body := f.get("/api/v1/sources/skill.demo/preview", &p)
	if p.Kind != "install" || p.Install == nil || p.Install.SHA != demoPin || p.Install.License.SPDX != "MIT" ||
		p.Install.WillWrite != filepath.Join(skills, "demo") || !slices.ContainsFunc(p.Install.Files, func(fi gitrepo.FileInfo) bool { return fi.Path == "SKILL.md" }) {
		t.Errorf("preview = %+v", p.Install)
	}
	if strings.Contains(body, f.dir) || strings.Contains(body, strings.ReplaceAll(f.dir, `\`, `\\`)) {
		t.Errorf("preview names the data folder: %s", body)
	}
	if _, err := os.Stat(skills); !os.IsNotExist(err) {
		t.Errorf("the preview wrote in the skills folder: %v", err)
	}
	// The version installed is the one shown.
	if code, _ := f.send("POST", "/api/v1/sources/skill.demo/install", `{"sha":"`+otherPin+`"}`); code != http.StatusBadRequest {
		t.Errorf("other sha = %d", code)
	}
	if code, _ := f.send("POST", "/api/v1/sources/skill.demo/install", `{}`); code != http.StatusBadRequest {
		t.Errorf("no sha = %d", code)
	}
	code, b := f.send("POST", "/api/v1/sources/skill.demo/install", `{"sha":"`+demoPin+`"}`)
	if code != http.StatusOK || !strings.Contains(b, `"installed":true`) {
		t.Fatalf("install = %d %s", code, b)
	}
	if raw, err := os.ReadFile(filepath.Join(skills, "demo", "SKILL.md")); err != nil || !strings.Contains(string(raw), "# Demo") {
		t.Errorf("SKILL.md: %q %v", raw, err)
	}
	if rows := f.auditRows("source.install"); len(rows) == 0 || rows[len(rows)-1].actor != "api" {
		t.Errorf("source.install = %+v", rows)
	}
	// No new version: nothing to upgrade.
	if code, _ := f.send("POST", "/api/v1/sources/skill.demo/upgrade", `{"sha":"`+otherPin+`"}`); code != http.StatusConflict {
		t.Errorf("upgrade without new version = %d", code)
	}
	// Removing an installed skill asks for confirmation.
	code, b = f.send("DELETE", "/api/v1/sources/skill.demo", "")
	if code != http.StatusConflict || !strings.Contains(b, `"error"`) {
		t.Errorf("delete without confirm = %d %s", code, b)
	}
	if _, err := os.Stat(filepath.Join(skills, "demo", "SKILL.md")); err != nil {
		t.Fatal("removed without confirmation")
	}
	if code, b := f.send("DELETE", "/api/v1/sources/skill.demo", `{"confirm":true}`); code != http.StatusOK || !strings.Contains(b, `"mode":"deleted"`) {
		t.Errorf("delete = %d %s", code, b)
	}
	if _, err := os.Stat(filepath.Join(skills, "demo")); !os.IsNotExist(err) {
		t.Errorf("skill folder still there: %v", err)
	}
	if code, _ := f.send("GET", "/api/v1/sources/feed.apple/preview", ""); code != http.StatusBadRequest {
		t.Errorf("preview of a feed = %d", code)
	}
}

// demoSARIF is a report with one finding in src/app.php.
const demoSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Demo","version":"1.0.0",
"rules":[{"id":"demo/injection","defaultConfiguration":{"level":"error"}}]}},
"results":[{"ruleId":"demo/injection","level":"error","message":{"text":"Injection."},
"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/app.php"},"region":{"startLine":3}}}]}]}]}`

// waitRun polls GET /plugin-runs/{id} until the run is no longer running.
func (f *fixture) waitRun(id string) (PluginRunView, string) {
	f.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		var v PluginRunView
		body := f.get("/api/v1/plugin-runs/"+id, &v)
		if v.Status != "running" || time.Now().After(deadline) {
			return v, body
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRunPluginReturns202AndRunStatus(t *testing.T) {
	f := newFixture(t, nil)
	report := filepath.Join(t.TempDir(), "report.sarif")
	if err := os.WriteFile(report, []byte(demoSARIF), 0o600); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"kind": "plugin", "name": "Demo SARIF", "format": "sarif", "input": report})
	if code, b := f.send("POST", "/api/v1/sources", string(body)); code != http.StatusCreated {
		t.Fatalf("add = %d %s", code, b)
	}
	// Off: refused before anything runs.
	if code, _ := f.send("POST", "/api/v1/sources/plugin.demo-sarif/run", `{"project":"demo"}`); code != http.StatusConflict {
		t.Errorf("run while off = %d", code)
	}
	if code, b := f.send("POST", "/api/v1/sources/plugin.demo-sarif/enable", `{}`); code != http.StatusOK {
		t.Fatalf("enable = %d %s", code, b)
	}
	for path, want := range map[string]int{
		"/api/v1/sources/plugin.demo-sarif/run": http.StatusNotFound, // unknown project
		"/api/v1/sources/feed.apple/run":        http.StatusBadRequest,
		"/api/v1/sources/nope.none/run":         http.StatusNotFound,
	} {
		project := "demo"
		if strings.Contains(path, "demo-sarif") {
			project = "nope"
		}
		if code, b := f.send("POST", path, `{"project":"`+project+`"}`); code != want {
			t.Errorf("%s = %d %s, want %d", path, code, b, want)
		}
	}
	if code, _ := f.send("POST", "/api/v1/sources/plugin.demo-sarif/run", `{}`); code != http.StatusBadRequest {
		t.Errorf("run without project = %d", code)
	}

	code, b := f.send("POST", "/api/v1/sources/plugin.demo-sarif/run", `{"project":"demo"}`)
	var started struct {
		RunID string `json:"run_id"`
	}
	if code != http.StatusAccepted || json.Unmarshal([]byte(b), &started) != nil || started.RunID == "" {
		t.Fatalf("run = %d %s", code, b)
	}
	v, raw := f.waitRun(started.RunID)
	if v.ID != started.RunID || v.Status != "ok" || v.Findings != 1 || v.Project != "demo" || v.SourceKey != "plugin.demo-sarif" || v.FinishedAt == "" {
		t.Errorf("run view = %+v", v)
	}
	for _, leak := range []string{"report_path", `"log"`, "report.sarif", f.proj.Path, strings.ReplaceAll(f.proj.Path, `\`, `\\`)} {
		if strings.Contains(raw, leak) {
			t.Errorf("run view leaks %q: %s", leak, raw)
		}
	}
	var findings []FindingView
	f.get("/api/v1/projects/demo/findings", &findings)
	if !slices.ContainsFunc(findings, func(fv FindingView) bool { return fv.SourceKey == "plugin.demo-sarif" && fv.RuleID == "demo/injection" }) {
		t.Errorf("plugin finding missing: %+v", findings)
	}
	if code, _ := f.send("GET", "/api/v1/plugin-runs/nope", ""); code != http.StatusNotFound {
		t.Errorf("unknown run = %d", code)
	}

	// A failed run keeps its error, without any path.
	if err := os.Remove(report); err != nil {
		t.Fatal(err)
	}
	code, b = f.send("POST", "/api/v1/sources/plugin.demo-sarif/run", `{"project":"demo"}`)
	if code != http.StatusAccepted || json.Unmarshal([]byte(b), &started) != nil {
		t.Fatalf("second run = %d %s", code, b)
	}
	v, raw = f.waitRun(started.RunID)
	if v.Status != "failed" || v.Error == "" || strings.Contains(raw, "report.sarif") || strings.Contains(raw, filepath.Dir(report)) {
		t.Errorf("failed run = %+v %s", v, raw)
	}
}

func TestItemsReadAndDiscoverActions(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	r := source.NewRepo(f.st)
	nginx, err := r.Get(ctx, "feed.nginx")
	if err != nil {
		t.Fatal(err)
	}
	if err := source.AddTech(ctx, f.st, "nginx"); err != nil {
		t.Fatal(err)
	}
	at := now.Add(-time.Hour).Format(time.RFC3339)
	if _, err := feed.NewRepo(f.st).Insert(ctx, []feed.Item{
		{SourceID: nginx.ID, GUID: "g1", Title: "nginx 1.27.3 fixes a flaw", URL: "https://nginx.org/a", PublishedAt: at, SeenAt: at},
		{SourceID: nginx.ID, GUID: "g2", Title: "nginx news", URL: "https://nginx.org/b", PublishedAt: at, SeenAt: at},
	}); err != nil {
		t.Fatal(err)
	}
	var items []ReadingView
	f.get("/api/v1/sources/items", &items)
	if len(items) != 2 || items[0].ID == "" || items[0].SourceKey != "feed.nginx" || items[0].Source != "nginx security advisories" || items[0].Read {
		t.Fatalf("items = %+v", items)
	}
	for _, q := range []string{"?since=bogus", "?since=-3d"} {
		if code, _ := f.send("GET", "/api/v1/sources/items"+q, ""); code != http.StatusBadRequest {
			t.Errorf("%s = %d", q, code)
		}
	}
	f.get("/api/v1/sources/items?since=30m", &items)
	if len(items) != 0 {
		t.Errorf("since=30m = %+v", items)
	}
	f.get("/api/v1/sources/items?since=7d&unread=1", &items)
	if len(items) != 2 {
		t.Fatalf("since=7d = %+v", items)
	}
	id := items[0].ID
	if code, b := f.send("POST", "/api/v1/sources/items/"+id+"/read", ""); code != http.StatusOK || !strings.Contains(b, `"read":true`) {
		t.Errorf("read = %d %s", code, b)
	}
	f.get("/api/v1/sources/items?unread=1", &items)
	if len(items) != 1 || items[0].ID == id {
		t.Errorf("unread after read = %+v", items)
	}
	f.get("/api/v1/sources/items", &items)
	if len(items) != 2 {
		t.Errorf("all items = %+v", items)
	}
	if code, _ := f.send("POST", "/api/v1/sources/items/nope/read", ""); code != http.StatusNotFound {
		t.Errorf("unknown item = %d", code)
	}
	if rows := f.auditRows("source.item_read"); len(rows) != 1 || rows[0].actor != "api" || rows[0].target != id {
		t.Errorf("source.item_read = %+v", rows)
	}

	// To discover: add, ignore.
	if _, err := f.st.DB().Exec(`INSERT INTO discovery (repo, topic, stars, description, html_url, first_seen_at, state) VALUES
		('example/mcp', 'mcp-security', 7, 'an MCP server', 'https://github.com/example/mcp', '2026-10-28T00:00:00Z', 'new'),
		('example/other', 'claude-skills', 3, 'other', '', '2026-10-28T00:00:00Z', 'new')`); err != nil {
		t.Fatal(err)
	}
	var found []gitrepo.Discovery
	f.get("/api/v1/sources/discoveries", &found)
	if len(found) != 2 {
		t.Fatalf("discoveries = %+v", found)
	}
	for body, want := range map[string]int{`{"action":"later"}`: 400, `{"action":"add","kind":"feed","pin":"` + demoPin + `"}`: 400,
		`{"action":"add","kind":"mcp","pin":"main"}`: 400} {
		if code, b := f.send("POST", "/api/v1/sources/discoveries/example/mcp", body); code != want {
			t.Errorf("%s = %d %s", body, code, b)
		}
	}
	if code, _ := f.send("POST", "/api/v1/sources/discoveries/example/none", `{"action":"ignore"}`); code != http.StatusNotFound {
		t.Errorf("unknown repo = %d", code)
	}
	code, b := f.send("POST", "/api/v1/sources/discoveries/example/mcp", `{"action":"add","kind":"mcp","pin":"`+demoPin+`"}`)
	if code != http.StatusCreated || !strings.Contains(b, `"key":"mcp.mcp"`) || !strings.Contains(b, `"state":"off"`) {
		t.Errorf("add = %d %s", code, b)
	}
	if code, b := f.send("POST", "/api/v1/sources/discoveries/example/other", `{"action":"ignore"}`); code != http.StatusOK {
		t.Errorf("ignore = %d %s", code, b)
	}
	f.get("/api/v1/sources/discoveries", &found)
	if len(found) != 0 {
		t.Errorf("after add and ignore = %+v", found)
	}

	// Technologies declared outside the projects.
	var tags []string
	f.get("/api/v1/tech", &tags)
	if !slices.Equal(tags, []string{"nginx"}) {
		t.Errorf("tech = %v", tags)
	}
	if code, b := f.send("POST", "/api/v1/tech", `{"tag":"postgresql"}`); code != http.StatusOK || !strings.Contains(b, "postgresql") {
		t.Errorf("add tech = %d %s", code, b)
	}
	if code, _ := f.send("POST", "/api/v1/tech", `{"tag":"Not A Tag"}`); code != http.StatusBadRequest {
		t.Errorf("bad tag = %d", code)
	}
	if code, b := f.send("DELETE", "/api/v1/tech/nginx", ""); code != http.StatusOK || strings.Contains(b, "nginx") {
		t.Errorf("remove tech = %d %s", code, b)
	}
	f.get("/api/v1/tech", &tags)
	if !slices.Equal(tags, []string{"postgresql"}) {
		t.Errorf("tech after = %v", tags)
	}
}

func TestTodayCarriesExploitedReadingCatalog(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	if _, err := f.st.DB().Exec(`UPDATE finding SET kev = 1, kev_added = '2026-03-12' WHERE id = ?`, f.ids["ACME-2026-0002"]); err != nil {
		t.Fatal(err)
	}
	r := source.NewRepo(f.st)
	if err := r.SetEnabled(ctx, "feed.nginx", true); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordRead(ctx, "feed.nginx", now, "error", "open "+winPathMarker+": denied", 0, ""); err != nil {
		t.Fatal(err)
	}
	f.setRules(policy.AllowRule{Host: "nginx.org", Purpose: policy.PurposeFeed})
	nginx, _ := r.Get(ctx, "feed.nginx")
	if err := source.AddTech(ctx, f.st, "nginx"); err != nil {
		t.Fatal(err)
	}
	at := now.Add(-time.Hour).Format(time.RFC3339)
	if _, err := feed.NewRepo(f.st).Insert(ctx, []feed.Item{{SourceID: nginx.ID, GUID: "g1", Title: "nginx fixes a flaw", URL: "https://nginx.org/a", PublishedAt: at, SeenAt: at}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DB().Exec(`INSERT INTO discovery (repo, topic, stars, description, html_url, first_seen_at, state) VALUES
		('example/mcp', 'mcp-security', 7, 'an MCP server', '', '2026-10-28T00:00:00Z', 'new')`); err != nil {
		t.Fatal(err)
	}
	var tv TodayView
	body := f.get("/api/v1/today?lang=fr", &tv)
	if len(tv.Exploited) != 1 || tv.Exploited[0].FindingID != f.ids["ACME-2026-0002"] || tv.Exploited[0].KEVAdded != "2026-03-12" || tv.ExploitedTotal != 1 {
		t.Errorf("exploited = %+v", tv.Exploited)
	}
	if len(tv.Reading) != 1 || tv.Reading[0].ID == "" || tv.Reading[0].Title != "nginx fixes a flaw" {
		t.Errorf("reading = %+v", tv.Reading)
	}
	if tv.Catalog.Silent || !slices.Contains(tv.Catalog.Failed, "feed.nginx") || !strings.Contains(tv.Catalog.Line, "feed.nginx") ||
		!strings.HasPrefix(tv.Catalog.Line, "Catalogue") || tv.Catalog.DiscoverNew != 1 || tv.DiscoverNew != 1 {
		t.Errorf("catalog = %+v, discover_new %d", tv.Catalog, tv.DiscoverNew)
	}
	for _, k := range []string{`"exploited_decided":0`, `"discover_new":1`, `"reading":[`, `"line":"`} {
		if !strings.Contains(body, k) {
			t.Errorf("today lacks %s", k)
		}
	}
	if strings.Contains(body, "npm.zip") {
		t.Errorf("today leaks a path: %s", body)
	}
	// The consent state follows the gateway, not the last read.
	if err := r.SetEnabled(ctx, "enrich.kev", true); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordRead(ctx, "enrich.kev", now, "ok", "", 3, ""); err != nil {
		t.Fatal(err)
	}
	f.get("/api/v1/today", &tv)
	if !slices.Contains(tv.Catalog.WaitingConsent, "enrich.kev") {
		t.Errorf("waiting = %+v", tv.Catalog.WaitingConsent)
	}
}

func TestNoPathsStripsLocalPathsWithSpaces(t *testing.T) {
	for in, want := range map[string]string{
		"open /home/x/My Projects/y.zip: permission denied":     "open <path>: permission denied",
		`open D:\Data\My Projects\y.zip: Access is denied.`:     "open <path>: Access is denied.",
		`read "/var/lib/michel/a b.json" failed`:                `read "<path>" failed`,
		"bad file (file:///home/x/My Projects/r.sarif) refused": "bad file (<path>) refused",
		`Get "https://www.cisa.gov/feeds/kev.json": EOF`:        `Get "https://www.cisa.gov/feeds/kev.json": EOF`,
		"open /tmp/x":             "open <path>",
		"no path here: just text": "no path here: just text",
	} {
		if got := noPaths(in); got != want {
			t.Errorf("noPaths(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUpgradeSkillFromThePage(t *testing.T) {
	f := newFixture(t, nil)
	skills := f.serveSkill()
	if code, b := f.send("POST", "/api/v1/sources/skill.demo/enable", `{}`); code != http.StatusOK {
		t.Fatalf("enable = %d %s", code, b)
	}
	if code, b := f.send("POST", "/api/v1/sources/skill.demo/install", `{"sha":"`+demoPin+`"}`); code != http.StatusOK {
		t.Fatalf("install = %d %s", code, b)
	}
	f.markNewVersion()
	if v := f.sourceViews("/api/v1/sources")["skill.demo"]; !slices.Contains(v.Badges, "new_version") {
		t.Errorf("badges = %v", v.Badges)
	}
	var p PreviewView
	f.get("/api/v1/sources/skill.demo/preview", &p)
	if p.Kind != "upgrade" || p.Upgrade == nil || p.Upgrade.From != demoPin || p.Upgrade.To != newPin ||
		p.Upgrade.OldDir != filepath.Join(skills, "demo") || p.Upgrade.NewDir != filepath.Join(skills, "renamed") || !strings.Contains(p.Upgrade.SkillMDDiff, "renamed") {
		t.Errorf("upgrade preview = %+v", p.Upgrade)
	}
	if _, err := os.Stat(filepath.Join(skills, "renamed")); !os.IsNotExist(err) {
		t.Errorf("the preview installed: %v", err)
	}
	// The installed version is no upgrade target, nor another sha.
	for _, sha := range []string{demoPin, otherPin} {
		if code, _ := f.send("POST", "/api/v1/sources/skill.demo/upgrade", `{"sha":"`+sha+`"}`); code != http.StatusBadRequest {
			t.Errorf("upgrade to %s = %d", sha, code)
		}
	}
	// The old folder carries another version's marker: Michel keeps it and
	// says so, the new version is installed all the same.
	marker := filepath.Join(skills, "demo", gitrepo.MarkerFile)
	if err := os.WriteFile(marker, []byte(`{"key":"skill.demo","sha":"`+otherPin+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, b := f.send("POST", "/api/v1/sources/skill.demo/upgrade", `{"sha":"`+newPin+`"}`)
	var iv InstallView
	if code != http.StatusOK || json.Unmarshal([]byte(b), &iv) != nil {
		t.Fatalf("upgrade = %d %s", code, b)
	}
	if iv.Warning != i18n.T(i18n.EN, "api.source.install.old_folder_kept") || iv.Source.Config["installed_sha"] != newPin ||
		slices.Contains(iv.Source.Badges, "new_version") || iv.Source.Status["new_version_available"] != false || iv.Source.Status["stars"] != float64(3) {
		t.Errorf("upgrade view = %+v", iv)
	}
	if strings.Contains(b, f.dir) || strings.Contains(b, strings.ReplaceAll(f.dir, `\`, `\\`)) {
		t.Errorf("answer names the data folder: %s", b)
	}
	if _, err := os.Stat(filepath.Join(skills, "renamed", "SKILL.md")); err != nil {
		t.Errorf("new version not installed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(skills, "demo")); err != nil {
		t.Errorf("the foreign-marked folder was removed: %v", err)
	}
	// Nothing left to upgrade.
	if code, _ := f.send("POST", "/api/v1/sources/skill.demo/upgrade", `{"sha":"`+newPin+`"}`); code != http.StatusConflict {
		t.Errorf("second upgrade = %d", code)
	}
}

func TestUpdateRoutesReadWithoutNetwork(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	// osv.packagist and osv.npm are on but wait for consent; enrich.kev too.
	if err := source.NewRepo(f.st).SetEnabled(ctx, "enrich.kev", true); err != nil {
		t.Fatal(err)
	}
	code, b := f.send("POST", "/api/v1/sources/enrich.kev/update", "")
	var uv UpdateView
	if code != http.StatusOK || json.Unmarshal([]byte(b), &uv) != nil {
		t.Fatalf("update one = %d %s", code, b)
	}
	if !slices.Equal(uv.WaitingConsent, []string{"enrich.kev"}) || uv.Source == nil || uv.Source.Key != "enrich.kev" ||
		uv.Source.LastRead.Result != "waiting_consent" || uv.Failed == nil || uv.Errors == nil || uv.SkipReasons == nil {
		t.Errorf("update one = %+v", uv)
	}
	code, b = f.send("POST", "/api/v1/sources/update", `{}`)
	uv = UpdateView{}
	if code != http.StatusOK || json.Unmarshal([]byte(b), &uv) != nil {
		t.Fatalf("update all = %d %s", code, b)
	}
	for _, k := range []string{"osv.packagist", "osv.npm", "enrich.kev"} {
		if !slices.Contains(uv.WaitingConsent, k) {
			t.Errorf("waiting = %v, lacks %s", uv.WaitingConsent, k)
		}
	}
	if uv.Source != nil {
		t.Errorf("update all names a source: %+v", uv.Source)
	}
	if code, _ := f.send("POST", "/api/v1/sources/nope.none/update", ""); code != http.StatusNotFound {
		t.Errorf("unknown key = %d", code)
	}
	// One update at a time.
	srv := New(f.deps, testToken).(*server)
	srv.updating.Lock()
	req := httptest.NewRequest("POST", "/api/v1/sources/update", nil)
	req.Host = "127.0.0.1:7331"
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	srv.updating.Unlock()
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), i18n.T(i18n.EN, "api.source.update.busy")) {
		t.Errorf("busy = %d %s", rec.Code, rec.Body.String())
	}
	// Errors and reasons leave without their paths.
	v := updateView(sourceupdate.Report{Failed: []string{"feed.nginx"}, Skipped: []string{"osv.npm"},
		Errors:      map[string]string{"feed.nginx": "open " + winPathMarker + ": denied; open " + posixPathMarker + ": denied"},
		SkipReasons: map[string]string{"osv.npm": "cannot read /home/demo/My Data/osv: gone"}})
	if v.Errors["feed.nginx"] != "open <path>: denied; open <path>: denied" || v.SkipReasons["osv.npm"] != "cannot read <path>: gone" ||
		v.Updated == nil || v.WaitingConsent == nil {
		t.Errorf("update view = %+v", v)
	}
}
