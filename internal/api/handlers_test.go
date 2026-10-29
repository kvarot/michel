package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/explain"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/source"
)

func TestTodayReturnsDigestInRequestedLang(t *testing.T) {
	f := newFixture(t, nil)
	for _, c := range []struct {
		query, acceptLang string
		want              i18n.Lang
	}{
		{"", "", i18n.EN},
		{"?lang=fr", "", i18n.FR},
		{"?lang=en", "fr-FR", i18n.EN},
		{"", "fr-CA,en;q=0.5", i18n.FR},
		{"", "de-DE", i18n.EN},
	} {
		resp, body := f.do("GET", "/api/v1/today"+c.query, testToken, "", "Accept-Language", c.acceptLang)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%+v: %d %s", c, resp.StatusCode, body)
		}
		var d digest.Digest
		if err := json.Unmarshal([]byte(body), &d); err != nil {
			t.Fatal(err)
		}
		want, err := digest.Compute(context.Background(), f.st, now, c.want, digest.Options{Assistant: "Michel"})
		if err != nil {
			t.Fatal(err)
		}
		if d.Lang != c.want || d.Title != want.Title || d.NewTotal != 2 || len(d.Projects) != 1 || d.Projects[0].Name != "demo" {
			t.Errorf("%+v: lang %s title %q (want %q) new %d", c, d.Lang, d.Title, want.Title, d.NewTotal)
		}
		if d.PageURL != "" || d.Assistant != "Michel" {
			t.Errorf("%+v: page %q assistant %q", c, d.PageURL, d.Assistant)
		}
		if len(d.Projects[0].New) == 0 || d.Projects[0].New[0].What != want.Projects[0].New[0].What {
			t.Errorf("%+v: what %+v", c, d.Projects[0].New)
		}
	}
	// Computing the page never records a run.
	var n int
	_ = f.st.DB().QueryRow(`SELECT COUNT(*) FROM digest_run`).Scan(&n)
	if n != 0 {
		t.Errorf("digest runs = %d", n)
	}
	resp, body := f.do("GET", "/api/v1/today?lang=de", testToken, "")
	var eb ErrorBody
	if resp.StatusCode != http.StatusBadRequest || json.Unmarshal([]byte(body), &eb) != nil || eb.Error == "" {
		t.Errorf("lang=de: %d %s", resp.StatusCode, body)
	}
}

func TestProjectsAndFindingsViews(t *testing.T) {
	f := newFixture(t, nil)
	var projects []map[string]any
	f.get("/api/v1/projects", &projects)
	if len(projects) != 1 {
		t.Fatalf("projects = %+v", projects)
	}
	p := projects[0]
	for _, k := range []string{"path", "test_cmd", "install_cmd", "id"} {
		if _, ok := p[k]; ok {
			t.Errorf("project view has %q: %+v", k, p)
		}
	}
	var pv ProjectView
	b, _ := json.Marshal(p)
	_ = json.Unmarshal(b, &pv)
	if pv.Name != "demo" || pv.FixLevel != 2 || pv.Classification == "" || pv.Total != 2 || pv.Open["critical"] != 1 || pv.Open["high"] != 1 ||
		pv.Open["medium"] != 0 || pv.Decided["ignore"] != 0 || pv.LastScanStatus != "ok" || pv.LastScanAt != ts(now.Add(-time.Hour)) {
		t.Errorf("project view = %+v", pv)
	}

	var list []map[string]any
	f.get("/api/v1/projects/demo/findings", &list)
	if len(list) != 2 || list[0]["package"] != "acme/vuln" || list[1]["package"] != "vuln-pkg" {
		t.Fatalf("findings = %+v", list)
	}
	if _, ok := list[0]["project_id"]; ok {
		t.Errorf("finding view has project_id: %+v", list[0])
	}
	ex, _ := list[0]["explanation"].(map[string]any)
	if ex == nil || ex["what"] == "" || list[0]["project"] != "demo" || list[0]["status"] != "new" || list[0]["id"] != f.ids["ACME-2026-0001"] {
		t.Errorf("finding view = %+v", list[0])
	}
	for q, want := range map[string]int{"?status=all": 3, "?status=gone": 1, "?status=new": 2, "?status=actionable": 2,
		"?severity=high": 1, "?status=all&severity=medium": 1, "?severity=low": 0, "?status=decided": 0} {
		var got []FindingView
		f.get("/api/v1/projects/demo/findings"+q, &got)
		if len(got) != want {
			t.Errorf("%s: %d findings, want %d", q, len(got), want)
		}
	}
	var fr []FindingView
	f.get("/api/v1/projects/demo/findings?lang=fr", &fr)
	var en []FindingView
	f.get("/api/v1/projects/demo/findings", &en)
	if len(fr) != 2 || fr[0].Explanation.What == "" || fr[0].Explanation.What == en[0].Explanation.What {
		t.Errorf("fr what %q / en %q", fr[0].Explanation.What, en[0].Explanation.What)
	}
	for path, code := range map[string]int{"/api/v1/projects/demo/findings?status=bogus": 400, "/api/v1/projects/demo/findings?severity=bogus": 400,
		"/api/v1/projects/nope/findings": 404} {
		resp, body := f.do("GET", path, testToken, "")
		var eb ErrorBody
		if resp.StatusCode != code || json.Unmarshal([]byte(body), &eb) != nil || eb.Error == "" {
			t.Errorf("%s = %d %s", path, resp.StatusCode, body)
		}
	}
	// A removed project is no longer listed.
	if _, err := f.st.DB().Exec(`UPDATE project SET active = 0`); err != nil {
		t.Fatal(err)
	}
	f.get("/api/v1/projects", &projects)
	if len(projects) != 0 {
		t.Errorf("inactive listed: %+v", projects)
	}
}

func TestFindingDetailHasExplanationAndDecision(t *testing.T) {
	f := newFixture(t, nil)
	id := f.ids["ACME-2026-0001"]
	var v FindingView
	body := f.get("/api/v1/findings/"+id, &v)
	fi, err := scan.NewRepo(f.st).FindByIDPrefix(context.Background(), id)
	if err != nil || len(fi) != 1 {
		t.Fatal(err)
	}
	a, _, _ := analyze.NewRepo(f.st).Get(context.Background(), id)
	facts := explain.FactsFrom(fi[0], a, true)
	facts.FixLevel = 2
	for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
		want, err := explain.Render(lang, facts)
		if err != nil {
			t.Fatal(err)
		}
		got := v
		if lang == i18n.FR {
			f.get("/api/v1/findings/"+id+"?lang=fr", &got)
		}
		if got.Explanation != want {
			t.Errorf("%s: explanation = %+v, want %+v", lang, got.Explanation, want)
		}
		if got.Glossary["transitive"] != explain.Term(lang, "transitive") || got.Glossary["breaking"] != explain.Term(lang, "breaking") {
			t.Errorf("%s: glossary = %+v", lang, got.Glossary)
		}
	}
	if v.ID != id || v.Package != "acme/vuln" || v.Project != "demo" || v.Analysis == nil || v.Decision != nil {
		t.Errorf("view = %+v", v)
	}
	if len(v.Analysis.Calls.Sites) != 1 || v.Analysis.Calls.Sites[0].File != "src/Billing/Invoice.php" || !v.Analysis.Changelog.Breaking {
		t.Errorf("analysis = %+v", v.Analysis)
	}
	if !strings.Contains(body, `"decision":null`) || strings.Contains(body, `"project_id":"`+f.proj.ID+`","manifest`) {
		t.Errorf("body = %s", body)
	}

	// Without analysis: the scan facts only, no glossary term about paths.
	var bare FindingView
	f.get("/api/v1/findings/"+f.ids["ACME-2026-0002"], &bare)
	if bare.Analysis != nil || bare.Explanation.What == "" || bare.Glossary["transitive"] != "" {
		t.Errorf("bare = %+v", bare)
	}

	// The decision in force is part of the view.
	if _, err := decide.NewRepo(f.st).Set(context.Background(), decide.Decision{FindingID: id, Action: decide.Fix, Author: "cli"}, now); err != nil {
		t.Fatal(err)
	}
	f.get("/api/v1/findings/"+id, &v)
	if v.Decision == nil || v.Decision.Action != decide.Fix || v.Status != "decided" {
		t.Errorf("decided view = %+v %+v", v, v.Decision)
	}
	// Exact ids only: a prefix or an unknown id is 404.
	for _, p := range []string{id[:8], "nope", f.ids["ACME-2026-0002"] + "x"} {
		resp, body := f.do("GET", "/api/v1/findings/"+p, testToken, "")
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, `"error"`) {
			t.Errorf("GET %s = %d %s", p, resp.StatusCode, body)
		}
	}
	// A gone finding is still shown.
	f.get("/api/v1/findings/"+f.gone, &v)
	if v.Status != "gone" {
		t.Errorf("gone view = %+v", v)
	}
}

// dueOf reads decision.due_at from a finding view.
func dueOf(t *testing.T, body string) string {
	t.Helper()
	var v struct {
		Decision struct {
			DueAt string `json:"due_at"`
		} `json:"decision"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	return v.Decision.DueAt
}

type auditRow struct {
	actor, action, target string
	evidence              map[string]any
}

func (f *fixture) auditRows(action string) []auditRow {
	f.t.Helper()
	rows, err := f.st.DB().Query(`SELECT actor, action, target, evidence FROM audit_event WHERE action = ? ORDER BY id`, action)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		var ev string
		if err := rows.Scan(&r.actor, &r.action, &r.target, &ev); err != nil {
			f.t.Fatal(err)
		}
		_ = json.Unmarshal([]byte(ev), &r.evidence)
		out = append(out, r)
	}
	return out
}

func TestPostDecisionAppliesSameRulesAsCLI(t *testing.T) {
	f := newFixture(t, nil)
	id := f.ids["ACME-2026-0002"]
	post := func(body, query string) (int, string) {
		t.Helper()
		resp, b := f.do("POST", "/api/v1/findings/"+id+"/decision"+query, testToken, body)
		return resp.StatusCode, b
	}
	for _, c := range []struct {
		body, query string
		lang        i18n.Lang
		hintKey     string
	}{
		{`{"action":"ignore"}`, "", i18n.EN, "api.decision.why_required"},
		{`{"action":"ignore","why":"   "}`, "?lang=fr", i18n.FR, "api.decision.why_required"},
		{`{"action":"later"}`, "", i18n.EN, "api.decision.unknown_action"},
		{`{"action":"defer","until":"2001-01-01"}`, "", i18n.EN, "api.decision.due_in_past"},
		{`{"action":"defer","until":"01/12/2099"}`, "", i18n.EN, "api.decision.bad_until"},
		{`{"action":"fix","until":"2099-12-01"}`, "", i18n.EN, "api.decision.date_not_defer"},
		{`{"action":"ignore","why":"` + strings.Repeat("é", decide.MaxJustification+1) + `"}`, "", i18n.EN, "api.decision.why_too_long"},
	} {
		code, b := post(c.body, c.query)
		var eb ErrorBody
		if code != http.StatusBadRequest || json.Unmarshal([]byte(b), &eb) != nil {
			t.Errorf("%s: %d %s", c.body[:min(len(c.body), 60)], code, b)
			continue
		}
		prefix := i18n.T(c.lang, c.hintKey)
		if i := strings.Index(prefix, "%"); i >= 0 {
			prefix = prefix[:i]
		}
		if eb.Error != i18n.T(c.lang, "api.decision.refused") || !strings.HasPrefix(eb.Hint, prefix) || eb.Hint == "" {
			t.Errorf("%s: error %q hint %q, want hint from %s", c.body[:min(len(c.body), 60)], eb.Error, eb.Hint, c.hintKey)
		}
	}
	if rows := f.auditRows("decision.set"); len(rows) != 0 {
		t.Fatalf("refused decisions audited: %+v", rows)
	}

	// defer without a date: 30 days, like the CLI.
	code, b := post(`{"action":"Defer ","why":" later\u0007 "}`, "")
	if code != http.StatusOK {
		t.Fatalf("defer: %d %s", code, b)
	}
	var v FindingView
	if err := json.Unmarshal([]byte(b), &v); err != nil {
		t.Fatal(err)
	}
	wantDue := now.Add(decide.DefaultDefer).Truncate(time.Second)
	if v.Decision == nil || v.Decision.Action != decide.Defer || dueOf(t, b) != ts(wantDue) || v.Decision.Author != "web" ||
		v.Decision.Justification != "later" || v.Status != "decided" || v.ID != id {
		t.Errorf("defer view = %+v %+v", v, v.Decision)
	}
	rows := f.auditRows("decision.set")
	if len(rows) != 1 {
		t.Fatalf("decision.set = %+v", rows)
	}
	r := rows[0]
	if r.actor != "web" || r.target != id || r.evidence["author"] != "web" || r.evidence["action"] != "defer" ||
		r.evidence["due_at"] != ts(wantDue) || r.evidence["package"] != "vuln-pkg" || r.evidence["osv_id"] != "ACME-2026-0002" ||
		r.evidence["justification"] != "later" || r.evidence["finding_id"] != id || r.evidence["project_id"] != f.proj.ID || len(r.evidence) != 8 {
		t.Errorf("decision.set = %+v", r)
	}
	var evID string
	_ = f.st.DB().QueryRow(`SELECT id FROM audit_event WHERE action = 'decision.set'`).Scan(&evID)
	if v.AuditEventID != evID || evID == "" {
		t.Errorf("audit event id %q, want %q", v.AuditEventID, evID)
	}

	// Deciding again replaces the decision, audited as on the CLI.
	code, b = post(`{"action":"defer","until":"2099-12-01"}`, "")
	if code != http.StatusOK {
		t.Fatalf("redefer: %d %s", code, b)
	}
	_ = json.Unmarshal([]byte(b), &v)
	if due := dueOf(t, b); due != "2099-12-01T00:00:00Z" {
		t.Errorf("until = %v", due)
	}
	sup := f.auditRows("decision.superseded")
	if len(sup) != 1 || sup[0].evidence["reason"] != "redecided" || sup[0].evidence["previous_action"] != "defer" || sup[0].actor != "web" {
		t.Errorf("decision.superseded = %+v", sup)
	}
	code, b = post(`{"action":"ignore","why":"only used by a dev tool"}`, "")
	if code != http.StatusOK || !strings.Contains(b, `"action":"ignore"`) {
		t.Errorf("ignore: %d %s", code, b)
	}

	// Gone: 409; unknown or prefix id: 404; nothing written.
	before := len(f.auditRows("decision.set"))
	resp, b := f.do("POST", "/api/v1/findings/"+f.gone+"/decision", testToken, `{"action":"fix"}`)
	var eb ErrorBody
	if resp.StatusCode != http.StatusConflict || json.Unmarshal([]byte(b), &eb) != nil || eb.Error == "" {
		t.Errorf("gone: %d %s", resp.StatusCode, b)
	}
	for _, p := range []string{id[:8], "nope"} {
		if resp, b := f.do("POST", "/api/v1/findings/"+p+"/decision", testToken, `{"action":"fix"}`); resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s: %d %s", p, resp.StatusCode, b)
		}
	}
	if after := len(f.auditRows("decision.set")); after != before {
		t.Errorf("decision.set %d -> %d", before, after)
	}
}

func TestAPIResponsesHaveNoAbsolutePathsNorCommands(t *testing.T) {
	f := newFixture(t, nil)
	// A recorded run, so /digests has content.
	d, err := digest.Compute(context.Background(), f.st, now, i18n.EN, digest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := digest.NewRepo(f.st).Save(context.Background(), digest.RunOf(d, now)); err != nil {
		t.Fatal(err)
	}
	// Sources whose stored errors name folders, a plugin with a report file,
	// an installed skill: their paths never leave either.
	ctx := context.Background()
	r := source.NewRepo(f.st)
	pathErr := "open " + filepath.Join(f.proj.Path, "composer.lock") + ": denied; open " + filepath.Join(f.dir, "osv", "npm.zip") +
		": denied; open " + winPathMarker + ": denied; open " + posixPathMarker + ": denied"
	for _, key := range []string{"osv.npm", "enrich.kev", "feed.nginx"} {
		if err := r.RecordRead(ctx, key, now, "error", pathErr, 0, ""); err != nil {
			t.Fatal(err)
		}
	}
	report := filepath.Join(f.proj.Path, "report.sarif")
	if err := os.WriteFile(report, []byte(demoSARIF), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Upsert(ctx, source.Entry{Key: "skill.demo", Kind: source.KindSkill, Origin: source.OriginUser, Name: "demo",
		URL: "https://github.com/example/skill", Hosts: []string{"api.github.com", "codeload.github.com"}, Purpose: policy.PurposeRepo,
		Config: source.Config{User: map[string]any{"repo": "example/skill", "pinned": demoPin, "installed_sha": demoPin,
			"install_dir": filepath.Join(f.dir, "skills", "demo")}}}); err != nil {
		t.Fatal(err)
	}
	var bodies []string
	keep := func(_ int, b string) { bodies = append(bodies, b) }
	addPlugin, _ := json.Marshal(map[string]any{"kind": "plugin", "name": "Demo SARIF", "format": "sarif", "input": report})
	keep(f.send("POST", "/api/v1/sources", string(addPlugin)))
	keep(f.send("POST", "/api/v1/sources/plugin.demo-sarif/enable", `{}`))
	code, b := f.send("POST", "/api/v1/sources/plugin.demo-sarif/run", `{"project":"demo"}`)
	bodies = append(bodies, b)
	var started struct {
		RunID string `json:"run_id"`
	}
	if code != http.StatusAccepted || json.Unmarshal([]byte(b), &started) != nil {
		t.Fatalf("run = %d %s", code, b)
	}
	_, runBody := f.waitRun(started.RunID)
	bodies = append(bodies, runBody)
	keep(f.send("POST", "/api/v1/sources/enrich.kev/enable", `{}`))
	keep(f.send("POST", "/api/v1/sources/enrich.kev/enable?lang=fr", `{}`))
	keep(f.send("POST", "/api/v1/sources/enrich.kev/enable", `{"consent":true}`))
	keep(f.send("POST", "/api/v1/sources/enrich.kev/disable", `{"forget":true}`))
	keep(f.send("POST", "/api/v1/sources/skill.demo/enable", `{"consent":true}`))
	keep(f.send("GET", "/api/v1/sources/skill.demo", ""))
	keep(f.send("DELETE", "/api/v1/sources/skill.demo", ""))
	keep(f.send("POST", "/api/v1/sources", `{"kind":"feed","name":"Mine","url":"https://example.org/feed"}`))
	keep(f.send("POST", "/api/v1/sources", `{"kind":"feed","name":"Mine","url":"http://example.org/feed"}`))
	keep(f.send("DELETE", "/api/v1/sources/feed.mine", ""))
	keep(f.send("POST", "/api/v1/sources/reset", `{"key":"feed.nginx"}`))
	keep(f.send("POST", "/api/v1/sources/feed.apple/run", `{"project":"demo"}`))
	keep(f.send("GET", "/api/v1/sources/feed.apple/preview", ""))
	for _, lang := range []string{"en", "fr"} {
		for _, path := range apiRoutes(f) {
			sep := "?"
			if strings.Contains(path, "?") {
				sep = "&"
			}
			_, body := f.do("GET", path+sep+"lang="+lang, testToken, "")
			bodies = append(bodies, body)
			_, body = f.do("GET", path, "", "")
			bodies = append(bodies, body)
		}
		for _, q := range []string{"?status=all", "?status=bogus"} {
			_, body := f.do("GET", "/api/v1/projects/demo/findings"+q+"&lang="+lang, testToken, "")
			bodies = append(bodies, body)
		}
		_, body := f.do("GET", "/api/v1/findings/"+f.gone+"?lang="+lang, testToken, "")
		bodies = append(bodies, body)
		_, body = f.do("GET", "/?lang="+lang, "", "")
		bodies = append(bodies, body)
	}
	for _, body := range []string{`{"action":"ignore"}`, `{"action":"fix"}`, `{"action":"defer","until":"2099-01-01"}`} {
		_, b := f.do("POST", "/api/v1/findings/"+f.ids["ACME-2026-0001"]+"/decision", testToken, body)
		bodies = append(bodies, b)
	}
	_, b = f.do("POST", "/api/v1/findings/"+f.gone+"/decision", testToken, `{"action":"fix"}`)
	bodies = append(bodies, b)
	var digests []digest.Run
	f.get("/api/v1/digests", &digests)
	if len(digests) != 1 {
		t.Errorf("digests = %+v", digests)
	}

	banned := []string{f.proj.Path, filepath.ToSlash(f.proj.Path), strings.ReplaceAll(f.proj.Path, `\`, `\\`),
		f.dir, filepath.ToSlash(f.dir), strings.ReplaceAll(f.dir, `\`, `\\`), `D:\\Data`, "/home/demo", "report_path", "install_dir",
		testCmdMarker, installCmdMarker, "phpunit-secret-marker", "test_cmd", "install_cmd", testToken}
	for _, body := range bodies {
		for _, s := range banned {
			if strings.Contains(body, s) {
				t.Errorf("response contains %q:\n%s", s, body)
			}
		}
	}
	if len(bodies) < 60 {
		t.Errorf("only %d responses checked", len(bodies))
	}
}

func TestMetaAndDigests(t *testing.T) {
	f := newFixture(t, nil)
	var m map[string]any
	f.get("/api/v1/meta?lang=fr", &m)
	if m["version"] != "test-version" || m["lang"] != "en" || m["assistant"] != "Michel" || m["osv_stale"] != false {
		t.Errorf("meta = %+v", m)
	}
	var runs []digest.Run
	f.get("/api/v1/digests", &runs)
	if runs == nil || len(runs) != 0 {
		t.Errorf("runs = %+v", runs)
	}
	for i := 0; i < 3; i++ {
		d, _ := digest.Compute(context.Background(), f.st, now.Add(time.Duration(i)*time.Hour), i18n.EN, digest.Options{})
		if err := digest.NewRepo(f.st).Save(context.Background(), digest.RunOf(d, now.Add(time.Duration(i)*time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	f.get("/api/v1/digests?last=2", &runs)
	if len(runs) != 2 || !runs[0].CreatedAt.After(runs[1].CreatedAt) {
		t.Errorf("last=2: %+v", runs)
	}
	f.get("/api/v1/digests", &runs)
	if len(runs) != 3 {
		t.Errorf("default: %d", len(runs))
	}
	for _, q := range []string{"?last=0", "?last=-1", "?last=abc", "?last=101"} {
		if resp, _ := f.do("GET", "/api/v1/digests"+q, testToken, ""); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d", q, resp.StatusCode)
		}
	}
}

// TestTodayKeepsTheLastDigestWindow: after the morning digest, the page
// still lists what that digest reported (its window extended to now).
func TestTodayKeepsTheLastDigestWindow(t *testing.T) {
	f := newFixture(t, nil)
	run := digest.Run{Since: now.Add(-25 * time.Hour), Until: now.Add(-time.Hour), Lang: i18n.EN, CreatedAt: now.Add(-time.Hour)}
	if err := digest.NewRepo(f.st).Save(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	var d digest.Digest
	f.get("/api/v1/today", &d)
	if !d.Since.Equal(run.Since) || !d.Until.Equal(now) || d.NewTotal != 2 || len(d.Projects) != 1 || len(d.Projects[0].New) != 2 {
		t.Errorf("since %v until %v new %d projects %+v", d.Since, d.Until, d.NewTotal, d.Projects)
	}
}

func TestFindingViewCarriesKEVAndEPSS(t *testing.T) {
	f := newFixture(t, nil)
	id := f.seed("acme/lib", "GHSA-kev", "unknown", "pending", now.Add(-time.Hour))
	if _, err := f.st.DB().Exec(`UPDATE finding SET kev = 1, kev_added = '2026-03-12', epss = 0.12, epss_percentile = 0.95,
		cvss_enriched = 9.1 WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	var v FindingView
	body := f.get("/api/v1/findings/"+id, &v)
	if !v.KEV || v.KEVAdded != "2026-03-12" || v.EPSS != 0.12 || v.EPSSPercentile != 0.95 || v.Malicious || v.Kind != "dependency" {
		t.Errorf("view = %+v", v)
	}
	if v.Severity != "critical" || v.SeveritySource != "enrichment" {
		t.Errorf("severity = %s from %s", v.Severity, v.SeveritySource)
	}
	for _, k := range []string{`"kev":true`, `"epss":0.12`, `"malicious":false`, `"kind":"dependency"`, `"severity_source":"enrichment"`} {
		if !strings.Contains(body, k) {
			t.Errorf("body lacks %s: %s", k, body)
		}
	}
	mal := f.seed("vuln-pkg", "MAL-2026-1", "critical", "new", now.Add(-time.Hour))
	if _, err := f.st.DB().Exec(`UPDATE finding SET malicious = 1 WHERE id = ?`, mal); err != nil {
		t.Fatal(err)
	}
	f.get("/api/v1/findings/"+mal, &v)
	if !v.Malicious || v.SeveritySource != "malicious" || v.KEV {
		t.Errorf("malicious view = %+v", v)
	}
}
