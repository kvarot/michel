package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/store"
)

// fakeAWS builds a fake AWS key in code, so no secret sits in the sources.
func fakeAWS() string { return "AKIA" + "ABCDEFGHIJKLMNOP" }

var tokenRe = regexp.MustCompile(`\[secret-[0-9a-f]{8}-[0-9]+\]`)

const findingID = "f1abcdef12345678"
const otherFindingID = "f2abcdef12345678"

type env struct {
	st      *store.Store
	secrets secret.Store
	root    string
	p       project.Project
	other   project.Project
	d       Deps
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func addFinding(t *testing.T, st *store.Store, id, projectID string) {
	t.Helper()
	if _, err := st.DB().Exec(`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, aliases, severity_label,
		cvss_score, installed_version, fixed_versions, status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, summary, kev, epss)
		VALUES (?, ?, 'composer.lock', 'Packagist', 'acme/lib', 'GHSA-aaaa-bbbb-cccc', '["CVE-2026-0001"]', 'high', 7.5,
		'1.0.0', '["1.0.1"]', 'new', 's1', 's1', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z', 'Remote code execution in the client', 0, 0.12)`,
		id, projectID); err != nil {
		t.Fatal(err)
	}
}

// newEnv builds the project demo (PHP, acme/lib 1.0.0 -> 1.0.1) with a use of
// the package at src/Http/Client.php:41 and a fake secret on the next line,
// plus a second project "other" with its own finding.
func newEnv(t *testing.T) env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	data := t.TempDir()
	secrets, err := secret.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	var lines []string
	for i := 1; i <= 60; i++ {
		lines = append(lines, fmt.Sprintf("// line %d", i))
	}
	lines[0] = "<?php"
	lines[40] = `use Acme\Lib\Client;`
	lines[41] = `$key = '` + fakeAWS() + `';`
	write(t, root, "src/Http/Client.php", strings.Join(lines, "\n")+"\n")
	write(t, root, "composer.lock", "{}")
	write(t, root, "composer.json", `{"require":{"acme/lib":"^1.0"}}`)
	write(t, root, "vendor/acme/lib/composer.json", `{"name":"acme/lib","autoload":{"psr-4":{"Acme\\Lib\\":"src/"}}}`)
	write(t, root, "vendor/acme/lib/CHANGELOG.md", "# Changelog\n\n## [1.0.1] - 2026-01-02\n### Removed\n- Removed the legacy option\n\n## [1.0.0] - 2026-01-01\n- First release\n")

	ctx := context.Background()
	p, err := project.NewRepo(st).Add(ctx, project.Project{Name: "demo", Path: root, TestCmd: "vendor/bin/phpunit", Tech: []string{"php"}})
	if err != nil {
		t.Fatal(err)
	}
	other, err := project.NewRepo(st).Add(ctx, project.Project{Name: "other", Path: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	addFinding(t, st, findingID, p.ID)
	addFinding(t, st, otherFindingID, other.ID)
	a := analyze.Analysis{FindingID: findingID, ProjectID: p.ID, ComputedAt: time.Now().UTC(), MichelVersion: "v1",
		Path:    analyze.DepPath{Directness: analyze.Direct, Via: []string{}},
		Upgrade: analyze.Upgrade{Target: "1.0.1", Jump: analyze.JumpPatch}, HasRootManifest: true,
		Calls:     analyze.CallSites{Count: 1, Quality: "psr4", Sites: []analyze.CallSite{{File: "src/Http/Client.php", Line: 41}}},
		Changelog: analyze.Changelog{Available: true},
		Risk:      analyze.Risk{Score: 34, Recommendation: analyze.RecAutoFix, Terms: map[string]int{}}}
	if err := analyze.NewRepo(st).Save(ctx, a); err != nil {
		t.Fatal(err)
	}
	return env{st: st, secrets: secrets, root: root, p: p, other: other,
		d: Deps{Store: st, DataDir: data, Policy: policy.Defaults(), Lang: i18n.EN, Secrets: secrets, Version: "test"}}
}

// bind creates an attempt on the demo finding with its token and mask table,
// and binds d to it.
func (e *env) bind(t *testing.T, token string) fix.Attempt {
	t.Helper()
	a, err := fix.NewRepo(e.st).CreateAttempt(context.Background(), fix.Attempt{FindingID: findingID, ProjectID: e.p.ID, Origin: fix.OriginAgent, CloneDir: e.root})
	if err != nil {
		t.Fatal(err)
	}
	if err := fix.SetAttemptToken(e.secrets, a.ID, "good-token"); err != nil {
		t.Fatal(err)
	}
	if err := mask.New().Save(e.secrets, a.ID); err != nil {
		t.Fatal(err)
	}
	e.d.Attempt, e.d.Token = a.ID, token
	return a
}

type reply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// session feeds lines to Serve and returns every reply line, decoded.
func session(t *testing.T, d Deps, lines ...string) ([]reply, string) {
	t.Helper()
	var out strings.Builder
	if err := Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out, d); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resps []reply
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	sc.Buffer(nil, 4<<20)
	for sc.Scan() {
		var r reply
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil || r.JSONRPC != "2.0" {
			t.Fatalf("output line is not a JSON-RPC message: %q (%v)", sc.Text(), err)
		}
		resps = append(resps, r)
	}
	return resps, out.String()
}

func call(id int, tool string, args any) string {
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	return string(raw)
}

const initLine = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"claude-code","version":"2"}}}`
const initializedLine = `{"jsonrpc":"2.0","method":"notifications/initialized"}`

type toolResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError"`
}

func result(t *testing.T, r reply) toolResult {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("error reply: %+v", r.Error)
	}
	var tr toolResult
	if err := json.Unmarshal(r.Result, &tr); err != nil || len(tr.Content) != 1 || tr.Content[0].Type != "text" {
		t.Fatalf("tool result %s: %v", r.Result, err)
	}
	return tr
}

func TestMCPInitializeAndList(t *testing.T) {
	e := newEnv(t)
	resps, _ := session(t, e.d, initLine, initializedLine, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, `{"jsonrpc":"2.0","id":"p","method":"ping"}`)
	if len(resps) != 3 {
		t.Fatalf("got %d responses, want 3 (a notification gets none)", len(resps))
	}
	var init struct {
		ProtocolVersion string                         `json:"protocolVersion"`
		Capabilities    map[string]json.RawMessage     `json:"capabilities"`
		ServerInfo      struct{ Name, Version string } `json:"serverInfo"`
	}
	if err := json.Unmarshal(resps[0].Result, &init); err != nil {
		t.Fatal(err)
	}
	if init.ProtocolVersion != "2025-06-18" || init.ServerInfo.Name != "michel" || init.ServerInfo.Version != "test" {
		t.Errorf("initialize = %s", resps[0].Result)
	}
	if _, ok := init.Capabilities["tools"]; !ok {
		t.Errorf("no tools capability: %s", resps[0].Result)
	}
	var list struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resps[1].Result, &list); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range list.Tools {
		names = append(names, tl.Name)
		if tl.InputSchema["type"] != "object" || tl.Description == "" {
			t.Errorf("tool %s: schema %v, description %q", tl.Name, tl.InputSchema, tl.Description)
		}
	}
	want := "list_findings get_finding get_brief get_call_sites get_changelog_excerpt get_attempt propose_fix"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("tools = %s, want %s", got, want)
	}
	if string(resps[2].ID) != `"p"` || string(resps[2].Result) != "{}" {
		t.Errorf("ping = %s %s", resps[2].ID, resps[2].Result)
	}

	// An unknown version gets the newest one; a known older one is kept.
	for v, want := range map[string]string{"1999-01-01": "2025-06-18", "2024-11-05": "2024-11-05"} {
		resps, _ := session(t, e.d, strings.Replace(initLine, "2025-06-18", v, 1))
		if err := json.Unmarshal(resps[0].Result, &init); err != nil || init.ProtocolVersion != want {
			t.Errorf("asked %s: got %s", v, resps[0].Result)
		}
	}
}

func TestMCPHasNoApprovalTool(t *testing.T) {
	for _, tl := range append(codeTools(), serverTools()...) {
		for _, bad := range []string{"approve", "apply", "merge", "policy", "setting"} {
			if strings.Contains(strings.ToLower(tl.Name), bad) {
				t.Errorf("tool %s looks like %s", tl.Name, bad)
			}
		}
	}
	e := newEnv(t)
	e.bind(t, "good-token")
	resps, _ := session(t, e.d, call(2, "approve_fix", map[string]any{}), call(3, "apply_fix", map[string]any{}))
	for _, r := range resps {
		if r.Error == nil || r.Error.Code != -32602 {
			t.Errorf("unknown tool answered %+v %s", r.Error, r.Result)
		}
	}
}

func TestMCPGetBriefIsMasked(t *testing.T) {
	e := newEnv(t)
	for _, bound := range []bool{false, true} {
		if bound {
			e.bind(t, "good-token")
		}
		resps, out := session(t, e.d, initLine,
			call(2, "get_brief", map[string]any{"id": findingID}),
			call(3, "get_call_sites", map[string]any{"id": findingID}),
			call(4, "get_finding", map[string]any{"id": findingID[:8]}),
			call(5, "get_changelog_excerpt", map[string]any{"id": findingID}),
			call(6, "list_findings", map[string]any{"project": "demo"}),
			call(7, "get_attempt", map[string]any{}))
		if strings.Contains(out, fakeAWS()) {
			t.Errorf("bound=%v: the secret leaks:\n%s", bound, out)
		}
		for _, r := range resps[1:] {
			text := result(t, r).Content[0].Text
			for _, abs := range []string{e.root, filepath.ToSlash(e.root), e.d.DataDir} {
				if strings.Contains(text, abs) || strings.Contains(text, strings.ReplaceAll(abs, `\`, `\\`)) {
					t.Errorf("bound=%v: an absolute path leaks (%s): %s", bound, abs, text)
				}
			}
		}
		var b struct{ Markdown string }
		if err := json.Unmarshal([]byte(result(t, resps[1]).Content[0].Text), &b); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.Markdown, "src/Http/Client.php") || !tokenRe.MatchString(b.Markdown) {
			t.Errorf("bound=%v: brief lacks the site or the mask token:\n%s", bound, b.Markdown)
		}
		sites := result(t, resps[2]).Content[0].Text
		if !strings.Contains(sites, "src/Http/Client.php") || !tokenRe.MatchString(sites) {
			t.Errorf("bound=%v: call sites = %s", bound, sites)
		}
		for i, r := range resps[1:] {
			if tr := result(t, r); tr.IsError {
				t.Errorf("bound=%v: call %d failed: %s", bound, i+2, tr.Content[0].Text)
			}
		}
		if cl := result(t, resps[4]).Content[0].Text; !strings.Contains(cl, "Removed the legacy option") {
			t.Errorf("changelog = %s", cl)
		}
	}
}

func TestMCPBoundSessionStaysInItsProject(t *testing.T) {
	e := newEnv(t)
	e.bind(t, "good-token")
	resps, _ := session(t, e.d,
		call(2, "list_findings", map[string]any{"project": "other"}),
		call(3, "get_finding", map[string]any{"id": otherFindingID}),
		call(4, "get_brief", map[string]any{"id": "f2ab"}),
		call(5, "list_findings", map[string]any{}))
	for _, r := range resps[:3] {
		if !result(t, r).IsError {
			t.Errorf("read outside the attempt's project: %s", r.Result)
		}
	}
	text := result(t, resps[3]).Content[0].Text
	if !strings.Contains(text, findingID) || strings.Contains(text, otherFindingID) {
		t.Errorf("list = %s", text)
	}

	// Unbound, every active project can be read.
	e.d.Attempt, e.d.Token = "", ""
	resps, _ = session(t, e.d, call(2, "list_findings", map[string]any{}), call(3, "get_finding", map[string]any{"id": otherFindingID}))
	if text := result(t, resps[0]).Content[0].Text; !strings.Contains(text, otherFindingID) || !strings.Contains(text, findingID) {
		t.Errorf("unbound list = %s", text)
	}
	if result(t, resps[1]).IsError {
		t.Errorf("unbound get_finding: %s", resps[1].Result)
	}
}

func TestMCPProposeNeedsToken(t *testing.T) {
	e := newEnv(t)
	calls := 0
	e.d.Propose = func(ctx context.Context, attemptID string, p fix.ProposeInput) (fix.Proposal, error) {
		calls++
		return fix.Proposal{ID: "p1", AttemptID: attemptID, Summary: p.Summary, Files: []string{"composer.lock"}, TestsStatus: "passed"}, nil
	}
	propose := call(2, "propose_fix", map[string]any{"summary": "bump acme/lib to 1.0.1", "notes": "lockfile only"})
	check := func(name string, d Deps) {
		t.Helper()
		resps, _ := session(t, d, propose)
		tr := result(t, resps[0])
		if !tr.IsError || !strings.Contains(tr.Content[0].Text, "read-only") {
			t.Errorf("%s: propose_fix = %s", name, resps[0].Result)
		}
	}
	check("no env", e.d)
	a := e.bind(t, "bad-token")
	check("bad token", e.d)
	d := e.d
	d.Token = ""
	check("attempt without token", d)
	d = e.d
	d.Attempt, d.Token = "", "good-token"
	check("token without attempt", d)
	if calls != 0 {
		t.Fatalf("Propose called %d times without a valid token", calls)
	}

	e.d.Token = "good-token"
	resps, _ := session(t, e.d, propose)
	tr := result(t, resps[0])
	if tr.IsError || calls != 1 || !strings.Contains(tr.Content[0].Text, "bump acme/lib") {
		t.Errorf("valid token: calls=%d %s", calls, resps[0].Result)
	}
	// A token deleted after the session started (the attempt ended) is
	// refused at the next call.
	if err := fix.DeleteAttemptToken(e.secrets, a.ID); err != nil {
		t.Fatal(err)
	}
	resps, _ = session(t, e.d, propose)
	if !result(t, resps[0]).IsError || calls != 1 {
		t.Errorf("deleted token: calls=%d %s", calls, resps[0].Result)
	}

	// The service's error comes back as a tool error.
	if err := fix.SetAttemptToken(e.secrets, a.ID, "good-token"); err != nil {
		t.Fatal(err)
	}
	e.d.Propose = func(context.Context, string, fix.ProposeInput) (fix.Proposal, error) {
		return fix.Proposal{}, errors.New("propose_fix is not available yet")
	}
	resps, _ = session(t, e.d, propose, call(3, "propose_fix", map[string]any{"summary": " "}))
	if tr := result(t, resps[0]); !tr.IsError || !strings.Contains(tr.Content[0].Text, "not available yet") {
		t.Errorf("service error: %s", resps[0].Result)
	}
	if !result(t, resps[1]).IsError {
		t.Errorf("empty summary accepted: %s", resps[1].Result)
	}
}

func TestMCPRejectsUnknownMethod(t *testing.T) {
	e := newEnv(t)
	resps, _ := session(t, e.d, `{"jsonrpc":"2.0","id":7,"method":"settings/set","params":{}}`, `{"jsonrpc":"2.0","method":"unknown/notification"}`)
	if len(resps) != 1 || resps[0].Error == nil || resps[0].Error.Code != -32601 || string(resps[0].ID) != "7" {
		t.Fatalf("responses = %+v", resps)
	}
}

func TestMCPMalformedLine(t *testing.T) {
	e := newEnv(t)
	long := `{"jsonrpc":"2.0","id":9,"method":"ping","params":{"x":"` + strings.Repeat("a", MaxLine) + `"}}`
	resps, _ := session(t, e.d, `{not json`, long, `{"jsonrpc":"2.0","id":3,"method":"ping"}`,
		call(4, "get_finding", map[string]any{"id": "../../etc"}),
		call(5, "get_finding", map[string]any{"id": findingID, "path": "/etc/passwd"}),
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":"x"}`)
	if len(resps) != 6 {
		t.Fatalf("got %d responses, want 6", len(resps))
	}
	for i := 0; i < 2; i++ {
		if resps[i].Error == nil || resps[i].Error.Code != -32700 || string(resps[i].ID) != "null" {
			t.Errorf("line %d: %+v %s", i, resps[i].Error, resps[i].ID)
		}
	}
	if resps[2].Error != nil || string(resps[2].ID) != "3" {
		t.Errorf("the server did not go on: %+v", resps[2])
	}
	if !result(t, resps[3]).IsError {
		t.Errorf("bad id accepted: %s", resps[3].Result)
	}
	for _, r := range resps[4:] {
		if r.Error == nil || r.Error.Code != -32602 {
			t.Errorf("invalid params answered %+v %s", r.Error, r.Result)
		}
	}
}
