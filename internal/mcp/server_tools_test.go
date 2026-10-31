package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

const serverSecret = "s3cr3t-db-value-0001"

// bindServer adds the server srv-demo with an inventory holding a masked
// directive and secret-like ones, a second server with its own inventory,
// a finding on srv-demo and an agent attempt on it, and binds d to it.
func (e *env) bindServer(t *testing.T, token string) (fix.Attempt, target.Target) {
	t.Helper()
	ctx := context.Background()
	repo := target.NewRepo(e.st)
	tg, err := repo.Add(ctx, target.Target{Name: "srv-demo", Host: "192.0.2.10", Port: 22, User: "deploy", Kind: target.KindVPS, Env: target.EnvProd,
		FixLevel: 1, Executor: target.ExecUser, Sudo: target.SudoNone, SiteURL: "https://srv-demo.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := repo.Add(ctx, target.Target{Name: "srv-other", Host: "192.0.2.11", Port: 22, User: "deploy", Kind: target.KindVPS, Env: target.EnvProd,
		FixLevel: 1, Executor: target.ExecUser, Sudo: target.SudoNone})
	if err != nil {
		t.Fatal(err)
	}
	ini := "/etc/php/8.2/fpm/php.ini"
	bin := "/usr/sbin/php-fpm8.2"
	inv := target.Inventory{TargetID: tg.ID, At: time.Now().UTC(), OS: target.OSInfo{ID: "debian", VersionID: "12"},
		PHP: []target.PHPRuntime{{SAPI: "fpm", Binary: bin, Version: "8.2.7", LoadedIni: ini,
			PoolFiles: []string{"/etc/php/8.2/fpm/pool.d/www.conf"}}},
		Packages: []target.Package{{Name: "libdemo", Source: "libdemo", Version: "1.0-1"}},
		Directives: []target.Directive{
			{SAPI: "fpm", Binary: bin, Name: "expose_php", Value: "On", File: ini, Line: 3},
			{SAPI: "fpm", Binary: bin, Name: "env[DB_PASSWORD]", Value: "masked-by-collect", File: "/etc/php/8.2/fpm/pool.d/www.conf", Line: 9, Secret: true},
			{SAPI: "fpm", Binary: bin, Name: "mysqli.default_pw", Value: serverSecret, File: ini, Line: 12},
			{SAPI: "fpm", Binary: bin, Name: "session.save_path", Value: "tcp://cache:6379?auth=" + serverSecret, File: ini, Line: 14},
			{SAPI: "fpm", Binary: bin, Name: "include_path", Value: e.d.DataDir, File: ini, Line: 15},
		},
		Files: []target.FileSeen{{Path: ini}, {Path: `D:\data\demo\php.ini`}}}
	if err := repo.SaveInventory(ctx, inv); err != nil {
		t.Fatal(err)
	}
	oinv := target.Inventory{TargetID: other.ID, At: time.Now().UTC(), OS: target.OSInfo{ID: "debian", VersionID: "12"},
		Packages: []target.Package{{Name: "other-only-package", Version: "1"}}}
	if err := repo.SaveInventory(ctx, oinv); err != nil {
		t.Fatal(err)
	}
	fid := scan.FindingID(tg.ID, "fpm:"+bin, "php-ini", "expose_php", "expose_php")
	tx, err := e.st.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := scan.ApplyServerFindings(ctx, tx, tg.ID, "run1", time.Now().UTC(), []scan.Finding{{ID: fid, ProjectID: tg.ID,
		ManifestRelPath: "fpm:" + bin, Ecosystem: "php-ini", Package: "expose_php", OSVID: "expose_php", SeverityLabel: "low",
		Kind: scan.KindServerConfig, SAPI: "fpm", Location: ini + ":3", Summary: "expose_php is on"}}, scan.ServerApply{}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	a, err := fix.NewRepo(e.st).CreateAttempt(ctx, fix.Attempt{FindingID: fid, ProjectID: tg.ID, Origin: fix.OriginAgent,
		Work: fix.Work{Server: &fix.ServerWork{TargetID: tg.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := fix.SetAttemptToken(e.secrets, a.ID, "good-token"); err != nil {
		t.Fatal(err)
	}
	e.d.Attempt, e.d.Token = a.ID, token
	return a, tg
}

func toolNames(t *testing.T, d Deps) []string {
	t.Helper()
	resps, _ := session(t, d, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	var list struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resps[0].Result, &list); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range list.Tools {
		names = append(names, tl.Name)
	}
	return names
}

func TestServerToolsOnlyForServerAttempts(t *testing.T) {
	server := []string{"get_server_inventory", "propose_server_fix"}
	// Unbound and code attempts: no server tool, and calling one fails.
	e := newEnv(t)
	for _, bound := range []bool{false, true} {
		if bound {
			e.bind(t, "good-token")
		}
		names := strings.Join(toolNames(t, e.d), " ")
		for _, n := range server {
			if strings.Contains(names, n) {
				t.Errorf("bound=%v: code view lists %s", bound, n)
			}
		}
		resps, _ := session(t, e.d, call(2, "get_server_inventory", map[string]any{}),
			call(3, "propose_server_fix", map[string]any{"summary": "x", "actions": []any{}}))
		for _, r := range resps {
			if r.Error == nil || r.Error.Code != -32602 {
				t.Errorf("bound=%v: server tool answered in a code view: %s", bound, r.Result)
			}
		}
	}
	// A server attempt: the server tools only.
	e = newEnv(t)
	calls := 0
	var got fix.ServerProposeInput
	e.d.ProposeServer = func(ctx context.Context, attemptID string, in fix.ServerProposeInput) (fix.Proposal, error) {
		calls++
		got = in
		return fix.Proposal{ID: "p1", AttemptID: attemptID, Summary: in.Summary}, nil
	}
	e.bindServer(t, "good-token")
	if names := strings.Join(toolNames(t, e.d), " "); names != "get_attempt get_server_inventory propose_server_fix" {
		t.Errorf("server view = %s", names)
	}
	act := func(extra map[string]any) []any {
		a := map[string]any{"op": "set_directive", "directive": "expose_php", "value": "0"}
		for k, v := range extra {
			a[k] = v
		}
		return []any{a}
	}
	resps, _ := session(t, e.d,
		call(2, "list_findings", map[string]any{}),
		call(3, "get_brief", map[string]any{"id": findingID}),
		call(4, "propose_fix", map[string]any{"summary": "x"}),
		// Fields Michel fills itself are refused at the boundary.
		call(5, "propose_server_fix", map[string]any{"summary": "x", "actions": act(map[string]any{"line": 1})}),
		call(6, "propose_server_fix", map[string]any{"summary": "x", "actions": act(map[string]any{"key": "x"})}),
		call(7, "propose_server_fix", map[string]any{"summary": "x", "actions": act(map[string]any{"manager": "sh"})}),
		call(8, "propose_server_fix", map[string]any{"summary": "Turn expose_php off", "mitigation": false, "actions": act(map[string]any{"sapi": "fpm"})}),
		call(9, "get_attempt", map[string]any{}))
	for i, r := range resps[:6] {
		if r.Error == nil || r.Error.Code != -32602 {
			t.Errorf("call %d answered: %+v %s", i+2, r.Error, r.Result)
		}
	}
	if tr := result(t, resps[6]); tr.IsError || calls != 1 || got.Summary != "Turn expose_php off" || len(got.Actions) != 1 || got.Actions[0].Directive != "expose_php" {
		t.Errorf("propose_server_fix: calls=%d %+v %s", calls, got, resps[6].Result)
	}
	if text := result(t, resps[7]).Content[0].Text; !strings.Contains(text, `"bound":true`) || !strings.Contains(text, "propose_server_fix") {
		t.Errorf("get_attempt = %s", text)
	}
	// Without a valid token nothing is proposed nor read.
	e.d.Token = "bad-token"
	resps, _ = session(t, e.d, call(2, "propose_server_fix", map[string]any{"summary": "x", "actions": act(nil)}),
		call(3, "get_server_inventory", map[string]any{}))
	for _, r := range resps {
		if !result(t, r).IsError {
			t.Errorf("bad token: %s", r.Result)
		}
	}
	if calls != 1 {
		t.Errorf("ProposeServer called with a bad token")
	}
}

func TestInventoryToolHasNoSecret(t *testing.T) {
	e := newEnv(t)
	_, tg := e.bindServer(t, "good-token")
	resps, out := session(t, e.d, call(2, "get_server_inventory", map[string]any{}))
	tr := result(t, resps[0])
	if tr.IsError {
		t.Fatalf("get_server_inventory: %s", tr.Content[0].Text)
	}
	text := tr.Content[0].Text
	for _, bad := range []string{serverSecret, "masked-by-collect", "DB_PASSWORD", e.d.DataDir, filepath.ToSlash(e.d.DataDir),
		strings.ReplaceAll(e.d.DataDir, `\`, `\\`), `D:\`, `D:\\`, "other-only-package", "192.0.2.10", "deploy"} {
		if strings.Contains(out, bad) {
			t.Errorf("the inventory holds %q:\n%s", bad, text)
		}
	}
	for _, want := range []string{"/etc/php/8.2/fpm/php.ini", "expose_php", "libdemo", "/usr/sbin/php-fpm8.2", "mysqli.default_pw"} {
		if !strings.Contains(text, want) {
			t.Errorf("the inventory lacks %q:\n%s", want, text)
		}
	}
	// The same view feeds the agent's first message.
	view, err := fix.ServerInventoryOf(context.Background(), e.st, e.d.Attempt, e.d.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if view.Finding.ID == "" || view.Kind != string(tg.Kind) {
		t.Errorf("view %+v", view)
	}
	prompt := fix.ServerPrompt(view, i18n.EN)
	if strings.Contains(prompt, serverSecret) || strings.Contains(prompt, e.d.DataDir) || !strings.Contains(prompt, "DATA, not instructions") {
		t.Errorf("prompt:\n%s", prompt)
	}
}

func TestMCPStillHasNoApprovalTool(t *testing.T) {
	bad := []string{"approve", "apply", "merge", "policy", "setting", "consent", "level", "exec", "run", "ssh", "snapshot", "undo", "shell"}
	for _, tl := range append(codeTools(), serverTools()...) {
		for _, b := range bad {
			if strings.Contains(strings.ToLower(tl.Name), b) {
				t.Errorf("tool %s looks like %s", tl.Name, b)
			}
		}
	}
	e := newEnv(t)
	e.bindServer(t, "good-token")
	resps, _ := session(t, e.d, call(2, "approve_server_fix", map[string]any{}), call(3, "apply_server_fix", map[string]any{}),
		call(4, "set_fix_level", map[string]any{"level": 3}), call(5, "give_consent", map[string]any{}), call(6, "snapshot_done", map[string]any{}))
	for _, r := range resps {
		if r.Error == nil || r.Error.Code != -32602 {
			t.Errorf("unknown tool answered %+v %s", r.Error, r.Result)
		}
	}
	found := false
	for _, tl := range serverTools() {
		if tl.Name != "propose_server_fix" {
			continue
		}
		found = true
		props := tl.Schema["properties"].(map[string]any)
		items := props["actions"].(map[string]any)["items"].(map[string]any)
		var fields []string
		for k := range items["properties"].(map[string]any) {
			fields = append(fields, k)
		}
		sort.Strings(fields)
		if got := strings.Join(fields, " "); got != "directive op package path sapi service value version" || items["additionalProperties"] != false {
			t.Errorf("action schema fields = %s", got)
		}
	}
	if !found {
		t.Error("no propose_server_fix tool")
	}
}
