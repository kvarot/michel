package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func (e env) findings(t *testing.T) map[string]string {
	t.Helper()
	rows, err := e.st.DB().Query(`SELECT rule_id, location, status FROM finding WHERE project_id = ?`, e.proj.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var r, l, s string
		if err := rows.Scan(&r, &l, &s); err != nil {
			t.Fatal(err)
		}
		out[r+"@"+l] = s
	}
	return out
}

func TestPluginRunDeniesEgressAndNeverWritesInProject(t *testing.T) {
	installFake(t, "trivy")
	t.Setenv("MICHEL_CANARY", "do-not-pass")
	e := newEnv(t)
	before := treeDigest(t, e.proj.Path)
	ctx := context.Background()
	entry := pluginEntry("plugin.trivy", "trivy", "sarif", true)
	res, err := RunPlugin(ctx, e.deps, entry, e.proj, "")
	if err != nil {
		t.Fatalf("RunPlugin: %v", err)
	}
	if res.New != 1 || res.RunID == "" {
		t.Errorf("result = %+v", res)
	}
	if after := treeDigest(t, e.proj.Path); after != before {
		t.Error("the project folder changed during the plugin run")
	}
	rel, err := filepath.Rel(filepath.Join(e.deps.DataDir, "plugins", "trivy"), res.ReportPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		t.Errorf("report %s is not under the data folder", res.ReportPath)
	}
	denied := false
	for _, ev := range e.events(t, "egress.attempt") {
		if ev.target == "ghcr.io" && ev.result == "denied" && strings.Contains(ev.evidence, `"purpose":"plugin.trivy"`) &&
			strings.Contains(ev.evidence, `"reason":"plugin subprocess"`) {
			denied = true
		}
	}
	if !denied {
		t.Errorf("no denied attempt to ghcr.io recorded: %+v", e.events(t, "egress.attempt"))
	}
	if got := e.findings(t); got["fake.rule@src/app.php:3"] != "new" {
		t.Errorf("findings = %v", got)
	}
	var kind, key string
	if err := e.st.DB().QueryRow(`SELECT kind, source_key FROM finding WHERE project_id = ?`, e.proj.ID).Scan(&kind, &key); err != nil ||
		kind != KindMisconfig || key != "plugin.trivy" {
		t.Errorf("kind %q key %q err %v", kind, key, err)
	}
	var status, version string
	var n int
	if err := e.st.DB().QueryRow(`SELECT status, tool_version, findings FROM plugin_run WHERE id = ?`, res.RunID).Scan(&status, &version, &n); err != nil ||
		status != "ok" || version != "0.99.0-fake" || n != 1 {
		t.Errorf("plugin_run = %s %s %d %v", status, version, n, err)
	}
	runs := e.events(t, "plugin.run")
	if len(runs) != 1 || runs[0].result != "ok" || runs[0].target != "plugin.trivy" {
		t.Fatalf("plugin.run events = %+v", runs)
	}
	var ev map[string]any
	_ = json.Unmarshal([]byte(runs[0].evidence), &ev)
	if h, _ := ev["argv_hash"].(string); len(h) != 64 || ev["argv"] != nil || ev["tool_version"] != "0.99.0-fake" ||
		ev["findings"] != 1.0 || ev["project"] != "demo" || ev["key"] != "plugin.trivy" {
		t.Errorf("plugin.run evidence = %v", ev)
	}
	for _, p := range []string{e.deps.DataDir, e.proj.Path, filepath.ToSlash(e.proj.Path)} {
		if strings.Contains(runs[0].evidence, strings.ReplaceAll(p, `\`, `\\`)) || strings.Contains(runs[0].evidence, p) {
			t.Errorf("the audit event holds a path: %s", runs[0].evidence)
		}
	}

	res, err = RunPlugin(ctx, e.deps, entry, e.proj, "")
	if err != nil || res.New != 0 || res.Still != 1 || res.Gone != 0 {
		t.Errorf("second run = %+v %v", res, err)
	}
}

func TestPluginRunIngestOnlyWithInput(t *testing.T) {
	e := newEnv(t)
	e.deps.Exec = func(context.Context, string, []string, []string, string) ([]byte, []byte, error) {
		t.Fatal("an ingest runs nothing")
		return nil, nil, nil
	}
	ctx := context.Background()
	entry := pluginEntry("plugin.codeql", "codeql", "sarif", false)
	res, err := RunPlugin(ctx, e.deps, entry, e.proj, filepath.Join("testdata", "codeql.sarif"))
	if err != nil || res.New != 2 {
		t.Fatalf("ingest = %+v %v", res, err)
	}
	// A second report without the note: that finding is gone.
	b, _ := os.ReadFile(filepath.Join("testdata", "codeql.sarif"))
	var doc map[string]any
	_ = json.Unmarshal(b, &doc)
	run := doc["runs"].([]any)[0].(map[string]any)
	run["results"] = run["results"].([]any)[:1]
	b, _ = json.Marshal(doc)
	second := filepath.Join(t.TempDir(), "second.sarif")
	if err := os.WriteFile(second, b, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err = RunPlugin(ctx, e.deps, entry, e.proj, second)
	if err != nil || res.New != 0 || res.Still != 1 || res.Gone != 1 {
		t.Errorf("second ingest = %+v %v", res, err)
	}
	if got := e.findings(t); got["js/unused-local-variable@src/util.js:7"] != "gone" || got["js/sql-injection@src/db.js:42"] != "pending" {
		t.Errorf("findings = %v", got)
	}
	var kind string
	if err := e.st.DB().QueryRow(`SELECT kind FROM finding WHERE rule_id = 'js/sql-injection'`).Scan(&kind); err != nil || kind != KindCode {
		t.Errorf("kind = %q %v", kind, err)
	}
	runs := e.events(t, "plugin.run")
	if len(runs) != 2 || !strings.Contains(runs[0].evidence, `"mode":"ingest"`) {
		t.Errorf("plugin.run = %+v", runs)
	}
}

func TestPluginRunNotRunnableForZAP(t *testing.T) {
	e := newEnv(t)
	called := false
	e.deps.Exec = func(context.Context, string, []string, []string, string) ([]byte, []byte, error) {
		called = true
		return nil, nil, nil
	}
	_, err := RunPlugin(context.Background(), e.deps, pluginEntry("plugin.zap", "zap", "sarif", true), e.proj, "")
	if !errors.Is(err, ErrNotRunnable) || called {
		t.Errorf("err %v, called %v", err, called)
	}
	if got := e.findings(t); len(got) != 0 {
		t.Errorf("findings = %v", got)
	}
}

func TestPluginRunToolFailureIsRecorded(t *testing.T) {
	e := newEnv(t)
	t.Setenv("MICHEL_CANARY", "x")
	e.deps.Exec = func(_ context.Context, _ string, args, env []string, dir string) ([]byte, []byte, error) {
		if len(args) == 1 && args[0] == "--version" {
			return []byte("semgrep 1.90.0\n"), nil, nil
		}
		for _, kv := range env {
			if strings.HasPrefix(kv, "MICHEL_") {
				t.Errorf("env leaks %s", kv)
			}
		}
		return nil, []byte("boom at " + dir), errors.New("exit status 2")
	}
	rules := filepath.Join(e.deps.DataDir, "plugins", "semgrep", "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rules, "r.yaml"), []byte("rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := RunPlugin(context.Background(), e.deps, pluginEntry("plugin.semgrep", "semgrep", "sarif", true), e.proj, "")
	if err == nil || strings.Contains(err.Error(), e.deps.DataDir) || strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
	var status, log string
	if err := e.st.DB().QueryRow(`SELECT status, log FROM plugin_run`).Scan(&status, &log); err != nil || status != "failed" || !strings.Contains(log, "boom") {
		t.Errorf("plugin_run = %s %q %v", status, log, err)
	}
	if runs := e.events(t, "plugin.run"); len(runs) != 1 || runs[0].result != "failed" {
		t.Errorf("plugin.run = %+v", runs)
	}
}

func TestSemgrepWithoutRulesSaysSo(t *testing.T) {
	e := newEnv(t)
	e.deps.Exec = func(_ context.Context, _ string, args, _ []string, _ string) ([]byte, []byte, error) {
		if len(args) == 1 && args[0] == "--version" {
			return []byte("1.90.0\n"), nil, nil
		}
		t.Fatal("semgrep must not run without rules")
		return nil, nil, nil
	}
	_, err := RunPlugin(context.Background(), e.deps, pluginEntry("plugin.semgrep", "semgrep", "sarif", true), e.proj, "")
	if !errors.Is(err, ErrNoRules) {
		t.Errorf("err = %v", err)
	}
}

func TestPluginRunNotInstalled(t *testing.T) {
	e := newEnv(t)
	t.Setenv("PATH", t.TempDir())
	_, err := RunPlugin(context.Background(), e.deps, pluginEntry("plugin.trivy", "trivy", "sarif", true), e.proj, "")
	if !errors.Is(err, ErrNotInstalled) {
		t.Errorf("err = %v", err)
	}
}

func TestEnvIsAnAllowlist(t *testing.T) {
	t.Setenv("MICHEL_CANARY", "x")
	t.Setenv("GITHUB_TOKEN", "x")
	env := toolEnv("127.0.0.1:1")
	want := map[string]bool{"HTTP_PROXY=http://127.0.0.1:1": true, "HTTPS_PROXY=http://127.0.0.1:1": true,
		"ALL_PROXY=http://127.0.0.1:1": true, "NO_PROXY=": true, "TRIVY_SKIP_DB_UPDATE=true": true, "SEMGREP_SEND_METRICS=off": true}
	for _, kv := range env {
		name := strings.ToUpper(kv[:strings.IndexByte(kv, '=')])
		switch name {
		case "PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "USERPROFILE", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
			"TRIVY_SKIP_DB_UPDATE", "SEMGREP_SEND_METRICS":
		default:
			t.Errorf("variable outside the allowlist: %s", kv)
		}
		delete(want, kv)
	}
	if len(want) != 0 {
		t.Errorf("missing: %v", want)
	}
}
