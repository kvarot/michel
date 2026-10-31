package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/fix"
)

// runWithStdin runs michel with stdin and returns stdout and stderr.
func runWithStdin(t *testing.T, dir, stdin string, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	deps := &Deps{Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errOut, Now: time.Now}
	t.Cleanup(func() { deps.Close() })
	cmd := NewRootCmd(deps)
	cmd.SetArgs(append([]string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", dir}, args...))
	err := cmd.Execute()
	deps.Close()
	return out.String(), errOut.String(), err
}

func TestMCPCommandReadOnlyWithoutEnv(t *testing.T) {
	t.Setenv(fix.EnvAttempt, "")
	t.Setenv(fix.EnvToken, "")
	dir, list := scannedDemo(t, true)
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_finding","arguments":{"id":"` + list[0].ID + `"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"propose_fix","arguments":{"summary":"bump"}}}`,
	}, "\n") + "\n"
	out, errOut, err := runWithStdin(t, dir, in, "mcp", "--lang", "en")
	if err != nil {
		t.Fatalf("mcp: %v\n%s", err, errOut)
	}
	// Stdout carries protocol messages only.
	var results []map[string]any
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil || m["jsonrpc"] != "2.0" {
			t.Fatalf("stdout line is not a protocol message: %q", sc.Text())
		}
		results = append(results, m)
	}
	if len(results) != 3 {
		t.Fatalf("got %d messages:\n%s", len(results), out)
	}
	if !strings.Contains(errOut, "read-only session") {
		t.Errorf("stderr lacks the read-only notice:\n%s", errOut)
	}
	get := results[1]["result"].(map[string]any)
	if get["isError"] != false {
		t.Errorf("get_finding failed: %v", get)
	}
	prop := results[2]["result"].(map[string]any)
	text := prop["content"].([]any)[0].(map[string]any)["text"].(string)
	if prop["isError"] != true || !strings.Contains(text, "read-only") {
		t.Errorf("propose_fix = %v", prop)
	}
	if strings.Contains(out, dir) || strings.Contains(out, strings.ReplaceAll(dir, `\`, `\`)) {
		t.Errorf("stdout leaks the data dir")
	}
}

func TestMCPCommandRefusesUnknownAttempt(t *testing.T) {
	t.Setenv(fix.EnvAttempt, "01JNOSUCHATTEMPT0000000000")
	t.Setenv(fix.EnvToken, "x")
	out, _, err := runWithStdin(t, t.TempDir(), "", "mcp")
	if err == nil || out != "" {
		t.Errorf("unknown attempt: err=%v out=%q", err, out)
	}
}
