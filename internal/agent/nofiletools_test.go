package agent

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestServerSessionHasNoFileTools: a session with NoFileTools (a server
// fix's agent) starts with no built-in tool at all and may use only
// Michel's MCP tools; a code session keeps its file tools.
func TestServerSessionHasNoFileTools(t *testing.T) {
	f := newFixture(t, fakeConfig{Turns: [][]string{{initLine, resultLine}}})
	spec := f.spec()
	spec.NoFileTools = true
	s, err := Start(context.Background(), f.d, spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	drain(t, s)
	r := f.record(t)
	setPath, _ := argAfter(r.Args, "--settings")
	set, _ := os.ReadFile(setPath)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if got, ok := argAfter(r.Args, "--tools"); !ok || got != "" {
		t.Errorf("--tools = %q (%t), want no built-in tool", got, ok)
	}
	var allowed []string
	for i, a := range r.Args {
		if a == "--allowedTools" {
			for _, x := range r.Args[i+1:] {
				if strings.HasPrefix(x, "--") {
					break
				}
				allowed = append(allowed, x)
			}
		}
	}
	if strings.Join(allowed, " ") != "mcp__michel__*" {
		t.Errorf("allowed = %q", allowed)
	}
	for _, tool := range []string{"Read", "Edit", "Write", "Glob", "Grep"} {
		if !slices.Contains(r.Args, tool) {
			t.Errorf("argv does not deny %s: %q", tool, r.Args)
		}
	}
	var cfg struct {
		Permissions struct {
			Allow []string `json:"allow"`
		} `json:"permissions"`
	}
	_ = json.Unmarshal(set, &cfg)
	if len(set) > 0 && strings.Join(cfg.Permissions.Allow, " ") != "mcp__michel__*" {
		t.Errorf("settings allow = %q", cfg.Permissions.Allow)
	}
	// A code session is unchanged.
	code := f.spec()
	if got := strings.Join(allowRules(code), " "); got != "Read(./**) Edit(./**) Write(./**) Glob Grep mcp__michel__*" {
		t.Errorf("code allow = %s", got)
	}
	if a, _ := argv(code, "m", "s"); func() string { v, _ := argAfter(a, "--tools"); return v }() != tools {
		t.Errorf("code --tools changed: %q", a)
	}
}
