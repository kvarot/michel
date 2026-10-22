package cli

import (
	"bytes"
	"errors"
	"github.com/kvarot/michel/internal/policy"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRootVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	deps := &Deps{Stdout: &out, Stderr: &errOut, Now: time.Now}
	cmd := NewRootCmd(deps)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "michel dev") {
		t.Fatalf("stdout = %q, want it to contain %q", out.String(), "michel dev")
	}
}

func TestRootPersistentFlags(t *testing.T) {
	cmd := NewRootCmd(&Deps{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Now: time.Now})
	for _, name := range []string{"config", "data-dir", "json"} {
		if cmd.PersistentFlags().Lookup(name) == nil {
			t.Errorf("missing persistent flag --%s", name)
		}
	}
}

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRootRefusesInvalidPolicy(t *testing.T) {
	cfg := writePolicy(t, "sovereignty:\n  ai:\n    external_providers_enabled: true\n")
	var out, errOut bytes.Buffer
	cmd := NewRootCmd(&Deps{Stdout: &out, Stderr: &errOut, Now: time.Now})
	cmd.SetArgs([]string{"--config", cfg, "--data-dir", t.TempDir(), "version"})
	err := cmd.Execute()
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 3 || ExitCode(err) != 3 {
		t.Fatalf("err = %v, want *ExitError with code 3", err)
	}
	for _, want := range []string{cfg, "strict_local forbids ai.external_providers_enabled", "Fix the file or delete it"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if out.Len() != 0 {
		t.Errorf("command ran despite invalid policy: %q", out.String())
	}
}

func TestRootLoadsPolicyAndReportsSource(t *testing.T) {
	dir := t.TempDir()
	deps := &Deps{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Now: time.Now}
	cmd := NewRootCmd(deps)
	cmd.SetArgs([]string{"--config", filepath.Join(dir, "none.yaml"), "--data-dir", dir, "version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if deps.PolicySource != policy.SourceDefaults || deps.Policy.Sovereignty.Mode != policy.ModeStrictLocal {
		t.Errorf("source=%q policy=%+v", deps.PolicySource, deps.Policy)
	}
	if !strings.Contains(deps.Stderr.(*bytes.Buffer).String(), "policy: defaults (no file at") {
		t.Errorf("stderr = %q", deps.Stderr.(*bytes.Buffer).String())
	}

	cfg := writePolicy(t, "assistant:\n  name: Gaston\n")
	deps2 := &Deps{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Now: time.Now}
	cmd = NewRootCmd(deps2)
	cmd.SetArgs([]string{"--config", cfg, "--data-dir", dir, "version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if deps2.PolicySource != policy.SourceFile || deps2.Policy.Assistant.Name != "Gaston" {
		t.Errorf("source=%q name=%q", deps2.PolicySource, deps2.Policy.Assistant.Name)
	}
	if !strings.Contains(deps2.Stderr.(*bytes.Buffer).String(), "policy: file "+cfg) {
		t.Errorf("stderr = %q", deps2.Stderr.(*bytes.Buffer).String())
	}
}

func TestRootFailsWithoutConfigDirAndFlags(t *testing.T) {
	old := userConfigDir
	userConfigDir = func() (string, error) { return "", errors.New("no home") }
	defer func() { userConfigDir = old }()

	cmd := NewRootCmd(&Deps{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Now: time.Now})
	cmd.SetArgs([]string{"version"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--config and --data-dir") {
		t.Fatalf("err = %v", err)
	}

	dir := t.TempDir()
	cmd = NewRootCmd(&Deps{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Now: time.Now})
	cmd.SetArgs([]string{"--config", filepath.Join(dir, "c.yaml"), "--data-dir", dir, "version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("with flags: %v", err)
	}
}
