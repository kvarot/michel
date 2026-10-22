package cli

import (
	"bytes"
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
