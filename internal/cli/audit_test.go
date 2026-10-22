package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/store"
	"github.com/spf13/cobra"
)

func run(t *testing.T, dir string, args ...string) (*Deps, string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	deps := &Deps{Stdout: &out, Stderr: &errOut, Now: time.Now}
	t.Cleanup(func() { deps.Close() })
	cmd := NewRootCmd(deps)
	cmd.AddCommand(&cobra.Command{Use: "noop", RunE: func(*cobra.Command, []string) error { return nil }})
	cmd.SetArgs(append([]string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", dir}, args...))
	err := cmd.Execute()
	deps.Close()
	return deps, out.String(), errOut.String(), err
}

func TestRootRecordsAppStart(t *testing.T) {
	dir := t.TempDir()
	deps, _, _, err := run(t, dir, "noop")
	if err != nil {
		t.Fatal(err)
	}
	_, out, _, err := run(t, dir, "audit", "verify")
	if err != nil || !strings.HasPrefix(out, "audit: 1 events verified, head ") {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if deps.Audit == nil || deps.Gateway == nil {
		t.Errorf("Audit/Gateway not wired: %+v", deps)
	}
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var action, target, result, ev string
	if err := s.DB().QueryRow(`SELECT action, target, result, evidence FROM audit_event`).Scan(&action, &target, &result, &ev); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(ev), &m)
	if action != "app.start" || target != "dev" || result != "ok" || m["mode"] != "strict_local" || m["policy_source"] != "defaults" || m["version"] != "dev" {
		t.Errorf("event = %s %s %s %v", action, target, result, m)
	}
}

func TestVersionSkipsStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	deps, out, _, err := run(t, dir, "version")
	if err != nil || !strings.Contains(out, "michel dev") || deps.Store != nil || deps.Audit != nil {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestAuditVerifyExitCode2OnTamper(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 2; i++ { // two app.start events
		if _, _, _, err := run(t, dir, "noop"); err != nil {
			t.Fatal(err)
		}
	}
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	var id string
	if err := s.DB().QueryRow(`SELECT id FROM audit_event ORDER BY rowid LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`UPDATE audit_event SET result='denied' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	s.Close()

	_, out, _, err := run(t, dir, "audit", "verify")
	if ExitCode(err) != 2 {
		t.Fatalf("exit = %d err=%v", ExitCode(err), err)
	}
	if want := "audit: BROKEN at event " + id + ": hash mismatch\n"; out != want {
		t.Errorf("out = %q, want %q", out, want)
	}

	_, out, _, err = run(t, dir, "--json", "audit", "verify")
	var j struct {
		Checked int
		Broken  *audit.Event
		Reason  string
	}
	if ExitCode(err) != 2 || json.Unmarshal([]byte(out), &j) != nil || j.Broken == nil || j.Broken.ID != id || j.Reason != "hash mismatch" {
		t.Errorf("json out=%q err=%v", out, err)
	}
}

func TestAuditListLast(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		run(t, dir, "noop")
	}
	_, out, _, err := run(t, dir, "audit", "list", "--last", "2")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "ts") || !strings.Contains(lines[1], "app.start") {
		t.Errorf("out = %q", out)
	}
}

func TestAuditCommandsWriteNothing(t *testing.T) {
	dir := t.TempDir()
	run(t, dir, "noop")
	count := func() int {
		s, err := store.Open(filepath.Join(dir, "michel.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		var n int
		s.DB().QueryRow(`SELECT COUNT(*) FROM audit_event`).Scan(&n)
		return n
	}
	before := count()
	for _, a := range [][]string{{"audit", "verify"}, {"audit", "list"}} {
		if _, _, _, err := run(t, dir, a...); err != nil {
			t.Fatal(err)
		}
	}
	if after := count(); after != before {
		t.Errorf("events %d -> %d: audit commands must not write", before, after)
	}
}

func TestAuditVerifyTailTruncated(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		run(t, dir, "noop")
	}
	s, _ := store.Open(filepath.Join(dir, "michel.db"))
	s.DB().Exec(`DELETE FROM audit_event WHERE rowid = (SELECT MAX(rowid) FROM audit_event)`)
	s.Close()
	_, out, _, err := run(t, dir, "audit", "verify")
	want := `audit: BROKEN at tail: tail truncated (expected 3 events, found 2)` + "\n"
	if ExitCode(err) != 2 || out != want {
		t.Errorf("out=%q err=%v", out, err)
	}
}

func TestAuditVerifyHeadAnchorAbsent(t *testing.T) {
	dir := t.TempDir()
	run(t, dir, "noop")
	if err := os.Remove(audit.HeadFile(filepath.Join(dir, "michel.db"))); err != nil {
		t.Fatal(err)
	}
	_, out, _, err := run(t, dir, "audit", "verify")
	if err != nil || strings.Contains(out, "BROKEN") || !strings.Contains(out, "audit: head anchor absent") ||
		!strings.HasPrefix(out, "audit: 1 events verified") {
		t.Errorf("out=%q err=%v", out, err)
	}
}
