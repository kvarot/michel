package cli

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/notify"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/serverlog"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

// brokenAuditDeps are Deps whose audit log refuses every notify.send row,
// and the buffer slog's default logger writes to while the test runs.
func brokenAuditDeps(t *testing.T) (*Deps, *bytes.Buffer) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.DB().Exec(`CREATE TRIGGER fail_notify BEFORE INSERT ON audit_event WHEN NEW.action = 'notify.send'
		BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	saved := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(saved) })
	now := func() time.Time { return time.Date(2026, 11, 5, 6, 0, 0, 0, time.UTC) }
	return &Deps{Store: st, Audit: audit.NewLogger(st, now), Now: now}, &buf
}

// A host-key refusal whose audit row cannot be written says so.
func TestTargetTrustRefusalAuditFailure(t *testing.T) {
	e := newTargetEnv(t)
	if _, _, _, err := run(t, e.dir, "target", "add", "srv-demo"); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(e.dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.DB().Exec(`CREATE TRIGGER fail_refusal BEFORE INSERT ON audit_event WHEN NEW.action = 'target.hostkey' AND NEW.result = 'refused'
		BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`)
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = run(t, e.dir, "target", "trust", "srv-demo", "--fingerprint", "SHA256:wrong")
	if err == nil || !strings.Contains(err.Error(), "not the one") || !strings.Contains(err.Error(), "audit log") {
		t.Errorf("wrong fingerprint, audit refused: %v", err)
	}
	setPin(t, e.dir, "srv-demo", "SHA256:other")
	_, _, _, err = run(t, e.dir, "target", "trust", "srv-demo", "--fingerprint", e.ssh.HostKeyFingerprint())
	if err == nil || !strings.Contains(err.Error(), "--replace") || !strings.Contains(err.Error(), "audit log") {
		t.Errorf("changed key, audit refused: %v", err)
	}
}

func TestServerAlertAuditFailureIsLogged(t *testing.T) {
	deps, buf := brokenAuditDeps(t)
	in := servercheck.AlertInput{Target: target.Target{ID: "01SRVDEMO", Name: "srv-demo"}, Kind: servercheck.AlertNew}
	sendServerAlert(context.Background(), deps, func() ([]notify.Notifier, error) { return nil, errors.New("locked") }, in)
	if out := buf.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "audit") || !strings.Contains(out, "01SRVDEMO") {
		t.Errorf("no warning for the lost audit row: %q", out)
	}
}

func TestServerLogAlertAuditFailureIsLogged(t *testing.T) {
	deps, buf := brokenAuditDeps(t)
	in := serverlog.AlertInput{Target: target.Target{ID: "01SRVDEMO", Name: "srv-demo"}, Kind: serverlog.AlertNew}
	sendServerLogAlert(context.Background(), deps, func() ([]notify.Notifier, error) { return nil, errors.New("locked") }, in, false)
	if out := buf.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "audit") || !strings.Contains(out, "01SRVDEMO") {
		t.Errorf("no warning for the lost audit row: %q", out)
	}
}
