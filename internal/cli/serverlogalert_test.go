package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/notify"
	"github.com/kvarot/michel/internal/serverlog"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

func TestServerLogAlertAuditsAChannelBuildFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := func() time.Time { return time.Date(2026, 11, 3, 6, 0, 0, 0, time.UTC) }
	deps := &Deps{Store: st, Audit: audit.NewLogger(st, now), Now: now}
	in := serverlog.AlertInput{Target: target.Target{ID: "01SRVDEMO", Name: "srv-demo"}, Kind: serverlog.AlertNew}
	build := func() ([]notify.Notifier, error) { return nil, errors.New("secret store is locked") }
	sendServerLogAlert(context.Background(), deps, build, in, false)
	var actor, result, evidence string
	if err := st.DB().QueryRow(`SELECT actor, result, evidence FROM audit_event WHERE action = 'notify.send'`).Scan(&actor, &result, &evidence); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"01SRVDEMO", `"new"`} {
		if actor != "serverlog" || result != "error" || !strings.Contains(evidence, want) {
			t.Errorf("actor %q result %q evidence %s lacks %q", actor, result, evidence, want)
		}
	}
}
