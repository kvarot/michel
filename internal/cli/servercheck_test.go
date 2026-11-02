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
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

func TestServerAlertAuditsAChannelBuildFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := func() time.Time { return time.Date(2026, 10, 23, 6, 0, 0, 0, time.UTC) }
	deps := &Deps{Store: st, Audit: audit.NewLogger(st, now), Now: now}
	in := servercheck.AlertInput{Target: target.Target{ID: "01SRVDEMO", Name: "srv-demo"}, Urgent: true, Kind: servercheck.AlertNew}
	build := func() ([]notify.Notifier, error) { return nil, errors.New("secret store is locked") }
	sendServerAlert(context.Background(), deps, build, in)
	var result, evidence string
	if err := st.DB().QueryRow(`SELECT result, evidence FROM audit_event WHERE action = 'notify.send'`).Scan(&result, &evidence); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"01SRVDEMO", `"new"`, "locked"} {
		if result != "error" || !strings.Contains(evidence, want) {
			t.Errorf("result %q evidence %s lacks %q", result, evidence, want)
		}
	}
}
