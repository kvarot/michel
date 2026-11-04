package fix

import (
	"context"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/target"
)

// D-1: a check that could not judge a finding does not say it still sees
// it. It says it could not judge, and what to turn on.
func TestProveSaysItCouldNotJudge(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		res      servercheck.CheckResult
		cause    string
		noSource bool
	}{
		{"source off", servercheck.CheckResult{Touched: true, SourceToEnable: "osv.debian"}, i18n.T(i18n.EN, "fix.server.cannot_judge_source", "osv.debian"), false},
		{"database missing", servercheck.CheckResult{Touched: true, SourceToEnable: "osv.debian", DatabaseMissing: true}, i18n.T(i18n.EN, "fix.server.cannot_judge_db", "osv.debian"), false},
		{"something unread", servercheck.CheckResult{Touched: true, ReleaseKnown: true, Unseen: 1}, i18n.T(i18n.EN, "fix.server.check_partial"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, s, a := pkgApproved(t)
			f.d.CheckServer = func(context.Context, string) (servercheck.CheckResult, error) { return tc.res, nil }
			if err := Apply(ctx, f.d, a.ID); err != nil {
				t.Fatal(err)
			}
			got := f.attempt(a.ID)
			if got.State != StateInconclusive || got.Cause != tc.cause {
				t.Errorf("state %s cause %q", got.State, got.Cause)
			}
			if strings.Contains(got.Cause, "still sees") {
				t.Errorf("says it still sees: %q", got.Cause)
			}
			steps := f.proposal(a.ID).Steps
			if last := steps[len(steps)-1]; last.Detail != detailPartial || last.OK {
				t.Errorf("last step %+v", last)
			}
			_ = s
		})
	}
}

// A finding the check really saw is still said to be seen.
func TestProveStillSeen(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	fd := f.finding(s, "expose_php")
	f.d.CheckServer = func(context.Context, string) (servercheck.CheckResult, error) {
		return servercheck.CheckResult{Touched: true, ReleaseKnown: true, Seen: []string{fd.ID}}, nil
	}
	if err := Apply(ctx, f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	got := f.attempt(a.ID)
	if got.State != StateInconclusive || got.Cause != i18n.T(i18n.EN, "fix.server.still_seen") {
		t.Errorf("state %s cause %q", got.State, got.Cause)
	}
}
