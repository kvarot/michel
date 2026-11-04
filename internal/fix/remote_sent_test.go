package fix

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/workcopy"
)

// The branch left, then Michel could not note it (the row of the push, or the
// audit log). The answer is a keyed refusal that says the send happened, not a
// bare error that the API turns into a 500, and a second click does not mislead.
func TestPushSentButNotNoted(t *testing.T) {
	for _, table := range []string{"fix_push", "audit_event"} {
		t.Run(table, func(t *testing.T) {
			f, spy := gitFixture(t)
			a, _ := applied(t, f)
			gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
			sayYes(t, f)
			pushes := 0
			spy.on = func(args, env []string) ([]byte, []byte, error, bool) {
				if slices.Contains(args, "push") {
					pushes++
					// The branch leaves, and the place where it is to be noted goes away.
					if _, err := f.st.DB().Exec(fmt.Sprintf(`ALTER TABLE %s RENAME TO %s_gone`, table, table)); err != nil {
						t.Fatal(err)
					}
					return pushAnswer(args, "*"), nil, nil, true
				}
				return nil, nil, nil, false
			}
			_, err := PushFix(context.Background(), f.d, a.ID)
			if pushes != 1 {
				t.Fatalf("pushes = %d", pushes)
			}
			if !errors.Is(err, ErrGitSentNotNoted) {
				t.Fatalf("err = %v, want ErrGitSentNotNoted", err)
			}
			if ErrorKey(err) != "api.git.sent_not_noted" {
				t.Errorf("key = %q", ErrorKey(err))
			}
			for _, lang := range []i18n.Lang{i18n.FR, i18n.EN} {
				say, hint := Explain(lang, err), ExplainHint(lang, err)
				if say == "" || hint == "" || strings.HasPrefix(say, "api.") || strings.HasPrefix(hint, "api.") {
					t.Errorf("%s: %q / %q", lang, say, hint)
				}
			}
		})
	}
}

// The second click, once the place where the push is noted is back: what the
// hint says. "=" (the branch is there, unchanged) sends nothing and notes it;
// "*" (the branch is gone from the site) sends it again and notes it; "!" (the
// branch moved on the site) is refused and nothing is noted.
func TestSecondClickAfterSentNotNoted(t *testing.T) {
	for _, c := range []struct {
		flag    string
		outcome string
		refused bool
	}{{"=", workcopy.PushAlready, false}, {"*", workcopy.PushPushed, false}, {"!", "", true}} {
		t.Run(c.flag, func(t *testing.T) {
			f, spy := gitFixture(t)
			a, _ := applied(t, f)
			gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
			sayYes(t, f)
			flag := "*"
			spy.on = func(args, env []string) ([]byte, []byte, error, bool) {
				if slices.Contains(args, "push") {
					return pushAnswer(args, flag), nil, nil, true
				}
				return nil, nil, nil, false
			}
			rename := func(from, to string) {
				if _, err := f.st.DB().Exec(fmt.Sprintf(`ALTER TABLE %s RENAME TO %s`, from, to)); err != nil {
					t.Fatal(err)
				}
			}
			rename("fix_push", "fix_push_gone")
			if _, err := PushFix(context.Background(), f.d, a.ID); !errors.Is(err, ErrGitSentNotNoted) {
				t.Fatalf("first click: %v", err)
			}
			rename("fix_push_gone", "fix_push")
			flag = c.flag
			out, err := PushFix(context.Background(), f.d, a.ID)
			_, noted, rerr := f.d.repo().Push(context.Background(), a.ID)
			if rerr != nil {
				t.Fatal(rerr)
			}
			if c.refused {
				if err == nil || ErrorKey(err) != "api.git.rejected" || noted {
					t.Errorf("err = %v, noted = %v", err, noted)
				}
				return
			}
			if err != nil || out.Outcome != c.outcome || !noted {
				t.Errorf("out = %+v, err = %v, noted = %v", out, err, noted)
			}
		})
	}
}

// Withdrawing a held fix whose flaw is gone says so in its cause.
func TestWithdrawHeldOnAGoneFlawSaysSo(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.plantKey()
	a := f.held()
	f.setFindingStatus(f.finding.ID, scan.StatusGone)
	if err := WithdrawHeld(context.Background(), f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	if got := f.attempt(a.ID); got.State != StateWithdrawn || got.Cause != i18n.T(f.d.lang(), "fix.cause.hold_withdrawn_gone") {
		t.Errorf("state %s, cause %q", got.State, got.Cause)
	}
	// A flaw still seen keeps the first sentence.
	f.setFindingStatus(f.finding.ID, scan.StatusPending)
	b := f.held()
	if err := WithdrawHeld(context.Background(), f.d, b.ID); err != nil {
		t.Fatal(err)
	}
	if got := f.attempt(b.ID); got.Cause != i18n.T(f.d.lang(), "fix.cause.hold_withdrawn") {
		t.Errorf("cause %q", got.Cause)
	}
}
