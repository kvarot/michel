package fix

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/i18n"
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
