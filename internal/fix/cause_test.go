package fix

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/workcopy"
)

// TestPlainCauseIsASentenceForTheUser: a failure of the work copy is told
// with a plain sentence and what to do, never with git's own words; the
// technical detail stays apart.
func TestPlainCauseIsASentenceForTheUser(t *testing.T) {
	gitErr := errors.New("git clone failed: exit status 128 (fatal: failed to unlink '<path>': Filename too long)")
	for name, tc := range map[string]struct {
		stage string
		err   error
		want  string
	}{
		"git":            {"fix.cause.prepare_failed", gitErr, "fix.cause.git_failed"},
		"not git":        {"fix.cause.prepare_failed", fmt.Errorf("%w: %v", ErrNotGit, workcopy.ErrNotGitRepo), "fix.cause.not_git"},
		"no commit":      {"fix.cause.prepare_failed", fmt.Errorf("copy: %w", workcopy.ErrNoCommit), "fix.cause.no_commit"},
		"too large":      {"fix.cause.prepare_failed", fmt.Errorf("copy: %w", workcopy.ErrCopyTooLarge), "fix.cause.too_large"},
		"unsafe install": {"fix.cause.prepare_failed", fmt.Errorf("install: %w", workcopy.ErrUnsafeInstall), "fix.cause.unsafe_install"},
		"outside copy":   {"fix.cause.prepare_failed", fmt.Errorf("diff: %w", workcopy.ErrOutsideCopy), "fix.cause.change_refused"},
		"change stage":   {"fix.cause.change_refused", errors.New("anything"), "fix.cause.change_refused"},
		"agent":          {"fix.cause.agent_start_failed", errors.New("exec: claude: not found"), "fix.cause.agent_start_failed"},
		"apply":          {"fix.cause.apply_failed", gitErr, "fix.cause.apply_failed"},
		"other":          {"fix.cause.prepare_failed", errors.New("disk full"), "fix.cause.prepare_failed"},
	} {
		if got := plainCause(tc.stage, tc.err); got != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
	}
	keys := []string{"fix.cause.git_failed", "fix.cause.not_git", "fix.cause.no_commit", "fix.cause.too_large", "fix.cause.unsafe_install",
		"fix.cause.change_refused", "fix.cause.agent_start_failed", "fix.cause.apply_failed", "fix.cause.prepare_failed"}
	for _, k := range keys {
		for _, l := range []i18n.Lang{i18n.EN, i18n.FR} {
			text := i18n.T(l, k)
			if text == k || strings.Contains(text, "%") || strings.Contains(text, "git clone") || strings.Contains(text, "exit status") || !strings.HasSuffix(text, ".") {
				t.Errorf("%s %s is not a plain sentence: %q", l, k, text)
			}
		}
	}
}
