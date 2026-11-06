package fix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/workcopy"
)

// SendMessage sends text to the agent of the attempt, masked, and keeps it in
// the conversation. ErrAgentGone when no session runs for it.
func SendMessage(ctx context.Context, d Deps, attemptID, text string) error {
	repo := d.repo()
	a, err := repo.GetAttempt(ctx, attemptID)
	if err != nil {
		return err
	}
	r, ok := d.sessions().get(attemptID)
	if !ok {
		return ErrAgentGone
	}
	if a.State != StatePreparing && a.State != StateProposed {
		return fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	text = strings.TrimSpace(scan.SanitizeText(text))
	if text == "" {
		return errors.New("the message is empty")
	}
	masked := r.mask(d.Secrets, attemptID, text)
	if _, err := repo.AddMessage(ctx, Message{AttemptID: attemptID, Role: RoleUser, Text: masked}); err != nil {
		return err
	}
	if err := r.sess.Send(masked); err != nil {
		return fmt.Errorf("%w: %v", ErrAgentGone, err)
	}
	return nil
}

// plainCause is the key of the sentence that tells the user, in plain
// words, why an attempt stopped and what to do. stage is the step that
// failed (fix.cause.prepare_failed, change_refused, agent_start_failed,
// apply_failed); a known error of the work copy gets its own sentence. The
// technical detail goes apart (Attempt.CauseDetail).
func plainCause(stage string, err error) string {
	switch {
	case errors.Is(err, ErrNotGit), errors.Is(err, workcopy.ErrNotGitRepo):
		return "fix.cause.not_git"
	case errors.Is(err, workcopy.ErrNoCommit):
		return "fix.cause.no_commit"
	case errors.Is(err, workcopy.ErrCopyTooLarge):
		return "fix.cause.too_large"
	case errors.Is(err, workcopy.ErrUnsafeInstall):
		return "fix.cause.unsafe_install"
	case stage == "fix.cause.change_refused" || changeRefused(err):
		return "fix.cause.change_refused"
	case stage == "fix.cause.agent_start_failed", stage == "fix.cause.apply_failed":
		return stage
	case err != nil && gitFailed.MatchString(err.Error()):
		return "fix.cause.git_failed"
	default:
		return "fix.cause.prepare_failed"
	}
}

// gitFailed matches the error of a failed git command (workcopy's gitErr).
var gitFailed = regexp.MustCompile(`\bgit [a-z-]+ failed\b`)

// changeRefused reports whether err is one of the refusals of the work
// copy that end the attempt with a cause.
func changeRefused(err error) bool {
	for _, target := range []error{workcopy.ErrOutsideCopy, workcopy.ErrExcludedPath, workcopy.ErrBinaryChange, workcopy.ErrDiffTooLarge,
		workcopy.ErrCopyTampered, workcopy.ErrNotACopy, workcopy.ErrInvalidCommit} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// noPath drops the file path of a file system error.
func noPath(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// maxShown bounds a command output quoted in a message.
const maxShown = 8000

// shown makes a text safe for a message of Michel: the copy, mirror and
// data folders replaced by <path>, control characters removed, bounded,
// then masked with the attempt's masker (secrets and other absolute paths).
func shown(m *mask.Masker, dirs []string, text string) string {
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		text = strings.ReplaceAll(text, dir, "<path>")
		text = strings.ReplaceAll(text, filepath.ToSlash(dir), "<path>")
	}
	text = strings.TrimSpace(scan.SanitizeText(strings.ToValidUTF8(text, "�")))
	if r := []rune(text); len(r) > maxShown {
		text = string(r[:maxShown]) + "…"
	}
	return m.Mask(text)
}

// maxDetail bounds the detail of an error in the audit log.
const maxDetail = 200

// auditDetail is what the audit keeps of an error: no path, no secret,
// sanitized and bounded.
func auditDetail(d Deps, err error) string {
	if err == nil {
		return ""
	}
	text := noPath(err).Error()
	if d.DataDir != "" {
		text = strings.ReplaceAll(text, d.DataDir, "<data>")
		text = strings.ReplaceAll(text, filepath.ToSlash(d.DataDir), "<data>")
	}
	text = mask.New().Mask(scan.SanitizeText(strings.ToValidUTF8(text, "")))
	if r := []rune(text); len(r) > maxDetail {
		text = string(r[:maxDetail]) + "…"
	}
	return text
}
