package serverlog

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/target"
)

// ErrConfirmationNeeded means a setting moves away from the recommended
// choice and the user has not confirmed it yet.
var ErrConfirmationNeeded = errors.New("a log setting moves away from the recommended choice: confirmation needed")

// Keys of Deviations, stable: the page and the audit use them.
const (
	DeviationStoreText = "store_text"
	DeviationAlertText = "alert_text"
	DeviationRetention = "retention"
)

// RecommendedRetentionDays is the retention the spec recommends.
const RecommendedRetentionDays = 90

// MaxTextRunes caps the cleaned text kept for an error.
const MaxTextRunes = 200

// Actors of the audit events of this file.
const (
	settingsActor = "web"
	purgeActor    = "serverlog"
)

// Deviations lists the settings of s that are not the recommended choice, in
// a fixed order: keeping the text, sending it in alerts, and a retention
// other than 90 days (the spec's table calls any other value a choice away
// from the recommendation).
func Deviations(s Settings) []string {
	var d []string
	if s.StoreText {
		d = append(d, DeviationStoreText)
	}
	if s.AlertText {
		d = append(d, DeviationAlertText)
	}
	if s.RetentionDays != RecommendedRetentionDays {
		d = append(d, DeviationRetention)
	}
	return d
}

// newDeviations are the deviations of next that cur did not already have:
// only a new step away from the recommendation asks for a confirmation.
func newDeviations(cur, next Settings) []string {
	had := map[string]bool{}
	for _, k := range Deviations(cur) {
		had[k] = true
	}
	var out []string
	for _, k := range Deviations(next) {
		if !had[k] {
			out = append(out, k)
		}
	}
	return out
}

// sealText is the only way a text reaches text_enc (Repo.Apply calls it). The
// filter and the parser have already replaced addresses, numbers, quoted
// strings, emails and URLs; validText is checked once more here, so that a
// record built any other way cannot store one: such a text is dropped (nil,
// nil), the error itself is still counted. The masker then hides what looks
// like a secret, the result is capped and encrypted. A raw line is not a
// cleaned text and does not pass validText as a rule.
func sealText(text string) ([]byte, error) {
	masked, ok := cleanedText(text)
	if !ok {
		return nil, nil
	}
	b, err := secret.Protect([]byte(masked))
	if err != nil {
		return nil, fmt.Errorf("cannot protect the log text: %w", err)
	}
	return b, nil
}

// OpenText decrypts a text stored by Apply.
func OpenText(enc []byte) (string, error) {
	b, err := secret.Unprotect(enc)
	if err != nil {
		return "", fmt.Errorf("cannot read the log text: %w", err)
	}
	return string(b), nil
}

// ChangeSettings saves next as the settings of t. The text of alerts needs
// the text to be kept. A step away from the recommended choice needs
// confirmed (ErrConfirmationNeeded otherwise); on a hds server Michel asks
// the same and does not block, and the audit says "health". Going back to
// not keeping text erases the stored text at once. Every change is audited
// with setting names and values, never with content.
func ChangeSettings(ctx context.Context, repo *Repo, log *audit.Logger, t target.Target, next Settings, confirmed bool) error {
	next.TargetID = t.ID
	if err := checkSettings(next); err != nil {
		return err
	}
	cur, err := repo.Settings(ctx, t.ID)
	if err != nil {
		return err
	}
	fresh := newDeviations(cur, next)
	if len(fresh) > 0 && !confirmed {
		return fmt.Errorf("%w (%v)", ErrConfirmationNeeded, fresh)
	}
	if err := repo.SaveSettings(ctx, next); err != nil {
		return err
	}
	ev := map[string]any{
		"store_text": next.StoreText, "alert_text": next.AlertText, "retention_days": next.RetentionDays,
		"was_store_text": cur.StoreText, "was_alert_text": cur.AlertText, "was_retention_days": cur.RetentionDays,
		"deviations": append([]string{}, Deviations(next)...), "confirmed": confirmed,
		"health": t.Classification == "health",
	}
	if _, err := log.Record(ctx, audit.Event{Actor: settingsActor, Action: "log.settings", Target: t.ID, Result: "ok", Evidence: ev}); err != nil {
		return err
	}
	if next.StoreText {
		return nil
	}
	// Whenever the text is off, not only when it was just switched off: if
	// this erasure failed once, the settings already say "none", and the
	// next save must still remove what is left. A failure is returned, the
	// caller sees it and saves again.
	erased, err := repo.EraseText(ctx, t.ID)
	if err != nil {
		return err
	}
	if cur.StoreText || erased > 0 {
		return auditPurge(ctx, log, settingsActor, t.ID, map[string]any{"scope": "text", "rows": erased, "reason": "text_off"})
	}
	return nil
}

func auditPurge(ctx context.Context, log *audit.Logger, actor, target string, ev map[string]any) error {
	_, err := log.Record(ctx, audit.Event{Actor: actor, Action: "log.purge", Target: target, Result: "ok", Evidence: ev})
	return err
}

// PurgeAudited applies the retention at now (Repo.Purge) and audits it, unless
// nothing went, with the number of rows that went, never what they held. A nil
// log records nothing (see Deps.Audit).
func PurgeAudited(ctx context.Context, repo *Repo, log *audit.Logger, now time.Time) error {
	before, err := repo.rowCounts(ctx)
	if err != nil {
		return err
	}
	if err := repo.Purge(ctx, now); err != nil {
		return err
	}
	after, err := repo.rowCounts(ctx)
	if err != nil {
		return err
	}
	gone := [3]int64{before[0] - after[0], before[1] - after[1], before[2] - after[2]}
	if gone == [3]int64{} || log == nil {
		return nil // a tick that removed nothing is not worth an audit event
	}
	return auditPurge(ctx, log, purgeActor, "", map[string]any{
		"scope": "retention", "signatures": gone[0], "counts": gone[1], "notes": gone[2],
	})
}

// EraseTextAudited removes the stored text of a server (Repo.EraseText) and
// audits it.
func EraseTextAudited(ctx context.Context, repo *Repo, log *audit.Logger, actor, targetID string) (int64, error) {
	n, err := repo.EraseText(ctx, targetID)
	if err != nil {
		return 0, err
	}
	return n, auditPurge(ctx, log, actor, targetID, map[string]any{"scope": "text", "rows": n})
}

// rowCounts returns how many signatures, hourly counts and notes are held.
func (r *Repo) rowCounts(ctx context.Context) ([3]int64, error) {
	var c [3]int64
	for i, q := range []string{`SELECT COUNT(*) FROM log_signature`, `SELECT COUNT(*) FROM log_bucket`, `SELECT COUNT(*) FROM log_note`} {
		if err := r.s.DB().QueryRowContext(ctx, q).Scan(&c[i]); err != nil {
			return c, fmt.Errorf("cannot count the log data: %w", err)
		}
	}
	return c, nil
}

// cleanedText is the text a server error may carry out of the filter: it must
// pass validText, then the masker hides what looks like a secret and the
// result is capped. ok is false for a text that must be dropped. Alerts use it
// too, so that what is stored and what is sent are the same text.
func cleanedText(text string) (string, bool) {
	if !validText(text) {
		return "", false
	}
	masked := mask.New().Mask(text)
	if utf8.RuneCountInString(masked) > MaxTextRunes {
		masked = string([]rune(masked)[:MaxTextRunes])
	}
	return masked, true
}
