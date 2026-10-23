package decide

import (
	"context"
	"time"

	"github.com/kvarot/michel/internal/audit"
)

// AuditError says the decision was stored but its audit events could not be
// written. Its message is the one of the audit failure.
type AuditError struct{ Err error }

func (e *AuditError) Error() string { return e.Err.Error() }
func (e *AuditError) Unwrap() error { return e.Err }

// Apply is what the CLI and the local API both do to decide on a finding:
// it stores d with Set (d is validated there), then writes the audit events
// with actor: decision.superseded (reason redecided) for the decision it
// replaces, then decision.set. pkg and osvID name the finding in the
// evidence. It returns the stored decision, the one it replaced (nil if
// none) and the decision.set event id. Set's errors (ErrFindingNotFound,
// ErrFindingGone, validation errors) come back as they are; an audit failure
// after the decision was stored comes back as an *AuditError, with the
// stored decision.
func Apply(ctx context.Context, repo *Repo, log *audit.Logger, actor string, d Decision, pkg, osvID string, now time.Time) (Decision, *Decision, string, error) {
	prev, hadPrev, err := repo.Current(ctx, d.FindingID)
	if err != nil {
		return Decision{}, nil, "", err
	}
	stored, err := repo.Set(ctx, d, now)
	if err != nil {
		return Decision{}, nil, "", err
	}
	var replaced *Decision
	if hadPrev {
		replaced = &prev
		if _, err := RecordSuperseded(ctx, log, actor, prev, Redecided); err != nil {
			return stored, replaced, "", &AuditError{err}
		}
	}
	ev, err := RecordSet(ctx, log, actor, stored, pkg, osvID)
	if err != nil {
		return stored, replaced, "", &AuditError{err}
	}
	return stored, replaced, ev.ID, nil
}
