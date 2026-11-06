package source

import (
	"context"
	"errors"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/store"
)

var (
	// ErrExists means a source with the entry's key is already registered.
	ErrExists = errors.New("this source already exists")
	// ErrRead means the registry could not be read to look for the key.
	ErrRead = errors.New("cannot read the sources")
	// ErrInvalid means the store refused the entry (the cause follows).
	ErrInvalid = errors.New("the source is not valid")
	// ErrAuditFailed means the source is stored but its audit event is not.
	ErrAuditFailed = errors.New("cannot record the source in the audit log")
)

// addError is a failure of AddUserEntry: it matches its kind with errors.Is
// and keeps the cause's own text.
type addError struct{ kind, cause error }

func (e addError) Error() string        { return e.cause.Error() }
func (e addError) Unwrap() error        { return e.cause }
func (e addError) Is(target error) bool { return target == e.kind }

// AddUserEntry stores a new entry of the user (made by NewUserEntry), runs
// after (nil for nothing; a discovery marks itself added) and audits
// source.add by actor. from says where it comes from ("discover", or "" for
// the form and the command line). Errors: ErrExists, ErrRead, ErrInvalid and
// ErrAuditFailed (each keeps its cause's text; the returned entry carries the key), or after's own error.
func AddUserEntry(ctx context.Context, st *store.Store, log *audit.Logger, actor string, e Entry, from string, after func() error) (Entry, error) {
	repo := NewRepo(st)
	if _, err := repo.Get(ctx, e.Key); err == nil {
		return e, ErrExists
	} else if !errors.Is(err, ErrNotFound) {
		return e, addError{ErrRead, err}
	}
	added, err := repo.Upsert(ctx, e)
	if err != nil {
		return e, addError{ErrInvalid, err}
	}
	if after != nil {
		if err := after(); err != nil {
			return added, err
		}
	}
	ev := map[string]any{"key": added.Key, "kind": string(added.Kind)}
	if from != "" {
		ev["from"] = from
	}
	if _, err := log.Record(ctx, audit.Event{Actor: actor, Action: "source.add", Target: added.Key, Result: "ok", Evidence: ev}); err != nil {
		return added, addError{ErrAuditFailed, err}
	}
	return added, nil
}
