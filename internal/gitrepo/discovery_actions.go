package gitrepo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

// ErrBadDiscoveryKind means a discovery is added with a kind other than
// skill or mcp.
var ErrBadDiscoveryKind = errors.New("a discovery becomes a skill or an mcp source")

// DiscoveryActions is what the CLI and the page share to act on a discovery: the
// store, the audit log and the actor of the audit events.
type DiscoveryActions struct {
	Store *store.Store
	Audit *audit.Logger
	Actor string
}

// Resolve returns the discovery's repository as listed (the match ignores
// case); ErrUnknownDiscovery when it is not listed.
func (d DiscoveryActions) Resolve(ctx context.Context, repo string) (string, error) {
	found, err := NewDiscoveryRepo(d.Store).List(ctx, "")
	if err != nil {
		return "", err
	}
	for _, f := range found {
		if strings.EqualFold(f.Repo, repo) {
			return f.Repo, nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrUnknownDiscovery, repo)
}

// Ignore hides a listed repository (case-insensitive match) and audits
// source.discover. It returns the repository as listed. Errors:
// ErrUnknownDiscovery, source.ErrAuditFailed (the state is changed).
func (d DiscoveryActions) Ignore(ctx context.Context, repo string) (string, error) {
	repo, err := d.Resolve(ctx, repo)
	if err != nil {
		return "", err
	}
	if err := NewDiscoveryRepo(d.Store).SetState(ctx, repo, StateIgnored); err != nil {
		return "", err
	}
	if _, err := d.Audit.Record(ctx, audit.Event{Actor: d.Actor, Action: "source.discover", Target: repo, Result: "ok",
		Evidence: map[string]any{"repo": repo, "state": StateIgnored}}); err != nil {
		return repo, auditFailed(err)
	}
	return repo, nil
}

// Add makes a listed repository (case-insensitive match) a skill or mcp
// source of the user, marks the discovery added and audits source.add with
// from=discover. Errors: ErrUnknownDiscovery, ErrBadDiscoveryKind, a
// *source.Refusal, and the errors of source.AddUserEntry.
func (d DiscoveryActions) Add(ctx context.Context, repo string, req source.UserEntryRequest) (source.Entry, error) {
	repo, err := d.Resolve(ctx, repo)
	if err != nil {
		return source.Entry{}, err
	}
	if req.Kind != source.KindSkill && req.Kind != source.KindMCP {
		return source.Entry{}, ErrBadDiscoveryKind
	}
	req.Repo = repo
	e, refusal := source.NewUserEntry(req)
	if refusal != nil {
		return source.Entry{}, refusal
	}
	return source.AddUserEntry(ctx, d.Store, d.Audit, d.Actor, e, "discover", func() error {
		return NewDiscoveryRepo(d.Store).SetState(ctx, repo, StateAdded)
	})
}

// auditFailed is source.ErrAuditFailed with err's text.
func auditFailed(err error) error { return errors.Join(source.ErrAuditFailed, err) }
