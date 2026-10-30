package readers

import (
	"context"
	"errors"

	"github.com/kvarot/michel/internal/feed"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sourceupdate"
)

func init() { sourceupdate.Register(feedReader{}) }

// feedReader reads a feed entry (RSS, Atom, GitHub advisories, watched page)
// into feed_item. The GitHub advisories spend the update's GitHub budget.
type feedReader struct{}

func (feedReader) Kinds() []source.Kind { return []source.Kind{source.KindFeed} }

func (feedReader) Read(ctx context.Context, e source.Entry, deps sourceupdate.Deps) (sourceupdate.Result, error) {
	declared, err := feed.DeclaredAll(ctx, deps.Store)
	if err != nil {
		return sourceupdate.Result{}, err
	}
	fd := feed.Deps{Store: deps.Store, Client: deps.Gateway.Client(policy.PurposeFeed), Secrets: deps.Secrets, Now: deps.Now,
		TakeGitHub: func() bool { return deps.Budget.Take(1) }}
	n, etag, err := feed.ReadEntry(ctx, fd, e, declared)
	switch {
	case errors.Is(err, feed.ErrNotModified):
		return sourceupdate.Result{Skipped: sourceupdate.SkipNotModified}, nil
	case errors.Is(err, feed.ErrRateBudget):
		return sourceupdate.Result{Skipped: sourceupdate.SkipRateBudget}, nil
	case errors.Is(err, feed.ErrRateLimited):
		return sourceupdate.Result{Skipped: sourceupdate.SkipRateLimited}, nil
	case err != nil:
		return sourceupdate.Result{}, err
	}
	return sourceupdate.Result{Items: n, ETag: etag}, nil
}
