package digest

import (
	"context"
	"sort"
	"time"

	"github.com/kvarot/michel/internal/feed"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/store"
)

// readingOf lists the MaxReading most recent unread items published since
// since that meet a technology declared or detected (feed.DeclaredAll),
// grouped by source (sources by name, items newest first).
func readingOf(ctx context.Context, s *store.Store, since time.Time, lang i18n.Lang) ([]ReadingItem, error) {
	declared, err := feed.DeclaredAll(ctx, s)
	if err != nil {
		return nil, err
	}
	items, err := feed.NewRepo(s).ListToRead(ctx, since, true, declared)
	if err != nil {
		return nil, err
	}
	if len(items) > MaxReading {
		items = items[:MaxReading]
	}
	out := make([]ReadingItem, 0, len(items))
	for _, it := range items {
		date := it.PublishedAt
		if date == "" {
			date = it.SeenAt
		}
		out = append(out, ReadingItem{ID: it.ID, Source: scan.SanitizeText(it.SourceName), Title: feed.Title(lang, it), URL: it.URL, PublishedAt: date, Tech: it.Tech})
	}
	// The list is newest first: a stable sort by source keeps that order
	// inside each source.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out, nil
}
