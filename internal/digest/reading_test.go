package digest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/feed"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	srcreg "github.com/kvarot/michel/internal/source"
)

func TestDigestReadingListsUnreadMatchingItems(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	repo := srcreg.NewRepo(f.st)
	add := func(key string, tech ...string) srcreg.Entry {
		e, err := repo.Upsert(ctx, srcreg.Entry{Key: key, Kind: srcreg.KindFeed, Origin: srcreg.OriginUser, Name: "Example " + key,
			URL: "https://example.org/" + key, Hosts: []string{"example.org"}, Purpose: policy.PurposeFeed, Enabled: true, Tech: tech})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	b := add("feed.b-news", "nginx")
	a := add("feed.a-news")
	if err := srcreg.AddTech(ctx, f.st, "nginx"); err != nil {
		t.Fatal(err)
	}
	at := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	var items []feed.Item
	for i := 0; i < 11; i++ {
		src := b
		if i%2 == 0 {
			src = a
		}
		items = append(items, feed.Item{SourceID: src.ID, GUID: fmt.Sprintf("g%02d", i), Title: fmt.Sprintf("nginx news %02d", i),
			URL: "https://example.org/" + fmt.Sprint(i), PublishedAt: at(time.Duration(i+1) * time.Minute), SeenAt: at(0)})
	}
	items = append(items,
		feed.Item{SourceID: a.ID, GUID: "read", Title: "nginx read", PublishedAt: at(time.Second), SeenAt: at(0), ReadAt: at(0)},
		feed.Item{SourceID: a.ID, GUID: "nomatch", Title: "something else", PublishedAt: at(time.Second), SeenAt: at(0)},
		feed.Item{SourceID: b.ID, GUID: "old", Title: "old", PublishedAt: at(48 * time.Hour), SeenAt: at(0)},
		feed.Item{SourceID: b.ID, GUID: "page:abc", Title: feed.PageChangedTitle, URL: "https://example.org/page", PublishedAt: at(30 * time.Second), SeenAt: at(0)},
	)
	if _, err := feed.NewRepo(f.st).Insert(ctx, items); err != nil {
		t.Fatal(err)
	}
	d := f.compute(i18n.EN, Options{})
	if len(d.Reading) != MaxReading {
		t.Fatalf("reading = %d items: %+v", len(d.Reading), d.Reading)
	}
	seen := map[string]bool{}
	for i, r := range d.Reading {
		seen[r.Title] = true
		if r.Title == "nginx read" || r.Title == "something else" || r.Title == "old" {
			t.Errorf("listed %q", r.Title)
		}
		if i > 0 && r.Source < d.Reading[i-1].Source {
			t.Errorf("not grouped by source: %q after %q", r.Source, d.Reading[i-1].Source)
		}
	}
	// The ten most recent: the page change (30 s) and news 00 to 08; 09 and 10 are left out.
	if !seen["The page changed"] || !seen["nginx news 08"] || seen["nginx news 09"] || seen["nginx news 10"] {
		t.Errorf("reading = %+v", d.Reading)
	}
	if d.Reading[0].Source != "Example feed.a-news" || d.Reading[0].Title != "nginx news 00" || d.Reading[0].URL != "https://example.org/0" {
		t.Errorf("first = %+v", d.Reading[0])
	}
	text, err := RenderText(d)
	if err != nil || !strings.Contains(text, "To read:") || !strings.Contains(text, "Example feed.a-news: nginx news 00") || !strings.Contains(text, "https://example.org/0") {
		t.Errorf("text:\n%s", text)
	}
	html, err := RenderHTML(d)
	if err != nil || !strings.Contains(html, "<h2>To read</h2>") || strings.Contains(html, `href="https://example.org`) {
		t.Errorf("html:\n%s", html)
	}
	fr := f.compute(i18n.FR, Options{})
	text, _ = RenderText(fr)
	if !strings.Contains(text, "À lire") || !strings.Contains(text, "La page a changé") {
		t.Errorf("fr text:\n%s", text)
	}
	// Exploited, the projects, then the reading.
	if strings.Index(text, "À lire") < strings.Index(text, "== demo ==") {
		t.Errorf("reading before the projects:\n%s", text)
	}
}
