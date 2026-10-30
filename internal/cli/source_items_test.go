package cli

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/feed"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

func TestSourceItemsAndRead(t *testing.T) {
	dir := t.TempDir()
	if _, out, _, err := run(t, dir, "source", "items"); err != nil || !strings.Contains(out, "declared no technology") {
		t.Fatalf("no tech: %q %v", out, err)
	}
	if _, _, _, err := run(t, dir, "tech", "add", "php"); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	nginx, err := source.NewRepo(s).Get(ctx, "feed.nginx")
	if err != nil {
		t.Fatal(err)
	}
	recent := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	old := time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := feed.NewRepo(s).Insert(ctx, []feed.Item{
		{SourceID: nginx.ID, GUID: "a", Title: "PHP-FPM behind nginx", URL: "https://example.org/a", PublishedAt: recent, SeenAt: recent},
		{SourceID: nginx.ID, GUID: "b", Title: "Old PHP news", URL: "https://example.org/b", PublishedAt: old, SeenAt: old},
		{SourceID: nginx.ID, GUID: "c", Title: "nginx only", URL: "https://example.org/c", PublishedAt: recent, SeenAt: recent},
		{SourceID: nginx.ID, GUID: "page:1", Title: feed.PageChangedTitle, URL: "https://example.org/p", PublishedAt: recent, SeenAt: recent, Tech: []string{"php"}},
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	_, out, _, err := run(t, dir, "source", "items")
	if err != nil || !strings.Contains(out, "PHP-FPM behind nginx") || !strings.Contains(out, "Old PHP news") || strings.Contains(out, "nginx only") ||
		!strings.Contains(out, "The page changed") || !strings.Contains(out, "https://example.org/a") {
		t.Fatalf("items:\n%s err %v", out, err)
	}
	_, out, _, err = run(t, dir, "source", "items", "--since", "7d", "--json")
	var items []feed.Item
	if err != nil || json.Unmarshal([]byte(out), &items) != nil || len(items) != 2 {
		t.Fatalf("json: %q err %v", out, err)
	}
	var id string
	for _, it := range items {
		if it.GUID == "a" {
			id = it.ID
		}
		if it.SourceKey != "feed.nginx" || it.ReadAt != "" {
			t.Errorf("item = %+v", it)
		}
	}
	// --tech replaces the declared technologies.
	if _, out, _, _ := run(t, dir, "source", "items", "--tech", "nginx"); !strings.Contains(out, "nginx only") {
		t.Errorf("--tech nginx:\n%s", out)
	}
	if _, _, _, err := run(t, dir, "source", "items", "--since", "soon"); err == nil || !strings.Contains(err.Error(), "soon") {
		t.Errorf("bad since: %v", err)
	}

	if _, out, _, err := run(t, dir, "source", "read", id); err != nil || !strings.Contains(out, id) {
		t.Fatalf("read: %q %v", out, err)
	}
	if _, out, _, _ := run(t, dir, "source", "items", "--unread"); strings.Contains(out, "PHP-FPM") || !strings.Contains(out, "Old PHP news") {
		t.Errorf("unread:\n%s", out)
	}
	if _, _, _, err := run(t, dir, "source", "read", "nope"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("unknown item: %v", err)
	}
	if _, _, _, err := run(t, dir, "source", "read"); err == nil {
		t.Error("read without id nor --all: no error")
	}
	if _, out, _, err := run(t, dir, "source", "read", "--all"); err != nil || !strings.Contains(out, "3 items") {
		t.Errorf("read --all: %q %v", out, err)
	}
	if _, out, _, _ := run(t, dir, "source", "items", "--unread"); !strings.Contains(out, "Nothing to read") {
		t.Errorf("after --all:\n%s", out)
	}
	_, out, _, err = run(t, dir, "--lang", "fr", "source", "items")
	if err != nil || !strings.Contains(out, "La page a changé") || !strings.Contains(out, "(lu)") {
		t.Errorf("fr:\n%s", out)
	}
	if ev := auditRows(t, dir, "source.item_read"); len(ev) != 2 || ev[1].evidence["count"] != float64(3) {
		t.Errorf("audit = %+v", ev)
	}
}
