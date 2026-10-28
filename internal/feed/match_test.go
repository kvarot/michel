package feed

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/source"
)

func TestMatchTechWholeWordFold(t *testing.T) {
	cases := []struct {
		title     string
		entryTech []string
		declared  []string
		matched   []string
		toRead    bool
	}{
		{"Nginx 1.27 fixes a bug", nil, []string{"nginx"}, []string{"nginx"}, true},
		{"enginx is not nginx-like", nil, []string{"nginx"}, []string{"nginx"}, true},
		{"enginx 1.0", nil, []string{"nginx"}, nil, false},
		{"NGINXs", nil, []string{"nginx"}, nil, false},
		{"(Node.js) security release", nil, []string{"node.js", "node"}, []string{"node", "node.js"}, true},
		{"Release of something", []string{"symfony"}, []string{"symfony", "php"}, nil, true},
		{"Release of something", []string{"drupal"}, []string{"symfony"}, nil, false},
		{"Symfony and PHP", []string{"drupal"}, nil, nil, false},
		{"Écran PHP", nil, []string{"php"}, []string{"php"}, true},
	}
	for _, c := range cases {
		m, ok := MatchTech(c.title, c.entryTech, c.declared)
		if !reflect.DeepEqual(m, c.matched) || ok != c.toRead {
			t.Errorf("MatchTech(%q, %v, %v) = %v %v, want %v %v", c.title, c.entryTech, c.declared, m, ok, c.matched, c.toRead)
		}
	}
}

func TestListToReadAndMarkRead(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	nginx := e.entry(t, "feed.nginx-like", "http://127.0.0.1/", "rss", "nginx")
	misc := e.entry(t, "feed.misc", "http://127.0.0.1/", "rss")
	r := NewRepo(e.st)
	day := func(d int) string { return now.Add(-time.Duration(d) * 24 * time.Hour).Format(time.RFC3339) }
	n, err := r.Insert(ctx, []Item{
		{SourceID: nginx.ID, GUID: "a", Title: "release", PublishedAt: day(1), Tech: []string{"nginx"}, SeenAt: day(0)},
		{SourceID: misc.ID, GUID: "b", Title: "PHP 8.4.1 is out", PublishedAt: day(2), SeenAt: day(0)},
		{SourceID: misc.ID, GUID: "c", Title: "unrelated", PublishedAt: day(3), SeenAt: day(0)},
		{SourceID: misc.ID, GUID: "d", Title: "old php", PublishedAt: day(20), SeenAt: day(0)},
		{SourceID: misc.ID, GUID: "e", Title: "php, no date", SeenAt: now.Add(-36 * time.Hour).Format(time.RFC3339)},
	})
	if err != nil || n != 5 {
		t.Fatalf("insert: %d %v", n, err)
	}
	if n, err := r.Insert(ctx, []Item{{SourceID: misc.ID, GUID: "b", Title: "again", SeenAt: day(0)}}); err != nil || n != 0 {
		t.Fatalf("duplicate insert: %d %v", n, err)
	}
	guids := func(items []Item) []string {
		out := []string{}
		for _, it := range items {
			out = append(out, it.GUID)
		}
		return out
	}
	got, err := r.ListToRead(ctx, now.Add(-7*24*time.Hour), false, []string{"nginx", "php"})
	if err != nil || !reflect.DeepEqual(guids(got), []string{"a", "e", "b"}) {
		t.Fatalf("to read = %v err %v", guids(got), err)
	}
	if got[0].SourceKey != "feed.nginx-like" || got[0].SourceName != "Example feed.nginx-like" {
		t.Errorf("source of a = %q %q", got[0].SourceKey, got[0].SourceName)
	}
	if got, _ := r.ListToRead(ctx, time.Time{}, false, nil); len(got) != 0 {
		t.Errorf("nothing declared: %v", guids(got))
	}
	if err := r.MarkRead(ctx, got[0].ID, now); err != nil {
		t.Fatal(err)
	}
	if err := r.MarkRead(ctx, got[0].ID, now); err != nil {
		t.Errorf("marking twice: %v", err)
	}
	if err := r.MarkRead(ctx, "nope", now); err != ErrItemNotFound {
		t.Errorf("unknown item: %v", err)
	}
	got, _ = r.ListToRead(ctx, time.Time{}, true, []string{"nginx", "php"})
	if !reflect.DeepEqual(guids(got), []string{"e", "b", "d"}) {
		t.Errorf("unread = %v", guids(got))
	}
	n, err = r.MarkAllRead(ctx, now)
	if err != nil || n != 4 {
		t.Errorf("mark all: %d %v", n, err)
	}
	if got, _ := r.List(ctx, time.Time{}, true); len(got) != 0 {
		t.Errorf("unread after mark all: %v", guids(got))
	}
}

func TestDeclaredAll(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	pr := project.NewRepo(e.st)
	p, err := pr.Add(ctx, project.Project{Name: "demo", Path: t.TempDir(), Tech: []string{"nginx"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := pr.UpdateTechAuto(ctx, p.ID, []string{"php", "symfony"}); err != nil {
		t.Fatal(err)
	}
	off, err := pr.Add(ctx, project.Project{Name: "demo-off", Path: t.TempDir(), Tech: []string{"redis"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pr.Remove(ctx, off.ID); err != nil {
		t.Fatal(err)
	}
	if err := source.AddTech(ctx, e.st, "postgresql"); err != nil {
		t.Fatal(err)
	}
	got, err := DeclaredAll(ctx, e.st)
	if err != nil || !reflect.DeepEqual(got, []string{"nginx", "php", "postgresql", "symfony"}) {
		t.Errorf("declared = %v err %v", got, err)
	}
}
