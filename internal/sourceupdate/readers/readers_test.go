package readers

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/feed"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sourceupdate"
	"github.com/kvarot/michel/internal/store"
)

func deps(t *testing.T, rules ...policy.AllowRule) sourceupdate.Deps {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	repo := source.NewRepo(s)
	if _, _, err := source.Sync(context.Background(), repo); err != nil {
		t.Fatal(err)
	}
	var p policy.Policy
	p.Sovereignty.Network.Allow = rules
	return sourceupdate.Deps{Store: s, Repo: repo, Audit: audit.NewLogger(s, time.Now), Gateway: egress.New(p, nil),
		OSVRoot: filepath.Join(t.TempDir(), "osv"), Now: time.Now}
}

func TestOSVReaderDownloadsThenHonoursNotModified(t *testing.T) {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, n := range []string{"A-1.json", "A-2.json"} {
		f, _ := w.Create(n)
		f.Write([]byte("{}"))
	}
	w.Close()
	var sinces []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ims := r.Header.Get("If-Modified-Since")
		sinces = append(sinces, ims)
		if ims != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Write(b.Bytes())
	}))
	defer srv.Close()
	defer osvdb.SetBaseURLForTest(srv.URL)()
	d := deps(t, policy.AllowRule{Host: osvdb.Host, Purpose: policy.PurposeOSV}, policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeOSV})
	ctx := context.Background()
	rep, err := sourceupdate.Run(ctx, d, []string{"osv.npm"}, "")
	if err != nil || !reflect.DeepEqual(rep.Updated, []string{"osv.npm"}) || rep.Items["osv.npm"] != 2 {
		t.Fatalf("first run: %v %+v", err, rep)
	}
	rep, err = sourceupdate.Run(ctx, d, []string{"osv.npm"}, "")
	if err != nil || rep.SkipReasons["osv.npm"] != sourceupdate.SkipNotModified || len(rep.Failed) != 0 {
		t.Fatalf("second run: %v %+v", err, rep)
	}
	if len(sinces) != 2 || sinces[0] != "" || sinces[1] == "" {
		t.Errorf("If-Modified-Since headers = %q", sinces)
	}
	e, _ := d.Repo.Get(ctx, "osv.npm")
	if e.LastReadResult != "ok" || e.LastReadItems != 2 {
		t.Errorf("entry = %q %d", e.LastReadResult, e.LastReadItems)
	}
	if st, _ := osvdb.Statuses(d.OSVRoot, []string{"npm"}); !st[0].Present {
		t.Error("database removed by the 304")
	}
}

func TestEnrichReaderRefusesUnknownFormat(t *testing.T) {
	d := deps(t)
	e := source.Entry{Key: "enrich.mine", Kind: source.KindEnrichment, Config: source.Config{User: map[string]any{"format": "nope"}}}
	if _, err := (enrichReader{}).Read(context.Background(), e, d); err == nil || !strings.Contains(err.Error(), "unknown enrichment format") {
		t.Errorf("err = %v", err)
	}
}

func TestFeedReaderReadsThenHonoursNotModified(t *testing.T) {
	rss := `<?xml version="1.0"?><rss version="2.0"><channel><item><guid>a</guid><title>nginx 1.27 security fix</title><link>https://example.org/a</link></item>` +
		`<item><guid>b</guid><title>other</title></item></channel></rss>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"x"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"x"`)
		w.Write([]byte(rss))
	}))
	defer srv.Close()
	d := deps(t, policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeFeed})
	ctx := context.Background()
	if _, err := d.Repo.Upsert(ctx, source.Entry{Key: "feed.example", Kind: source.KindFeed, Origin: source.OriginUser, Name: "Example",
		URL: srv.URL, Hosts: []string{"127.0.0.1"}, Purpose: policy.PurposeFeed, Enabled: true,
		Config: source.Config{User: map[string]any{"format": "auto"}}}); err != nil {
		t.Fatal(err)
	}
	if err := source.AddTech(ctx, d.Store, "nginx"); err != nil {
		t.Fatal(err)
	}
	rep, err := sourceupdate.Run(ctx, d, nil, source.KindFeed)
	if err != nil || !reflect.DeepEqual(rep.Updated, []string{"feed.example"}) || rep.Items["feed.example"] != 2 {
		t.Fatalf("first run: %v %+v", err, rep)
	}
	var tech string
	if err := d.Store.DB().QueryRow(`SELECT tech FROM feed_item WHERE guid = 'a'`).Scan(&tech); err != nil || tech != `["nginx"]` {
		t.Errorf("tech of a = %q err %v", tech, err)
	}
	rep, err = sourceupdate.Run(ctx, d, []string{"feed.example"}, "")
	if err != nil || rep.SkipReasons["feed.example"] != sourceupdate.SkipNotModified {
		t.Fatalf("second run: %v %+v", err, rep)
	}
	e, _ := d.Repo.Get(ctx, "feed.example")
	if e.LastReadResult != "ok" || e.LastReadItems != 2 || e.LastReadETag != `"x"` {
		t.Errorf("entry = %q %d %q", e.LastReadResult, e.LastReadItems, e.LastReadETag)
	}
}

func TestUpdatePurgesOldItemsOfSourcesNotRead(t *testing.T) {
	d := deps(t)
	ctx := context.Background()
	nginx, err := d.Repo.Get(ctx, "feed.nginx")
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-feed.Retention - time.Hour).UTC().Format(time.RFC3339)
	recent := time.Now().UTC().Format(time.RFC3339)
	if _, err := feed.NewRepo(d.Store).Insert(ctx, []feed.Item{
		{SourceID: nginx.ID, GUID: "old", Title: "t", SeenAt: old},
		{SourceID: nginx.ID, GUID: "recent", Title: "t", SeenAt: recent},
	}); err != nil {
		t.Fatal(err)
	}
	// A run that reads no feed at all still purges.
	if _, err := sourceupdate.Run(ctx, d, nil, source.KindReference); err != nil {
		t.Fatal(err)
	}
	var guids []string
	rows, err := d.Store.DB().Query(`SELECT guid FROM feed_item`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var g string
		rows.Scan(&g)
		guids = append(guids, g)
	}
	if !reflect.DeepEqual(guids, []string{"recent"}) {
		t.Errorf("left = %q", guids)
	}
}
