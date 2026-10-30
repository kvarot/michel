package feed

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

var now = time.Date(2026, 10, 28, 7, 0, 0, 0, time.UTC)

// bom is the UTF-8 byte order mark some servers put before the XML.
const bom = "\xef\xbb\xbf"

type env struct {
	deps Deps
	repo *source.Repo
	st   *store.Store
}

func newEnv(t *testing.T) env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var p policy.Policy
	p.Sovereignty.Network.Allow = []policy.AllowRule{{Host: "127.0.0.1", Purpose: policy.PurposeFeed}}
	gw := egress.New(p, nil)
	return env{deps: Deps{Store: st, Client: gw.Client(policy.PurposeFeed), Now: func() time.Time { return now }}, repo: source.NewRepo(st), st: st}
}

// entry stores a user feed entry reading url with format.
func (e env) entry(t *testing.T, key, url, format string, tech ...string) source.Entry {
	t.Helper()
	cfg := map[string]any{"format": format}
	en, err := e.repo.Upsert(context.Background(), source.Entry{Key: key, Kind: source.KindFeed, Origin: source.OriginUser, Name: "Example " + key,
		URL: url, Hosts: []string{"127.0.0.1"}, Purpose: policy.PurposeFeed, Enabled: true, Tech: tech,
		Config: source.Config{User: cfg}})
	if err != nil {
		t.Fatal(err)
	}
	return en
}

func (e env) count(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM feed_item`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e env) items(t *testing.T) []Item {
	t.Helper()
	items, err := NewRepo(e.st).List(context.Background(), time.Time{}, false)
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func serve(t *testing.T, ct string, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ct)
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDetectRSSAndAtom(t *testing.T) {
	cases := []struct {
		name, ct string
		body     string
		want     string
	}{
		{"rss", "application/rss+xml", string(fixture(t, "rss.xml")), "rss"},
		{"atom", "application/atom+xml", string(fixture(t, "atom.xml")), "atom"},
		{"rss served as html", "text/html", bom + "  <?xml version=\"1.0\"?>\n<!DOCTYPE rss>\n<!-- c --><rss><channel/></rss>", "rss"},
		{"latin-1 atom", "text/xml", "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><feed xmlns=\"http://www.w3.org/2005/Atom\"><title>caf\xe9</title></feed>", "atom"},
		{"html page", "text/html", "<!DOCTYPE html><html><body><p>hello</body></html>", ""},
		{"json", "application/json", `{"a": 1}`, ""},
		{"empty", "", "", ""},
	}
	for _, c := range cases {
		if got := Detect(c.ct, []byte(c.body)); got != c.want {
			t.Errorf("%s: Detect = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRSSReaderCapsAndSanitizes(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	// A body over MaxFeedBytes is refused, nothing is written.
	big := serve(t, "application/rss+xml", []byte("<rss><channel>"+strings.Repeat("x", 6<<20)+"</channel></rss>"))
	en := e.entry(t, "feed.big", big.URL, "rss")
	if _, _, err := ReadEntry(ctx, e.deps, en, nil); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("6 MB body: err = %v", err)
	}
	if n := e.count(t); n != 0 {
		t.Fatalf("items after a refused body = %d", n)
	}

	// 5,000 items in about 1 MB: only the first MaxItemsPerRead are kept.
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>`)
	b.WriteString("<item><guid>g0</guid><title><![CDATA[<b>x\x00</b>]]></title><link>https://example.org/0</link></item>")
	for i := 1; i < 5000; i++ {
		fmt.Fprintf(&b, "<item><guid>g%d</guid><title>Item %d</title><link>https://example.org/%d</link><description>%s</description></item>", i, i, i, strings.Repeat("d", 100))
	}
	b.WriteString("</channel></rss>")
	if b.Len() < 500<<10 || b.Len() > 2<<20 {
		t.Fatalf("body is %d bytes", b.Len())
	}
	many := serve(t, "application/rss+xml", []byte(b.String()))
	en = e.entry(t, "feed.many", many.URL, "rss")
	n, _, err := ReadEntry(ctx, e.deps, en, nil)
	if err != nil || n != MaxItemsPerRead {
		t.Fatalf("5,000 items: n = %d err = %v", n, err)
	}
	if c := e.count(t); c != MaxItemsPerRead {
		t.Fatalf("stored = %d", c)
	}
	var title string
	if err := e.st.DB().QueryRow(`SELECT title FROM feed_item WHERE guid = 'g0'`).Scan(&title); err != nil || title != "x" {
		t.Errorf("title of g0 = %q err %v", title, err)
	}

	// The fixture: HTML stripped, entities decoded, bad link dropped.
	items, err := RSS{}.Parse(fixture(t, "rss.xml"), en)
	if err != nil || len(items) != 3 {
		t.Fatalf("rss fixture: %d items, err %v", len(items), err)
	}
	if items[0].GUID != "example-1" || items[0].Title != "Nginx 1.27.3 fixes a buffer overflow" || items[0].URL != "https://example.org/news/1" ||
		items[0].PublishedAt != "2026-10-26T10:00:00Z" || items[0].Summary != "A fix & more" {
		t.Errorf("item 0 = %+v", items[0])
	}
	if items[1].GUID != "https://example.org/news/2" || items[1].PublishedAt != "2026-10-25T07:00:00Z" {
		t.Errorf("item 1 = %+v", items[1])
	}
	if items[2].URL != "" || !strings.HasPrefix(items[2].GUID, "title:") {
		t.Errorf("item 2 = %+v", items[2])
	}
	long := `<rss><channel><item><title>t</title><description>` + strings.Repeat("é", 2000) + `</description></item></channel></rss>`
	items, err = RSS{}.Parse([]byte(long), en)
	if err != nil || len([]rune(items[0].Summary)) != MaxSummary {
		t.Errorf("summary runes = %d err %v", len([]rune(items[0].Summary)), err)
	}
}

func TestStripHTML(t *testing.T) {
	cases := map[string]string{
		"<b>x\x00</b>":                       "x",
		"a <script>var s = '<p>';</script>b": "a b",
		"<style>p{}</style>  c &amp;&nbsp;d": "c & d",
		"<!-- <b>no</b> -->e\n\n\tf":         "e f",
		"1 &lt; 2":                           "1 < 2",
		"\u009b31m red":                      "31m red",
	}
	for in, want := range cases {
		if got := StripHTML(in); got != want {
			t.Errorf("StripHTML(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAtomParses(t *testing.T) {
	en := source.Entry{Key: "feed.atom", URL: "https://example.org/feed.atom"}
	items, err := Atom{}.Parse(fixture(t, "atom.xml"), en)
	if err != nil || len(items) != 2 {
		t.Fatalf("%d items, err %v", len(items), err)
	}
	a, b := items[0], items[1]
	if a.GUID != "urn:example:releases:2" || a.Title != "Security release 2.4.1" || a.URL != "https://example.org/releases/2.4.1" ||
		a.PublishedAt != "2026-10-27T08:00:00Z" || a.Summary != "Fixes CVE-2026-0001." {
		t.Errorf("entry 0 = %+v", a)
	}
	if b.GUID != "https://example.org/releases/2.4.0" || b.Title != "Plain & simple" || b.PublishedAt != "2026-10-20T07:00:00Z" || b.Summary != "bold" {
		t.Errorf("entry 1 = %+v", b)
	}
	if _, err := (Atom{}).Parse([]byte("<feed><entry>"), en); err == nil {
		t.Error("truncated atom: no error")
	}
	// An external entity is never fetched nor expanded.
	xxe := `<?xml version="1.0"?><!DOCTYPE feed [<!ENTITY x SYSTEM "file:///etc/passwd">]><feed><entry><title>&x;</title></entry></feed>`
	if items, err := (Atom{}).Parse([]byte(xxe), en); err == nil && len(items) > 0 && items[0].Title != "" {
		t.Errorf("external entity expanded: %+v", items)
	}
}

func TestGitHubAdvisoriesParsesAndSendsToken(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	var got []*http.Request
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Clone(context.Background()))
		if status != http.StatusOK {
			w.WriteHeader(status)
			fmt.Fprint(w, "token tok-123 rejected")
			return
		}
		w.Header().Set("ETag", `"gh1"`)
		w.Write(fixture(t, "advisories.json"))
	}))
	defer srv.Close()
	defer SetGitHubAPIForTest(srv.URL)()
	secrets, err := secret.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.Set("github-token", []byte("tok-123\n")); err != nil {
		t.Fatal(err)
	}
	budget := 2
	e.deps.Secrets = secrets
	e.deps.TakeGitHub = func() bool {
		if budget == 0 {
			return false
		}
		budget--
		return true
	}
	en, err := e.repo.Upsert(ctx, source.Entry{Key: "feed.lib", Kind: source.KindFeed, Origin: source.OriginUser, Name: "Example lib",
		Hosts: []string{"api.github.com"}, Purpose: policy.PurposeFeed, Enabled: true, Tech: []string{"node"},
		Config: source.Config{User: map[string]any{"format": "github_advisories", "repo": "example/lib"}}})
	if err != nil {
		t.Fatal(err)
	}
	n, etag, err := ReadEntry(ctx, e.deps, en, nil)
	if err != nil || n != 2 || etag != `"gh1"` {
		t.Fatalf("n = %d etag %q err %v", n, etag, err)
	}
	r := got[0]
	if r.URL.Path != "/repos/example/lib/security-advisories" || r.URL.Query().Get("state") != "published" || r.URL.Query().Get("per_page") != "50" {
		t.Errorf("request = %s", r.URL)
	}
	if r.Header.Get("Authorization") != "Bearer tok-123" || r.Header.Get("Accept") != "application/vnd.github+json" {
		t.Errorf("headers = %v", r.Header)
	}
	items := e.items(t)
	if len(items) != 2 {
		t.Fatalf("items = %+v", items)
	}
	a := items[0]
	if a.GUID != "GHSA-aaaa-bbbb-cccc" || a.Title != "Path traversal in the static handler" || a.PublishedAt != "2026-10-26T12:00:00Z" ||
		a.URL != "https://github.com/example/lib/security/advisories/GHSA-aaaa-bbbb-cccc" || !strings.Contains(a.Summary, "high") ||
		!strings.Contains(a.Summary, "vuln-pkg") || !reflect.DeepEqual(a.Tech, []string{"node"}) || a.SourceKey != "feed.lib" {
		t.Errorf("advisory = %+v", a)
	}

	// The token never reaches an error.
	status = http.StatusInternalServerError
	if _, _, err := ReadEntry(ctx, e.deps, en, nil); err == nil || strings.Contains(err.Error(), "tok-123") {
		t.Errorf("server error: %v", err)
	}
	// The budget is spent: no request at all.
	before := len(got)
	if _, _, err := ReadEntry(ctx, e.deps, en, nil); !errors.Is(err, ErrRateBudget) || len(got) != before {
		t.Errorf("no budget: err %v, %d requests", err, len(got)-before)
	}
	// A rate limit is reported as such.
	budget, status = 1, http.StatusForbidden
	if _, _, err := ReadEntry(ctx, e.deps, en, nil); !errors.Is(err, ErrRateLimited) {
		t.Errorf("403: %v", err)
	}
	// Without a token, no Authorization header.
	if err := secrets.Delete("github-token"); err != nil {
		t.Fatal(err)
	}
	budget, status = 1, http.StatusOK
	if _, _, err := ReadEntry(ctx, e.deps, en, nil); err != nil {
		t.Fatal(err)
	}
	if h := got[len(got)-1].Header.Get("Authorization"); h != "" {
		t.Errorf("Authorization without a token = %q", h)
	}
	// A bad repo setting is refused before any request.
	en.Config.User["repo"] = "../evil"
	budget = 1
	before = len(got)
	if _, _, err := ReadEntry(ctx, e.deps, en, nil); err == nil || len(got) != before {
		t.Errorf("bad repo: err %v", err)
	}
}

func TestPageChangeCreatesOneItemPerHash(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	body := "<html><body><h1>Advisories</h1><p>none</p><script>var nonce='1';</script></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	en := e.entry(t, "feed.page", srv.URL, "auto", "nginx")
	for i := 0; i < 2; i++ {
		if _, _, err := ReadEntry(ctx, e.deps, en, nil); err != nil {
			t.Fatal(err)
		}
	}
	body = "<html><body><h1>Advisories</h1><p>none</p><script>var nonce='2';</script></body></html>"
	if n, _, err := ReadEntry(ctx, e.deps, en, nil); err != nil || n != 0 {
		t.Fatalf("script change: n = %d err %v", n, err)
	}
	items := e.items(t)
	if len(items) != 1 || !strings.HasPrefix(items[0].GUID, "page:") || items[0].Title != PageChangedTitle || items[0].URL != srv.URL ||
		items[0].PublishedAt != "2026-10-28T07:00:00Z" {
		t.Fatalf("items = %+v", items)
	}
	body = "<html><body><h1>Advisories</h1><p>CVE-2026-0002 fixed</p></body></html>"
	if n, _, err := ReadEntry(ctx, e.deps, en, nil); err != nil || n != 1 {
		t.Fatalf("changed page: n = %d err %v", n, err)
	}
	if c := e.count(t); c != 2 {
		t.Errorf("items = %d", c)
	}
}

func TestReadEntryHonoursETag(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	var inm []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inm = append(inm, r.Header.Get("If-None-Match"))
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Type", "application/rss+xml")
		w.Write(fixture(t, "rss.xml"))
	}))
	defer srv.Close()
	en := e.entry(t, "feed.etag", srv.URL, "auto")
	n, etag, err := ReadEntry(ctx, e.deps, en, nil)
	if err != nil || n != 3 || etag != `"v1"` {
		t.Fatalf("first: n %d etag %q err %v", n, etag, err)
	}
	en.LastReadETag = etag
	if _, _, err := ReadEntry(ctx, e.deps, en, nil); !errors.Is(err, ErrNotModified) {
		t.Fatalf("second: %v", err)
	}
	if !reflect.DeepEqual(inm, []string{"", `"v1"`}) {
		t.Errorf("If-None-Match = %q", inm)
	}
	// Reading the same feed again adds nothing.
	en.LastReadETag = ""
	if n, _, err := ReadEntry(ctx, e.deps, en, nil); err != nil || n != 0 || e.count(t) != 3 {
		t.Errorf("third: n %d err %v count %d", n, err, e.count(t))
	}
}

func TestReadEntryPurgesOldItems(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	srv := serve(t, "application/rss+xml", fixture(t, "rss.xml"))
	en := e.entry(t, "feed.old", srv.URL, "rss")
	other := e.entry(t, "feed.other", srv.URL, "rss")
	old := now.Add(-Retention - 24*time.Hour).Format(time.RFC3339)
	for _, row := range [][2]string{{en.ID, "old"}, {other.ID, "kept-elsewhere"}} {
		if _, err := e.st.DB().Exec(`INSERT INTO feed_item (id, source_id, guid, title, published_at, seen_at) VALUES (?,?,?,?,?,?)`,
			row[1], row[0], row[1], "old news", old, old); err != nil {
			t.Fatal(err)
		}
	}
	// An item of the feed published before the retention is not stored.
	stale := `<rss><channel><item><guid>stale</guid><title>t</title><pubDate>` + now.Add(-Retention-time.Hour).Format(time.RFC1123Z) + `</pubDate></item></channel></rss>`
	srv2 := serve(t, "application/rss+xml", []byte(stale))
	en2 := e.entry(t, "feed.stale", srv2.URL, "rss")
	if _, _, err := ReadEntry(ctx, e.deps, en, nil); err != nil {
		t.Fatal(err)
	}
	if n, _, err := ReadEntry(ctx, e.deps, en2, nil); err != nil || n != 0 {
		t.Fatalf("stale: n %d err %v", n, err)
	}
	var guids []string
	rows, err := e.st.DB().Query(`SELECT guid FROM feed_item ORDER BY guid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var g string
		rows.Scan(&g)
		guids = append(guids, g)
	}
	if len(guids) != 4 || guids[0] != "example-1" || !slicesContains(guids, "kept-elsewhere") || slicesContains(guids, "old") {
		t.Errorf("guids = %q", guids)
	}
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
