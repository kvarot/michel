package gitrepo

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sourceupdate"
	"github.com/kvarot/michel/internal/store"
)

// fakeAPI answers the three status requests and the search, and records
// each request with its Authorization header.
type fakeAPI struct {
	mu    sync.Mutex
	paths []string
	auth  []string
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.RequestURI())
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		f.mu.Unlock()
		switch r.URL.Path {
		case "/repos/example/skill":
			w.Write([]byte(`{"stargazers_count": 42, "pushed_at": "2026-10-20T10:00:00Z", "archived": false, "default_branch": "main"}`))
		case "/repos/example/skill/commits/main":
			w.Write([]byte(`{"sha": "` + shaB + `"}`))
		case "/repos/example/skill/releases/latest":
			http.NotFound(w, r)
		case "/search/repositories":
			w.Write([]byte(`{"items": [
				{"full_name": "example/skill", "stargazers_count": 42, "description": "known", "html_url": "https://github.com/example/skill"},
				{"full_name": "example/mcp", "stargazers_count": 7, "description": "an MCP server\u001b[2J", "html_url": "https://github.com/example/mcp"}]}`))
		case "/moved":
			http.Redirect(w, r, "/repos/example/skill", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(SetBaseURLsForTest(srv.URL, srv.URL))
	return f
}

func (f *fakeAPI) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func TestStatusUsesThreeRequestsAndBudget(t *testing.T) {
	api := newFakeAPI(t)
	client := testClient(policy.PurposeRepo)
	b := &sourceupdate.Budget{Remaining: 3}
	st, err := Status(context.Background(), client, "tok", "example", "skill", b)
	if err != nil {
		t.Fatal(err)
	}
	if got := api.requests(); len(got) != 3 || !strings.HasSuffix(got[2], "/releases/latest") {
		t.Errorf("requests = %v", got)
	}
	if b.Remaining != 0 {
		t.Errorf("budget left = %d", b.Remaining)
	}
	if st.Stars != 42 || st.HeadSHA != shaB || st.DefaultBranch != "main" || st.LatestRelease != "" || st.PushedAt != "2026-10-20T10:00:00Z" || st.CheckedAt == "" {
		t.Errorf("status = %+v", st)
	}
	for _, a := range api.auth {
		if a != "Bearer tok" {
			t.Errorf("authorization = %q", a)
		}
	}
	b = &sourceupdate.Budget{Remaining: 2}
	before := len(api.requests())
	if _, err := Status(context.Background(), client, "", "example", "skill", b); !errors.Is(err, ErrBudget) {
		t.Fatalf("budget 2: err = %v", err)
	}
	for _, p := range api.requests()[before:] {
		if strings.HasSuffix(p, "/releases/latest") {
			t.Error("the third request went out")
		}
	}
	if _, err := Status(context.Background(), client, "", "example/../x", "skill", nil); err == nil {
		t.Error("a bad owner was accepted")
	}
}

func TestStatusFlagsNewVersion(t *testing.T) {
	newFakeAPI(t)
	st, err := Status(context.Background(), testClient(policy.PurposeRepo), "", "example", "skill", nil)
	if err != nil {
		t.Fatal(err)
	}
	m := StatusMap(st, shaA)
	nv, ok := m["new_version"].(map[string]any)
	if !ok || nv["from"] != shaA || nv["to"] != shaB || m["head_sha"] != shaB {
		t.Errorf("status map = %v", m)
	}
	e := source.Entry{Status: m}
	if from, to, ok := e.NewVersion(); !ok || from != shaA || to != shaB {
		t.Errorf("entry new version = %s %s %v", from, to, ok)
	}
	if m := StatusMap(st, shaB); m["new_version"] != nil || m["new_version_available"] != false {
		t.Errorf("same sha flagged: %v", m)
	}
	if m := StatusMap(st, ""); m["new_version"] != nil {
		t.Errorf("nothing pinned (plugin) flagged: %v", m)
	}
}

func TestDiscoverSkipsKnownRepos(t *testing.T) {
	api := newFakeAPI(t)
	found, err := Discover(context.Background(), testClient(policy.PurposeDiscover), "", []string{"mcp-security", "bad topic!"}, &sourceupdate.Budget{Remaining: 5})
	if err != nil {
		t.Fatal(err)
	}
	if got := api.requests(); len(got) != 1 || !strings.Contains(got[0], "q=topic%3Amcp-security") || !strings.Contains(got[0], "per_page=20") {
		t.Errorf("requests = %v", got)
	}
	if len(found) != 2 || strings.ContainsRune(found[1].Description, '\x1b') {
		t.Fatalf("found = %+v", found)
	}
	s, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dr := NewDiscoveryRepo(s)
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	n, err := dr.Save(context.Background(), found, map[string]bool{"example/skill": true}, now)
	if err != nil || n != 1 {
		t.Fatalf("save: %d %v", n, err)
	}
	if n, err := dr.Save(context.Background(), found, map[string]bool{"example/skill": true}, now); err != nil || n != 0 {
		t.Errorf("second save: %d %v", n, err)
	}
	list, err := dr.List(context.Background(), "new")
	if err != nil || len(list) != 1 || list[0].Repo != "example/mcp" || list[0].Topic != "mcp-security" || list[0].FirstSeenAt != "2026-10-28T00:00:00Z" {
		t.Fatalf("list = %+v %v", list, err)
	}
	if err := dr.SetState(context.Background(), "example/mcp", "ignored"); err != nil {
		t.Fatal(err)
	}
	if list, _ := dr.List(context.Background(), "new"); len(list) != 0 {
		t.Errorf("ignored still new: %+v", list)
	}
	if err := dr.SetState(context.Background(), "example/none", "ignored"); !errors.Is(err, ErrUnknownDiscovery) {
		t.Errorf("unknown repo: %v", err)
	}
	if _, err := Discover(context.Background(), testClient(policy.PurposeDiscover), "", []string{"a", "b"}, &sourceupdate.Budget{Remaining: 1}); !errors.Is(err, ErrBudget) {
		t.Errorf("budget: %v", err)
	}
}

func TestStatusDoesNotFollowRedirects(t *testing.T) {
	newFakeAPI(t)
	_, err := getJSON(context.Background(), testClient(policy.PurposeRepo), apiBase+"/moved", "tok", nil)
	if err == nil {
		t.Error("a redirect was followed")
	}
}
