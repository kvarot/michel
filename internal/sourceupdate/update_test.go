package sourceupdate

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/enrich"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

// fakeReader reads with fn and counts its calls.
type fakeReader struct {
	kinds []source.Kind
	fn    func(ctx context.Context, e source.Entry, deps Deps) (Result, error)
	mu    sync.Mutex
	calls []string
}

func (f *fakeReader) Kinds() []source.Kind { return f.kinds }

func (f *fakeReader) Read(ctx context.Context, e source.Entry, deps Deps) (Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, e.Key)
	f.mu.Unlock()
	return f.fn(ctx, e, deps)
}

// useReaders replaces the registry for the test.
func useReaders(t *testing.T, rs ...Reader) {
	t.Helper()
	regMu.Lock()
	old := registry
	registry = map[source.Kind]Reader{}
	regMu.Unlock()
	for _, r := range rs {
		Register(r)
	}
	t.Cleanup(func() {
		regMu.Lock()
		registry = old
		regMu.Unlock()
	})
}

type countingSink struct {
	mu       sync.Mutex
	attempts []egress.Attempt
}

func (s *countingSink) Record(a egress.Attempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts = append(s.attempts, a)
	return nil
}

var fixedNow = time.Date(2026, 10, 28, 6, 30, 0, 0, time.UTC)

// env is a store with the given user entries (all enabled) and a gateway
// allowing every host of rules for its purpose.
func env(t *testing.T, sink egress.Sink, rules []policy.AllowRule, entries ...source.Entry) Deps {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	repo := source.NewRepo(s)
	for _, e := range entries {
		e.Origin, e.Enabled = source.OriginUser, true
		if e.Name == "" {
			e.Name = e.Key
		}
		if _, err := repo.Upsert(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	var p policy.Policy
	p.Sovereignty.Network.Allow = rules
	return Deps{Store: s, Repo: repo, Audit: audit.NewLogger(s, func() time.Time { return fixedNow }),
		Gateway: egress.New(p, sink), Now: func() time.Time { return fixedNow }, Budget: &Budget{Remaining: 50}}
}

func feedEntry(key, host string) source.Entry {
	return source.Entry{Key: key, Kind: source.KindFeed, Hosts: []string{host}, Purpose: policy.PurposeFeed}
}

func skillEntry(key string) source.Entry {
	return source.Entry{Key: key, Kind: source.KindSkill, Hosts: []string{"api.github.com"}, Purpose: policy.PurposeRepo}
}

func auditCount(t *testing.T, d Deps, action string) int {
	t.Helper()
	var n int
	if err := d.Store.DB().QueryRow(`SELECT COUNT(*) FROM audit_event WHERE action = ?`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRunSkipsWaitingConsentWithoutNetwork(t *testing.T) {
	sink := &countingSink{}
	r := &fakeReader{kinds: []source.Kind{source.KindFeed}, fn: func(ctx context.Context, e source.Entry, deps Deps) (Result, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://feed.example.org/x", nil)
		resp, err := deps.Gateway.Client(policy.PurposeFeed).Do(req)
		if err == nil {
			resp.Body.Close()
		}
		return Result{}, err
	}}
	useReaders(t, r)
	d := env(t, sink, nil, feedEntry("feed.a", "feed.example.org"))
	rep, err := Run(context.Background(), d, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 0 || len(sink.attempts) != 0 {
		t.Fatalf("reader calls %v, attempts %v", r.calls, sink.attempts)
	}
	if !reflect.DeepEqual(rep.WaitingConsent, []string{"feed.a"}) || len(rep.Failed) != 0 || len(rep.Updated) != 0 {
		t.Errorf("report = %+v", rep)
	}
	e, _ := d.Repo.Get(context.Background(), "feed.a")
	if e.LastReadResult != "waiting_consent" {
		t.Errorf("last read result = %q", e.LastReadResult)
	}
}

func TestRunContinuesAfterOneFailure(t *testing.T) {
	r := &fakeReader{kinds: []source.Kind{source.KindFeed}, fn: func(ctx context.Context, e source.Entry, deps Deps) (Result, error) {
		if e.Key == "feed.a" {
			return Result{}, errors.New("the server answered 500 Internal Server Error")
		}
		return Result{Items: 3}, nil
	}}
	useReaders(t, r)
	rules := []policy.AllowRule{{Host: "a.example.org", Purpose: policy.PurposeFeed}, {Host: "b.example.org", Purpose: policy.PurposeFeed}}
	d := env(t, nil, rules, feedEntry("feed.a", "a.example.org"), feedEntry("feed.b", "b.example.org"))
	rep, err := Run(context.Background(), d, nil, "")
	if !errors.Is(err, ErrSomeFailed) {
		t.Fatalf("err = %v", err)
	}
	if !reflect.DeepEqual(rep.Failed, []string{"feed.a"}) || !reflect.DeepEqual(rep.Updated, []string{"feed.b"}) || rep.Items["feed.b"] != 3 {
		t.Errorf("report = %+v", rep)
	}
	if n := auditCount(t, d, "source.read"); n != 2 {
		t.Errorf("source.read events = %d", n)
	}
	e, _ := d.Repo.Get(context.Background(), "feed.a")
	if e.LastReadResult != "error" || e.LastReadError == "" {
		t.Errorf("failed entry = %q %q", e.LastReadResult, e.LastReadError)
	}
}

func TestRunRespectsGitHubBudget(t *testing.T) {
	r := &fakeReader{kinds: []source.Kind{source.KindSkill}, fn: func(ctx context.Context, e source.Entry, deps Deps) (Result, error) {
		deps.Budget.Take(1)
		return Result{Items: 1}, nil
	}}
	useReaders(t, r)
	rules := []policy.AllowRule{{Host: "api.github.com", Purpose: policy.PurposeRepo}}
	d := env(t, nil, rules, skillEntry("skill.a"), skillEntry("skill.b"), skillEntry("skill.c"))
	d.Budget = &Budget{Remaining: 2}
	rep, err := Run(context.Background(), d, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.calls, []string{"skill.a", "skill.b"}) || !reflect.DeepEqual(rep.Skipped, []string{"skill.c"}) ||
		rep.SkipReasons["skill.c"] != "rate budget" {
		t.Fatalf("calls %v, report %+v", r.calls, rep)
	}
	e, _ := d.Repo.Get(context.Background(), "skill.c")
	if e.LastReadResult != "skipped" || e.LastReadError != "rate budget" {
		t.Errorf("skipped entry = %q %q", e.LastReadResult, e.LastReadError)
	}
}

func TestRunRecordsReadOnEntry(t *testing.T) {
	r := &fakeReader{kinds: []source.Kind{source.KindFeed}, fn: func(ctx context.Context, e source.Entry, deps Deps) (Result, error) {
		if e.LastReadETag == `"v1"` {
			return Result{Skipped: SkipNotModified}, nil
		}
		return Result{Items: 1532, ETag: `"v1"`}, nil
	}}
	useReaders(t, r)
	rules := []policy.AllowRule{{Host: "a.example.org", Purpose: policy.PurposeFeed}}
	d := env(t, nil, rules, feedEntry("feed.a", "a.example.org"))
	if _, err := Run(context.Background(), d, nil, ""); err != nil {
		t.Fatal(err)
	}
	e, _ := d.Repo.Get(context.Background(), "feed.a")
	if !e.LastReadAt.Equal(fixedNow) || e.LastReadResult != "ok" || e.LastReadItems != 1532 || e.LastReadETag != `"v1"` || e.LastReadError != "" {
		t.Fatalf("entry = %v %q %d %q %q", e.LastReadAt, e.LastReadResult, e.LastReadItems, e.LastReadETag, e.LastReadError)
	}
	// The second read is answered 304: the entry stays current, its items
	// and etag are kept, and it is reported skipped, not failed.
	later := fixedNow.Add(24 * time.Hour)
	d.Now = func() time.Time { return later }
	rep, err := Run(context.Background(), d, []string{"feed.a"}, "")
	if err != nil || !reflect.DeepEqual(rep.Skipped, []string{"feed.a"}) || rep.SkipReasons["feed.a"] != SkipNotModified {
		t.Fatalf("second run: %v %+v", err, rep)
	}
	e, _ = d.Repo.Get(context.Background(), "feed.a")
	if !e.LastReadAt.Equal(later) || e.LastReadResult != "ok" || e.LastReadItems != 1532 || e.LastReadETag != `"v1"` {
		t.Errorf("entry after 304 = %v %q %d %q", e.LastReadAt, e.LastReadResult, e.LastReadItems, e.LastReadETag)
	}
}

func TestRunOrderAndUnknownKey(t *testing.T) {
	var order []string
	mk := func(k source.Kind) *fakeReader {
		return &fakeReader{kinds: []source.Kind{k}, fn: func(ctx context.Context, e source.Entry, deps Deps) (Result, error) {
			order = append(order, e.Key)
			return Result{}, nil
		}}
	}
	useReaders(t, mk(source.KindFeed), mk(source.KindSkill), mk(source.KindOSV))
	rules := []policy.AllowRule{{Host: "a.example.org", Purpose: policy.PurposeFeed}, {Host: "api.github.com", Purpose: policy.PurposeRepo},
		{Host: "osv.example.org", Purpose: policy.PurposeOSV}}
	osv := source.Entry{Key: "osv.zzz", Kind: source.KindOSV, Hosts: []string{"osv.example.org"}, Purpose: policy.PurposeOSV,
		Config: source.Config{User: map[string]any{"ecosystem": "Zzz"}}}
	d := env(t, nil, rules, skillEntry("skill.a"), feedEntry("feed.a", "a.example.org"), osv)
	if _, err := Run(context.Background(), d, nil, ""); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"osv.zzz", "feed.a", "skill.a"}) {
		t.Errorf("order = %v", order)
	}
	if _, err := Run(context.Background(), d, []string{"feed.nope"}, ""); !errors.Is(err, source.ErrNotFound) {
		t.Errorf("unknown key: %v", err)
	}
}

func TestRunKeepsAnOnDemandReadCutByTime(t *testing.T) {
	r := &fakeReader{kinds: []source.Kind{source.KindFeed}, fn: func(ctx context.Context, e source.Entry, deps Deps) (Result, error) {
		if e.Key == "feed.a" {
			return Result{Items: 42}, enrich.ErrOutOfTime
		}
		return Result{Items: 7, Skipped: SkipPartial}, nil
	}}
	useReaders(t, r)
	rules := []policy.AllowRule{{Host: "a.example.org", Purpose: policy.PurposeFeed}, {Host: "b.example.org", Purpose: policy.PurposeFeed}}
	d := env(t, nil, rules, feedEntry("feed.a", "a.example.org"), feedEntry("feed.b", "b.example.org"))
	rep, err := Run(context.Background(), d, nil, "")
	if err != nil {
		t.Fatalf("a read cut by time is not a failure: %v %+v", err, rep)
	}
	if !reflect.DeepEqual(rep.Skipped, []string{"feed.a", "feed.b"}) || rep.SkipReasons["feed.a"] != SkipPartial ||
		rep.SkipReasons["feed.b"] != SkipPartial || rep.Items["feed.a"] != 42 || rep.Items["feed.b"] != 7 || len(rep.Failed) != 0 {
		t.Fatalf("report = %+v", rep)
	}
	e, _ := d.Repo.Get(context.Background(), "feed.a")
	if e.LastReadResult != ResultSkipped || e.LastReadError != SkipPartial || e.LastReadItems != 42 {
		t.Errorf("entry = %q %q %d", e.LastReadResult, e.LastReadError, e.LastReadItems)
	}
}

func TestRunRematchesServersAfterAnOSVUpdate(t *testing.T) {
	skipped := false
	useReaders(t, &fakeReader{kinds: []source.Kind{source.KindOSV}, fn: func(ctx context.Context, e source.Entry, deps Deps) (Result, error) {
		if skipped {
			return Result{Skipped: SkipNotModified}, nil
		}
		return Result{Items: 3}, nil
	}}, &fakeReader{kinds: []source.Kind{source.KindFeed}, fn: func(ctx context.Context, e source.Entry, deps Deps) (Result, error) {
		return Result{Items: 1}, nil
	}})
	rules := []policy.AllowRule{{Host: "osv.example.org", Purpose: policy.PurposeOSV}, {Host: "a.example.org", Purpose: policy.PurposeFeed}}
	osv := source.Entry{Key: "osv.zzz", Kind: source.KindOSV, Hosts: []string{"osv.example.org"}, Purpose: policy.PurposeOSV,
		Config: source.Config{User: map[string]any{"ecosystem": "Zzz"}}}
	d := env(t, nil, rules, osv, feedEntry("feed.a", "a.example.org"))
	calls := 0
	d.Rematch = func(context.Context) (int, error) { calls++; return 2, nil }

	rep, err := Run(context.Background(), d, nil, "")
	if err != nil || calls != 1 || rep.Rematched != 2 {
		t.Fatalf("after an update: calls %d, report %+v, err %v", calls, rep, err)
	}
	// A feed alone, or a database the server reports unchanged, rematches nothing.
	if _, err := Run(context.Background(), d, []string{"feed.a"}, ""); err != nil || calls != 1 {
		t.Fatalf("feed only: calls %d, err %v", calls, err)
	}
	skipped = true
	if _, err := Run(context.Background(), d, nil, ""); err != nil || calls != 1 {
		t.Fatalf("not modified: calls %d, err %v", calls, err)
	}
	skipped = false
	d.Rematch = func(context.Context) (int, error) { return 0, errors.New("rematch broke") }
	rep, err = Run(context.Background(), d, nil, "")
	if !errors.Is(err, ErrSomeFailed) || rep.RematchError != "rematch broke" {
		t.Fatalf("a failed rematch: %+v, %v", rep, err)
	}
}
