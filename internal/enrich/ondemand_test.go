package enrich

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/scan"
)

func fixtureFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVulnrichmentPathForCVE(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
		http.NotFound(w, r)
	}))
	defer srv.Close()
	defer SetBaseURLsForTest(srv.URL, "", "")()
	_, err := Vulnrichment().Fetch(context.Background(), srv.Client(), "CVE-2024-12345")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if got != "/2024/12xxx/CVE-2024-12345.json" {
		t.Errorf("path = %s", got)
	}
	_, _ = Vulnrichment().Fetch(context.Background(), srv.Client(), "CVE-2024-0001")
	if got != "/2024/0xxx/CVE-2024-0001.json" {
		t.Errorf("path = %s", got)
	}
}

func TestOnDemandRefusesMalformedCVE(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	defer SetBaseURLsForTest(srv.URL, srv.URL, srv.URL)()
	for _, src := range []OnDemand{Vulnrichment(), NVD(""), CIRCL()} {
		for _, bad := range []string{"CVE-2024-1/../../x", "../CVE-2024-0001", "CVE-24-1", "CVE-2024-0001?x=1", ""} {
			if _, err := src.Fetch(context.Background(), srv.Client(), bad); err == nil {
				t.Errorf("%s accepted %q", src.Key(), bad)
			}
		}
	}
	if hits.Load() != 0 {
		t.Error("a malformed id reached the network")
	}
}

func TestVulnrichmentParsesCVSSAndSSVC(t *testing.T) {
	body := fixtureFile(t, "vulnrichment-CVE-2024-0001.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()
	defer SetBaseURLsForTest(srv.URL, "", "")()
	r, err := Vulnrichment().Fetch(context.Background(), srv.Client(), "CVE-2024-0001")
	if err != nil {
		t.Fatal(err)
	}
	if r.CVE != "CVE-2024-0001" || r.CVSSScore != 8.1 || !strings.HasPrefix(r.CVSSVector, "CVSS:3.1/") ||
		r.SSVCExploitation != "poc" || r.SSVCAutomatable != "no" || r.SSVCTechnicalImpact != "partial" {
		t.Errorf("record = %+v", r)
	}
	if len(r.CWE) != 2 || r.CWE[0] != "CWE-79" || r.CWE[1] != "CWE-352" {
		t.Errorf("cwe = %v", r.CWE)
	}
}

func TestNVDParsesMetricsAndSendsAPIKeyHeader(t *testing.T) {
	body := fixtureFile(t, "nvd-CVE-2024-0001.json")
	var key, cve string
	var has bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, has = r.Header["Apikey"]
		key = r.Header.Get("apiKey")
		cve = r.URL.Query().Get("cveId")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	defer SetBaseURLsForTest("", srv.URL, "")()
	r, err := NVD("s3cret").Fetch(context.Background(), srv.Client(), "CVE-2024-0001")
	if err != nil {
		t.Fatal(err)
	}
	if !has || key != "s3cret" || cve != "CVE-2024-0001" {
		t.Errorf("header = %v %q, cveId = %q", has, key, cve)
	}
	if r.CVSSScore != 7.5 || !strings.HasPrefix(r.CVSSVector, "CVSS:3.1/") || len(r.CWE) != 1 || r.CWE[0] != "CWE-79" {
		t.Errorf("record = %+v", r)
	}
	if _, err := NVD("").Fetch(context.Background(), srv.Client(), "CVE-2024-0001"); err != nil {
		t.Fatal(err)
	}
	if has {
		t.Error("an empty key was sent")
	}
}

func TestNVDErrorsNeverCarryTheKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	defer SetBaseURLsForTest("", srv.URL, "")()
	_, err := NVD("s3cret").Fetch(context.Background(), srv.Client(), "CVE-2024-0001")
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("err = %v", err)
	}
}

func TestNVDEmptyResultIsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()
	defer SetBaseURLsForTest("", srv.URL, "")()
	if _, err := NVD("").Fetch(context.Background(), srv.Client(), "CVE-2024-0001"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestCIRCLParses(t *testing.T) {
	body := fixtureFile(t, "circl-CVE-2024-0001.json")
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.URL.Path; _, _ = w.Write(body) }))
	defer srv.Close()
	defer SetBaseURLsForTest("", "", srv.URL)()
	r, err := CIRCL().Fetch(context.Background(), srv.Client(), "CVE-2024-0001")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/CVE-2024-0001" || r.CVSSScore != 6.5 || len(r.CWE) != 1 || r.CWE[0] != "CWE-200" {
		t.Errorf("path %s record = %+v", got, r)
	}
}

func TestCandidatesOnlyUnknownSeverityWithoutRecord(t *testing.T) {
	f := newFixture(t)
	f.seedFinding(t, "f1", scan.StatusNew, "unknown", "CVE-2024-0001")
	f.seedFinding(t, "f2", scan.StatusNew, "unknown", "CVE-2024-0002")
	f.seedFinding(t, "f3", scan.StatusNew, "high", "CVE-2024-0003")
	f.seedFinding(t, "f4", scan.StatusGone, "unknown", "CVE-2024-0004")
	f.seedFinding(t, "f5", scan.StatusNew, "unknown", "CVE-2024-0005")
	f.seedFinding(t, "f6", scan.StatusNew, "unknown")
	if _, err := f.st.DB().Exec(`UPDATE finding SET last_seen_at = '2026-10-20T00:00:00Z' WHERE id = 'f5'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DB().Exec(`INSERT INTO cve_enrichment (cve, cvss_score, fetched_at, source_key) VALUES ('CVE-2024-0002', 5.0, '2026-10-25T00:00:00Z', 'enrich.nvd')`); err != nil {
		t.Fatal(err)
	}
	got, err := Candidates(context.Background(), f.st.DB(), "enrich.stub", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "CVE-2024-0005" || got[1] != "CVE-2024-0001" {
		t.Errorf("candidates = %v", got)
	}
	if got, _ := Candidates(context.Background(), f.st.DB(), "enrich.stub", 1); len(got) != 1 || got[0] != "CVE-2024-0005" {
		t.Errorf("limited = %v", got)
	}
}

// stub is an OnDemand answering from a script.
type stub struct {
	calls []string
	reply func(n int, cve string) (CVERecord, error)
}

func (s *stub) Key() string { return "enrich.stub" }
func (s *stub) Fetch(_ context.Context, _ *http.Client, cve string) (CVERecord, error) {
	s.calls = append(s.calls, cve)
	return s.reply(len(s.calls), cve)
}

func TestRunOnDemandStopsAtRateLimit(t *testing.T) {
	f := newFixture(t)
	for _, c := range []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"} {
		f.seedFinding(t, "f"+c[9:], scan.StatusNew, "unknown", c)
	}
	s := &stub{reply: func(n int, cve string) (CVERecord, error) {
		if n == 2 {
			return CVERecord{}, ErrRateLimited
		}
		return CVERecord{CVE: cve, CVSSScore: 5.5, CWE: []string{"CWE-79"}}, nil
	}}
	fetched, notFound, failed, err := RunOnDemand(context.Background(), f.deps, s, 10)
	if !errors.Is(err, ErrRateLimited) || fetched != 1 || notFound != 0 || failed != 0 || len(s.calls) != 2 {
		t.Errorf("fetched %d notFound %d failed %d calls %v err %v", fetched, notFound, failed, s.calls, err)
	}
	if f.count(t, "cve_enrichment") != 1 {
		t.Error("expected one stored row")
	}
}

func TestRunOnDemandStoresNotFoundAndCountsFailures(t *testing.T) {
	f := newFixture(t)
	for _, c := range []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"} {
		f.seedFinding(t, "f"+c[9:], scan.StatusNew, "unknown", c)
	}
	s := &stub{reply: func(n int, cve string) (CVERecord, error) {
		switch cve {
		case "CVE-2024-0001":
			return CVERecord{}, ErrNotFound
		case "CVE-2024-0002":
			return CVERecord{}, errors.New("boom")
		}
		return CVERecord{CVE: cve, CVSSScore: 9.5, CVSSVector: "CVSS:3.1/x\x00y", SSVCExploitation: "none"}, nil
	}}
	fetched, notFound, failed, err := RunOnDemand(context.Background(), f.deps, s, 10)
	if err != nil || fetched != 1 || notFound != 1 || failed != 1 {
		t.Fatalf("fetched %d notFound %d failed %d err %v", fetched, notFound, failed, err)
	}
	var score float64
	var src, vec string
	if err := f.st.DB().QueryRow(`SELECT cvss_score, cvss_source, cvss_vector FROM cve_enrichment WHERE cve = 'CVE-2024-0003'`).Scan(&score, &src, &vec); err != nil {
		t.Fatal(err)
	}
	if score != 9.5 || src != "stub" || strings.ContainsRune(vec, 0) {
		t.Errorf("row = %v %q %q", score, src, vec)
	}
	if f.count(t, "cve_enrichment") != 1 || f.count(t, "cve_enrichment_miss") != 1 { // found; miss; the failure is retried
		t.Errorf("rows = %d, misses = %d", f.count(t, "cve_enrichment"), f.count(t, "cve_enrichment_miss"))
	}
	if got, _ := Candidates(context.Background(), f.st.DB(), "enrich.stub", 10); len(got) != 1 || got[0] != "CVE-2024-0002" { // 0001 missed for this source, 0003 has a score
		t.Errorf("remaining candidates = %v", got)
	}
}

func TestRunOnDemandCapsBody(t *testing.T) {
	f := newFixture(t)
	f.seedFinding(t, "f1", scan.StatusNew, "unknown", "CVE-2024-0001")
	big := strings.Repeat("a", 4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush() // chunked: no Content-Length to refuse early
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"` + big + `"}}]}`))
	}))
	defer srv.Close()
	defer SetBaseURLsForTest("", srv.URL, "")()
	defer SetMaxOnDemandBytesForTest(1024)()
	f.deps.Client = srv.Client()
	fetched, _, failed, err := RunOnDemand(context.Background(), f.deps, NVD(""), 10)
	if err != nil || fetched != 0 || failed != 1 {
		t.Errorf("fetched %d failed %d err %v", fetched, failed, err)
	}
	if f.count(t, "cve_enrichment") != 0 {
		t.Error("an over-sized answer was stored")
	}
}

func TestApplyUsesEnrichedCVSSForUnknown(t *testing.T) {
	f := newFixture(t)
	f.seedFinding(t, "f1", scan.StatusNew, "unknown", "CVE-2024-0001")
	if _, err := f.st.DB().Exec(`INSERT INTO cve_enrichment (cve, cvss_score, fetched_at, source_key) VALUES ('CVE-2024-0001', 8.1, '2026-10-25T00:00:00Z', 'enrich.vulnrichment')`); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), f.deps); err != nil {
		t.Fatal(err)
	}
	fs, err := scan.NewRepo(f.st).ListFindings(context.Background(), f.proj.ID, "all")
	if err != nil || len(fs) != 1 {
		t.Fatal(err, fs)
	}
	if fs[0].CVSSEnriched != 8.1 {
		t.Errorf("cvss_enriched = %v", fs[0].CVSSEnriched)
	}
	if l, src := scan.EffectiveSeverity(fs[0]); l != "high" || src != scan.SeverityFromEnrichment {
		t.Errorf("effective = %s %s", l, src)
	}
}

func TestOnDemandSourcesFallBackOnEachOther(t *testing.T) {
	f := newFixture(t)
	f.seedFinding(t, "f1", scan.StatusNew, "unknown", "CVE-2024-0001")
	ctx := context.Background()
	first := &stub{reply: func(int, string) (CVERecord, error) { return CVERecord{}, ErrNotFound }}
	first2 := &stubKey{stub: first, key: "enrich.vulnrichment"}
	if _, nf, _, err := RunOnDemand(ctx, f.deps, first2, 10); err != nil || nf != 1 {
		t.Fatal(nf, err)
	}
	// The same source is not asked twice about a miss.
	if _, _, _, err := RunOnDemand(ctx, f.deps, first2, 10); err != nil || len(first.calls) != 1 {
		t.Errorf("calls = %v err %v", first.calls, err)
	}
	// Another source still is, and its score is stored.
	second := &stub{reply: func(_ int, c string) (CVERecord, error) { return CVERecord{CVE: c, CVSSScore: 7.7}, nil }}
	if n, _, _, err := RunOnDemand(ctx, f.deps, &stubKey{stub: second, key: "enrich.nvd"}, 10); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	var score float64
	var key string
	if err := f.st.DB().QueryRow(`SELECT cvss_score, source_key FROM cve_enrichment WHERE cve = 'CVE-2024-0001'`).Scan(&score, &key); err != nil || score != 7.7 || key != "enrich.nvd" {
		t.Errorf("row = %v %s %v", score, key, err)
	}
	// With a score, nobody is asked any more.
	third := &stub{reply: func(int, string) (CVERecord, error) { return CVERecord{}, errors.New("must not be called") }}
	if _, _, f2, err := RunOnDemand(ctx, f.deps, &stubKey{stub: third, key: "enrich.circl"}, 10); err != nil || f2 != 0 || len(third.calls) != 0 {
		t.Errorf("calls = %v", third.calls)
	}
}

func TestRunOnDemandNeverErasesAScoreWithoutOne(t *testing.T) {
	f := newFixture(t)
	f.seedFinding(t, "f1", scan.StatusNew, "unknown", "CVE-2024-0001")
	ctx := context.Background()
	// SSVC-only answer fills the empty row and counts as a miss for that source.
	s := &stub{reply: func(_ int, c string) (CVERecord, error) { return CVERecord{CVE: c, SSVCExploitation: "none"}, nil }}
	if _, _, _, err := RunOnDemand(ctx, f.deps, s, 10); err != nil {
		t.Fatal(err)
	}
	if f.count(t, "cve_enrichment_miss") != 1 {
		t.Error("a score-less answer is a miss")
	}
	if _, err := f.st.DB().Exec(`UPDATE cve_enrichment SET cvss_score = 6.0 WHERE cve = 'CVE-2024-0001'`); err != nil {
		t.Fatal(err)
	}
	if err := saveRecord(ctx, f.st.DB(), now, CVERecord{CVE: "CVE-2024-0001", SSVCExploitation: "poc"}, "x", "enrich.x"); err != nil {
		t.Fatal(err)
	}
	var score float64
	var ssvc string
	_ = f.st.DB().QueryRow(`SELECT cvss_score, ssvc_exploitation FROM cve_enrichment WHERE cve = 'CVE-2024-0001'`).Scan(&score, &ssvc)
	if score != 6.0 || ssvc != "none" {
		t.Errorf("row = %v %q", score, ssvc)
	}
}

func TestGetJSONDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()
	defer SetBaseURLsForTest("", srv.URL, "")()
	client := srv.Client()
	_, err := NVD("s3cret").Fetch(context.Background(), client, "CVE-2024-0001")
	if err == nil || strings.Contains(err.Error(), "s3cret") || hits.Load() != 0 {
		t.Errorf("err = %v, hits = %d", err, hits.Load())
	}
	if client.CheckRedirect != nil {
		t.Error("the caller's client was modified")
	}
}

// stubKey gives a stub another source key.
type stubKey struct {
	*stub
	key string
}

func (s *stubKey) Key() string { return s.key }

// spacedStub is a stub asked at a given pace.
type spacedStub struct {
	*stub
	gap time.Duration
}

func (s *spacedStub) Interval() time.Duration { return s.gap }

func TestRunOnDemandStopsBeforeDeadline(t *testing.T) {
	f := newFixture(t)
	for _, c := range []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004", "CVE-2024-0005"} {
		f.seedFinding(t, "f"+c[9:], scan.StatusNew, "unknown", c)
	}
	base := time.Now()
	fake := base
	oc, op, om := clock, pause, requestMargin
	t.Cleanup(func() { clock, pause, requestMargin = oc, op, om })
	clock = func() time.Time { return fake }
	pause = func(_ context.Context, d time.Duration) error { fake = fake.Add(d); return nil }
	requestMargin = 30 * time.Second
	// 50 s left: before the 2nd, 3rd and 4th requests 50, 44 and 38 s are
	// left, at least the 6 s gap + 30 s margin; before the 5th only 32 s.
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(50*time.Second))
	defer cancel()
	s := &spacedStub{stub: &stub{reply: func(_ int, cve string) (CVERecord, error) {
		return CVERecord{CVE: cve, CVSSScore: 5}, nil
	}}, gap: 6 * time.Second}
	fetched, notFound, failed, err := RunOnDemand(ctx, f.deps, s, 10)
	if !errors.Is(err, ErrOutOfTime) || fetched != 4 || notFound != 0 || failed != 0 || len(s.calls) != 4 {
		t.Fatalf("fetched %d notFound %d failed %d calls %v err %v", fetched, notFound, failed, s.calls, err)
	}
	if f.count(t, "cve_enrichment") != 4 {
		t.Errorf("rows = %d, want the 4 fetched kept", f.count(t, "cve_enrichment"))
	}
}

func TestRunOnDemandWithoutDeadlineAsksEveryCandidate(t *testing.T) {
	f := newFixture(t)
	for _, c := range []string{"CVE-2024-0001", "CVE-2024-0002"} {
		f.seedFinding(t, "f"+c[9:], scan.StatusNew, "unknown", c)
	}
	op := pause
	t.Cleanup(func() { pause = op })
	pause = func(context.Context, time.Duration) error { return nil }
	s := &spacedStub{stub: &stub{reply: func(_ int, cve string) (CVERecord, error) {
		return CVERecord{CVE: cve, CVSSScore: 5}, nil
	}}, gap: time.Hour}
	if n, _, _, err := RunOnDemand(context.Background(), f.deps, s, 10); err != nil || n != 2 {
		t.Fatalf("fetched %d err %v", n, err)
	}
}

func TestPauseReturnsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := sleepCtx(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("the pause ignored the context")
	}
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Errorf("short pause: %v", err)
	}
}
