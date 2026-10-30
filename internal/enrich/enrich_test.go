package enrich

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/store"
)

var now = time.Date(2026, 10, 26, 6, 0, 0, 0, time.UTC)

type fixture struct {
	st   *store.Store
	deps Deps
	proj project.Project
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	p, err := project.NewRepo(st).Add(context.Background(), project.Project{Name: "demo", Path: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return now }
	return fixture{st: st, proj: p, deps: Deps{Store: st, Audit: audit.NewLogger(st, clock), Client: http.DefaultClient, Now: clock}}
}

func (f fixture) count(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := f.st.DB().QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// serve answers every request with body and etag; a request carrying
// If-None-Match equal to etag gets 304.
func serve(t *testing.T, body *[]byte, etag string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if etag != "" && r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if etag != "" {
			w.Header().Set("ETag", etag)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(*body)))
		_, _ = w.Write(*body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// pointAt makes the readers fetch from srv for the test.
func pointAt(t *testing.T, kev, epss string) {
	t.Helper()
	oldK, oldE := kevURL, epssURL
	kevURL, epssURL = kev, epss
	t.Cleanup(func() { kevURL, epssURL = oldK, oldE })
}

func kevBody(t *testing.T, keep int) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "kev.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["vulnerabilities"] = doc["vulnerabilities"].([]any)[:keep]
	b, _ := json.Marshal(doc)
	return b
}

func TestReadKEVReplacesTable(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	body := kevBody(t, 3)
	srv := serve(t, &body, "")
	pointAt(t, srv.URL, "")
	f.deps.Client = srv.Client()
	n, _, err := ReadKEV(ctx, f.deps, "")
	if err != nil || n != 3 || f.count(t, "kev") != 3 {
		t.Fatalf("first read: %d items, %v, %d rows", n, err, f.count(t, "kev"))
	}
	var name, added, due, ransom, notes string
	if err := f.st.DB().QueryRow(`SELECT name, date_added, due_date, ransomware, notes_url FROM kev WHERE cve = 'CVE-2024-0002'`).
		Scan(&name, &added, &due, &ransom, &notes); err != nil {
		t.Fatal(err)
	}
	if name != "Vuln Pkg [31mPath Traversal" || added != "2026-05-01" || due != "2026-05-22" || ransom != "Known" || notes != "" {
		t.Errorf("row = %q %q %q %q %q", name, added, due, ransom, notes)
	}
	if err := f.st.DB().QueryRow(`SELECT notes_url FROM kev WHERE cve = 'CVE-2024-0001'`).Scan(&notes); err != nil || notes != "https://example.org/acme/advisory" {
		t.Errorf("notes_url = %q %v", notes, err)
	}
	body = kevBody(t, 2)
	if n, _, err := ReadKEV(ctx, f.deps, ""); err != nil || n != 2 || f.count(t, "kev") != 2 {
		t.Fatalf("second read: %d items, %v, %d rows", n, err, f.count(t, "kev"))
	}
}

func TestReadKEVHonoursETag(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	body := kevBody(t, 3)
	srv := serve(t, &body, `"v1"`)
	pointAt(t, srv.URL, "")
	f.deps.Client = srv.Client()
	n, etag, err := ReadKEV(ctx, f.deps, "")
	if err != nil || n != 3 || etag != `"v1"` {
		t.Fatalf("first read: %d %q %v", n, etag, err)
	}
	n, etag, err = ReadKEV(ctx, f.deps, `"v1"`)
	if !errors.Is(err, ErrNotModified) || n != 0 || etag != `"v1"` {
		t.Errorf("second read: %d %q %v", n, etag, err)
	}
	if f.count(t, "kev") != 3 {
		t.Errorf("table changed on 304: %d rows", f.count(t, "kev"))
	}
}

func TestReadKEVCapsBody(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	body := kevBody(t, 3)
	srv := serve(t, &body, "")
	pointAt(t, srv.URL, "")
	f.deps.Client = srv.Client()
	if _, _, err := ReadKEV(ctx, f.deps, ""); err != nil {
		t.Fatal(err)
	}
	old := maxKEVBytes
	maxKEVBytes = int64(len(body)) - 1
	t.Cleanup(func() { maxKEVBytes = old })
	body = kevBody(t, 2)
	maxKEVBytes = int64(len(body)) - 1
	if _, _, err := ReadKEV(ctx, f.deps, ""); err == nil {
		t.Fatal("a body over the cap was accepted")
	}
	if f.count(t, "kev") != 3 {
		t.Errorf("table changed by a refused read: %d rows", f.count(t, "kev"))
	}
	if MaxKEVBytes != 50<<20 || MaxEPSSBytes != 200<<20 {
		t.Errorf("caps = %d %d", MaxKEVBytes, MaxEPSSBytes)
	}
}

func TestReadEPSSParsesGzipCSV(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	body, err := os.ReadFile(filepath.Join("testdata", "epss.csv.gz"))
	if err != nil {
		t.Fatal(err)
	}
	srv := serve(t, &body, `"e1"`)
	pointAt(t, "", srv.URL)
	f.deps.Client = srv.Client()
	n, etag, err := ReadEPSS(ctx, f.deps, "")
	if err != nil || n != 3 || etag != `"e1"` {
		t.Fatalf("read: %d %q %v", n, etag, err)
	}
	var score, pct float64
	var model string
	if err := f.st.DB().QueryRow(`SELECT score, percentile, model_date FROM epss WHERE cve = 'CVE-2024-0001'`).Scan(&score, &pct, &model); err != nil {
		t.Fatal(err)
	}
	if score != 0.12 || pct != 0.95 || model != "2026-10-25" {
		t.Errorf("row = %v %v %q", score, pct, model)
	}
	if _, _, err := ReadEPSS(ctx, f.deps, `"e1"`); !errors.Is(err, ErrNotModified) {
		t.Errorf("304: %v", err)
	}
	if f.count(t, "epss") != 3 {
		t.Errorf("rows = %d", f.count(t, "epss"))
	}
}

func TestLookupOfPicksCVEAlias(t *testing.T) {
	l := Lookup{
		KEV:  map[string]KEVEntry{"CVE-2024-1": {Added: "2026-03-12"}},
		EPSS: map[string]EPSSEntry{"CVE-2024-1": {Score: 0.1, Percentile: 0.6}, "CVE-2024-2": {Score: 0.3, Percentile: 0.8}},
		CVSS: map[string]float64{"CVE-2024-2": 7.5},
	}
	kev, added, epss, pct, cvss := l.Of([]string{"GHSA-x", "CVE-2024-1"})
	if !kev || added != "2026-03-12" || epss != 0.1 || pct != 0.6 || cvss != 0 {
		t.Errorf("Of = %v %q %v %v %v", kev, added, epss, pct, cvss)
	}
	kev, _, epss, pct, cvss = l.Of([]string{"cve-2024-2", "CVE-2024-1"})
	if !kev || epss != 0.3 || pct != 0.8 || cvss != 7.5 {
		t.Errorf("Of with two CVEs = %v %v %v %v", kev, epss, pct, cvss)
	}
	if kev, _, epss, _, _ := l.Of([]string{"GHSA-x"}); kev || epss != 0 {
		t.Error("an advisory without CVE got an enrichment")
	}
}

// seedFinding inserts a finding with the given aliases and status.
func (f fixture) seedFinding(t *testing.T, id, status, severity string, aliases ...string) {
	t.Helper()
	al, _ := json.Marshal(aliases)
	if _, err := f.st.DB().Exec(`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, aliases,
		severity_label, installed_version, fixed_versions, status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, status_changed_at)
		VALUES (?, ?, 'composer.lock', 'Packagist', 'acme/lib', ?, ?, ?, '1.0.0', '["1.0.1"]', ?, 's1', 's1',
		'2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')`,
		id, f.proj.ID, "GHSA-"+id, string(al), severity, status); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) decide(t *testing.T, findingID, action string, seenKEV int) {
	t.Helper()
	if _, err := f.st.DB().Exec(`INSERT INTO decision (id, finding_id, project_id, action, justification, author, created_at,
		seen_severity, seen_fixed_versions, seen_kev) VALUES (?, ?, ?, ?, 'not reachable', 'cli', '2026-10-02T00:00:00Z', 'low', '["1.0.1"]', ?)`,
		"d-"+findingID, findingID, f.proj.ID, action, seenKEV); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DB().Exec(`UPDATE finding SET status = 'decided' WHERE id = ?`, findingID); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) seedSources(t *testing.T) {
	t.Helper()
	db := f.st.DB()
	for _, q := range []string{
		`INSERT INTO kev (cve, date_added) VALUES ('CVE-2024-0001', '2026-03-12')`,
		`INSERT INTO epss (cve, score, percentile, model_date) VALUES ('CVE-2024-0001', 0.12, 0.95, '2026-10-25'), ('CVE-2024-0003', 0.5, 0.97, '2026-10-25')`,
		`INSERT INTO cve_enrichment (cve, cvss_score, fetched_at, source_key) VALUES ('CVE-2024-0003', 9.1, '2026-10-25T00:00:00Z', 'enrich.vulnrichment')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

func TestApplyFillsFindingColumns(t *testing.T) {
	f := newFixture(t)
	f.seedSources(t)
	f.seedFinding(t, "f1", scan.StatusNew, "low", "CVE-2024-0001")
	f.seedFinding(t, "f2", scan.StatusPending, "unknown", "CVE-2024-0003")
	f.seedFinding(t, "f3", scan.StatusGone, "low", "CVE-2024-0001")
	f.seedFinding(t, "f4", scan.StatusNew, "low")
	res, err := Apply(context.Background(), f.deps)
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated != 2 || res.NowKEV != 1 || res.Superseded != 0 {
		t.Errorf("result = %+v", res)
	}
	fs, err := scan.NewRepo(f.st).ListFindings(context.Background(), f.proj.ID, "all")
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]scan.Finding{}
	for _, x := range fs {
		by[x.ID] = x
	}
	if x := by["f1"]; !x.KEV || x.KEVAdded != "2026-03-12" || x.EPSS != 0.12 || x.EPSSPercentile != 0.95 {
		t.Errorf("f1 = %+v", x)
	}
	if x := by["f2"]; x.KEV || x.CVSSEnriched != 9.1 || x.EPSSPercentile != 0.97 {
		t.Errorf("f2 = %+v", x)
	}
	if l, src := scan.EffectiveSeverity(by["f2"]); l != "critical" || src != scan.SeverityFromEnrichment {
		t.Errorf("f2 effective severity = %s %s", l, src)
	}
	if x := by["f3"]; x.KEV {
		t.Error("a gone finding was enriched")
	}
	if res, err := Apply(context.Background(), f.deps); err != nil || res.Updated != 0 || res.NowKEV != 0 {
		t.Errorf("second Apply = %+v %v", res, err)
	}
}

func TestApplySupersedesIgnoreWhenKEVAppears(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.seedFinding(t, "f1", scan.StatusNew, "low", "CVE-2024-0001")
	f.decide(t, "f1", "ignore", 0)
	if res, err := Apply(ctx, f.deps); err != nil || res.Superseded != 0 {
		t.Fatalf("Apply without KEV = %+v %v", res, err)
	}
	if _, err := f.st.DB().Exec(`INSERT INTO kev (cve, date_added) VALUES ('CVE-2024-0001', '2026-10-25')`); err != nil {
		t.Fatal(err)
	}
	res, err := Apply(ctx, f.deps)
	if err != nil || res.Superseded != 1 || res.NowKEV != 1 {
		t.Fatalf("Apply = %+v %v", res, err)
	}
	var at, reason, status, changed string
	if err := f.st.DB().QueryRow(`SELECT superseded_at, superseded_reason FROM decision WHERE id = 'd-f1'`).Scan(&at, &reason); err != nil {
		t.Fatal(err)
	}
	if at != now.Format(time.RFC3339) || reason != "kev_changed" {
		t.Errorf("decision = %q %q", at, reason)
	}
	if err := f.st.DB().QueryRow(`SELECT status, status_changed_at FROM finding WHERE id = 'f1'`).Scan(&status, &changed); err != nil {
		t.Fatal(err)
	}
	if status != scan.StatusPending || changed != now.Format(time.RFC3339) {
		t.Errorf("finding = %s since %s", status, changed)
	}
	var actor, target, raw string
	if err := f.st.DB().QueryRow(`SELECT actor, target, evidence FROM audit_event WHERE action = 'decision.superseded'`).Scan(&actor, &target, &raw); err != nil {
		t.Fatal(err)
	}
	var ev map[string]any
	_ = json.Unmarshal([]byte(raw), &ev)
	if actor != "enrich" || target != "f1" || ev["reason"] != "kev_changed" || ev["previous_action"] != "ignore" || ev["project_id"] != f.proj.ID {
		t.Errorf("event = %s %s %s", actor, target, raw)
	}
	if res, err := Apply(ctx, f.deps); err != nil || res.Superseded != 0 {
		t.Errorf("third Apply = %+v %v", res, err)
	}
}

func TestApplyLeavesFixDecisionWhenKEVUnchanged(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.seedSources(t)
	f.seedFinding(t, "f1", scan.StatusNew, "low", "CVE-2024-0001")
	f.decide(t, "f1", "fix", 1)
	res, err := Apply(ctx, f.deps)
	if err != nil || res.Superseded != 0 {
		t.Fatalf("Apply = %+v %v", res, err)
	}
	var at, status string
	if err := f.st.DB().QueryRow(`SELECT superseded_at FROM decision WHERE id = 'd-f1'`).Scan(&at); err != nil || at != "" {
		t.Errorf("decision superseded: %q %v", at, err)
	}
	if err := f.st.DB().QueryRow(`SELECT status FROM finding WHERE id = 'f1'`).Scan(&status); err != nil || status != scan.StatusDecided {
		t.Errorf("status = %s %v", status, err)
	}
}

func TestLookupFuncAnswersOnlyKnownCVEs(t *testing.T) {
	f := newFixture(t)
	f.seedSources(t)
	m, err := LookupFunc(f.st.DB())([]string{"CVE-2024-0001", "CVE-2024-0003", "CVE-2099-0001"})
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || !m["CVE-2024-0001"].KEV || m["CVE-2024-0003"].CVSS != 9.1 || m["CVE-2024-0003"].EPSS != 0.5 {
		t.Errorf("lookup = %+v", m)
	}
}

func TestReadEPSSCapsDecompressedText(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	body, err := os.ReadFile(filepath.Join("testdata", "epss.csv.gz"))
	if err != nil {
		t.Fatal(err)
	}
	srv := serve(t, &body, "")
	pointAt(t, "", srv.URL)
	f.deps.Client = srv.Client()
	if _, _, err := ReadEPSS(ctx, f.deps, ""); err != nil {
		t.Fatal(err)
	}
	// A small download that inflates past the cap: the compressed body is
	// within it, the decompressed text is not.
	var csv strings.Builder
	csv.WriteString("#model_version:v2025.03.14,score_date:2026-10-26T00:00:00+0000\ncve,epss,percentile\n")
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&csv, "CVE-2024-%05d,0.5,0.5\n", 10000+i)
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte(csv.String()))
	w.Close()
	body = gz.Bytes()
	old := maxEPSSBytes
	t.Cleanup(func() { maxEPSSBytes = old })
	maxEPSSBytes = int64(csv.Len()) - 1
	if int64(len(body)) > maxEPSSBytes {
		t.Fatalf("the compressed body (%d) must fit the cap (%d)", len(body), maxEPSSBytes)
	}
	_, _, err = ReadEPSS(ctx, f.deps, "")
	if err == nil || !strings.Contains(err.Error(), "decompressed") {
		t.Fatalf("a text over the cap once decompressed was accepted: %v", err)
	}
	if f.count(t, "epss") != 3 {
		t.Errorf("table changed by a refused read: %d rows", f.count(t, "epss"))
	}
	maxEPSSBytes = int64(csv.Len())
	if n, _, err := ReadEPSS(ctx, f.deps, ""); err != nil || n != 5000 {
		t.Errorf("at the cap: %d %v", n, err)
	}
}
