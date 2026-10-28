package enrich

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"encoding/json"

	"github.com/kvarot/michel/internal/scan"
)

// The on-demand enrichments (Vulnrichment, NVD, CIRCL) are asked about one
// CVE at a time, only for the findings OSV gives no severity for. Only the
// CVE id leaves the machine (and the NVD key, in a header, when set).

// MaxOnDemandBytes caps the body of one on-demand answer; the per-run caps
// bound how many CVEs one update asks each source about.
const (
	MaxOnDemandBytes      int64 = 5 << 20
	MaxVulnrichmentPerRun       = 200
	MaxNVDPerRun                = 100
	MaxCIRCLPerRun              = 200
)

// Errors of the on-demand readers.
var (
	// ErrNotFound means the source knows nothing about the CVE (404).
	ErrNotFound = errors.New("the source does not know this CVE")
	// ErrRateLimited means the source refused the request for want of quota
	// (403 or 429): the run stops, the next update goes on.
	ErrRateLimited = errors.New("the source is rate limiting Michel")
)

// maxOnDemandBytes and pause are what tests replace.
var (
	maxOnDemandBytes = MaxOnDemandBytes
	pause            = time.Sleep
)

// CVERecord is what an on-demand source says about one CVE.
type CVERecord struct {
	CVE                                                    string
	CVSSScore                                              float64
	CVSSVector                                             string
	SSVCExploitation, SSVCAutomatable, SSVCTechnicalImpact string
	CWE                                                    []string
}

// OnDemand is one on-demand enrichment source. Key is its source key
// ("enrich.<name>"); Fetch asks it about one CVE with the egress client.
type OnDemand interface {
	Key() string
	Fetch(ctx context.Context, client *http.Client, cve string) (CVERecord, error)
}

// spaced is implemented by sources that must be asked at a given pace.
type spaced interface{ Interval() time.Duration }

var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

// checkCVE returns cve upper-cased, or an error when it is not a plain CVE
// id: it ends up in a URL and must not be able to alter it.
func checkCVE(cve string) (string, error) {
	cve = strings.ToUpper(strings.TrimSpace(cve))
	if !cveID.MatchString(cve) {
		return "", fmt.Errorf("%q is not a CVE identifier", cleanField(cve))
	}
	return cve, nil
}

// getJSON GETs url (with the optional headers) and returns the body, read up
// to the on-demand cap. 404 is ErrNotFound; 403 and 429 are ErrRateLimited.
// The errors never repeat the request headers.
func getJSON(ctx context.Context, client *http.Client, url string, headers map[string]string) ([]byte, error) {
	if client == nil {
		return nil, errors.New("no HTTP client: build it with the egress gateway")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.New("cannot build the request")
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// Never follow a redirect: the request may carry an API key. The caller's
	// client is copied, not changed.
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		var ue interface{ Unwrap() error }
		if errors.As(err, &ue) && ue.Unwrap() != nil {
			err = ue.Unwrap() // drop the URL wrapper
		}
		return nil, fmt.Errorf("the request failed: %w", err)
	}
	defer resp.Body.Close()
	limit := maxOnDemandBytes
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
		return nil, ErrRateLimited
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("the server answered %s", resp.Status)
	case resp.ContentLength > limit:
		return nil, fmt.Errorf("the answer is %d bytes, more than the %d bytes Michel accepts", resp.ContentLength, limit)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read the answer: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("the answer is more than the %d bytes Michel accepts", limit)
	}
	return body, nil
}

// clean sanitises a record read from a source: control characters stripped,
// text capped, the score kept in 0..10 and the CWE list in shape.
func (r CVERecord) clean() CVERecord {
	r.CVSSScore = max(0, min(10, r.CVSSScore))
	r.CVSSVector = cleanField(r.CVSSVector)
	r.SSVCExploitation = cleanField(r.SSVCExploitation)
	r.SSVCAutomatable = cleanField(r.SSVCAutomatable)
	r.SSVCTechnicalImpact = cleanField(r.SSVCTechnicalImpact)
	cwe := []string{}
	for _, c := range r.CWE {
		c = strings.ToUpper(cleanField(c))
		if cweID.MatchString(c) && !contains(cwe, c) {
			cwe = append(cwe, c)
		}
	}
	r.CWE = cwe
	return r
}

var cweID = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Candidates lists up to limit CVEs of the findings not gone whose severity
// OSV leaves unknown, most recently seen findings first. A CVE already given
// a CVSS score by any source is left out, and so is one sourceKey has
// already missed (cve_enrichment_miss): the other sources are still asked.
func Candidates(ctx context.Context, db *sql.DB, sourceKey string, limit int) ([]string, error) {
	skip := map[string]bool{}
	if err := each(ctx, db, `SELECT cve FROM cve_enrichment WHERE cvss_score > 0
		UNION SELECT cve FROM cve_enrichment_miss WHERE source_key = ?`, []any{sourceKey}, func(r *sql.Rows) error {
		var c string
		if err := r.Scan(&c); err != nil {
			return err
		}
		skip[c] = true
		return nil
	}); err != nil {
		return nil, fmt.Errorf("cannot read the enrichment data: %w", err)
	}
	out := []string{}
	if limit <= 0 {
		return out, nil
	}
	seen := map[string]bool{}
	var full bool
	err := each(ctx, db, `SELECT osv_id, aliases FROM finding WHERE status <> ? AND severity_label = 'unknown'
		ORDER BY last_seen_at DESC, id`, []any{scan.StatusGone}, func(r *sql.Rows) error {
		var osv, al string
		if err := r.Scan(&osv, &al); err != nil {
			return err
		}
		var aliases []string
		_ = json.Unmarshal([]byte(al), &aliases)
		for _, c := range scan.CVEsOf(scan.Finding{OSVID: osv, Aliases: aliases}) {
			if seen[c] || skip[c] || !cveID.MatchString(c) {
				continue
			}
			seen[c] = true
			out = append(out, c)
			if len(out) >= limit {
				full = true
				return errStop
			}
		}
		return nil
	})
	if err != nil && !(full && errors.Is(err, errStop)) {
		return nil, fmt.Errorf("cannot read the findings: %w", err)
	}
	return out, nil
}

var errStop = errors.New("stop")

// RunOnDemand asks src about up to limit candidate CVEs. An answer with a
// CVSS score is stored in cve_enrichment (source_key = src.Key()). A CVE the
// source does not know, or answers without a score, is noted in
// cve_enrichment_miss for this source only, so it is not asked again while
// the other sources still are. An answer without a score but with SSVC or
// CWE data fills the CVE's row only when it has no score yet; a row with a
// score is never overwritten by one without. A failure stores nothing and
// is retried. The run stops at the first rate limit and returns
// ErrRateLimited with the counts so far.
func RunOnDemand(ctx context.Context, deps Deps, src OnDemand, limit int) (fetched, notFound, failed int, err error) {
	db := deps.Store.DB()
	cves, err := Candidates(ctx, db, src.Key(), limit)
	if err != nil {
		return 0, 0, 0, err
	}
	var gap time.Duration
	if s, ok := src.(spaced); ok {
		gap = s.Interval()
	}
	name := strings.TrimPrefix(src.Key(), "enrich.")
	for i, cve := range cves {
		if err := ctx.Err(); err != nil {
			return fetched, notFound, failed, err
		}
		if i > 0 && gap > 0 {
			pause(gap)
		}
		rec, ferr := src.Fetch(ctx, deps.Client, cve)
		switch {
		case errors.Is(ferr, ErrRateLimited):
			return fetched, notFound, failed, ErrRateLimited
		case errors.Is(ferr, ErrNotFound):
			if err := saveMiss(ctx, db, deps.Now(), cve, src.Key()); err != nil {
				return fetched, notFound, failed, err
			}
			notFound++
		case ferr != nil:
			if ctx.Err() != nil {
				return fetched, notFound, failed, ctx.Err()
			}
			failed++
		default:
			rec.CVE = cve
			rec = rec.clean()
			if rec.CVSSScore == 0 {
				if err := saveMiss(ctx, db, deps.Now(), cve, src.Key()); err != nil {
					return fetched, notFound, failed, err
				}
				if rec.SSVCExploitation == "" && rec.SSVCAutomatable == "" && rec.SSVCTechnicalImpact == "" && len(rec.CWE) == 0 {
					notFound++
					continue
				}
			}
			if err := saveRecord(ctx, db, deps.Now(), rec, name, src.Key()); err != nil {
				return fetched, notFound, failed, err
			}
			fetched++
		}
	}
	return fetched, notFound, failed, nil
}

func stamp(now time.Time) string { return now.UTC().Truncate(time.Second).Format(time.RFC3339) }

func saveMiss(ctx context.Context, db *sql.DB, now time.Time, cve, key string) error {
	_, err := db.ExecContext(ctx, `INSERT INTO cve_enrichment_miss (cve, source_key, fetched_at) VALUES (?,?,?)
		ON CONFLICT (cve, source_key) DO UPDATE SET fetched_at = excluded.fetched_at`, cve, key, stamp(now))
	if err != nil {
		return fmt.Errorf("cannot store the enrichment of %s: %w", cve, err)
	}
	return nil
}

// saveRecord writes one cve_enrichment row; an existing row with a score is
// only replaced by a record that has one.
func saveRecord(ctx context.Context, db *sql.DB, now time.Time, rec CVERecord, cvssSource, key string) error {
	cwe, _ := json.Marshal(rec.CWE)
	if rec.CVSSScore == 0 {
		cvssSource = ""
	}
	_, err := db.ExecContext(ctx, `INSERT INTO cve_enrichment (cve, cvss_score, cvss_vector, cvss_source, ssvc_exploitation,
		ssvc_automatable, ssvc_technical_impact, cwe, fetched_at, source_key) VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (cve) DO UPDATE SET cvss_score = excluded.cvss_score, cvss_vector = excluded.cvss_vector,
		cvss_source = excluded.cvss_source, ssvc_exploitation = excluded.ssvc_exploitation,
		ssvc_automatable = excluded.ssvc_automatable, ssvc_technical_impact = excluded.ssvc_technical_impact,
		cwe = excluded.cwe, fetched_at = excluded.fetched_at, source_key = excluded.source_key
		WHERE excluded.cvss_score > 0 OR cve_enrichment.cvss_score = 0`,
		rec.CVE, rec.CVSSScore, rec.CVSSVector, cvssSource, rec.SSVCExploitation, rec.SSVCAutomatable,
		rec.SSVCTechnicalImpact, string(cwe), stamp(now), key)
	if err != nil {
		return fmt.Errorf("cannot store the enrichment of %s: %w", rec.CVE, err)
	}
	return nil
}
