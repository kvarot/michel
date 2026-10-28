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
	resp, err := client.Do(req)
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
// OSV leaves unknown and that have no cve_enrichment row yet, most recently
// seen findings first.
func Candidates(ctx context.Context, db *sql.DB, limit int) ([]string, error) {
	type row struct{ osv, aliases string }
	var rows []row
	if err := each(ctx, db, `SELECT osv_id, aliases FROM finding WHERE status <> ? AND severity_label = 'unknown'
		ORDER BY last_seen_at DESC, id`, []any{scan.StatusGone}, func(r *sql.Rows) error {
		var x row
		if err := r.Scan(&x.osv, &x.aliases); err != nil {
			return err
		}
		rows = append(rows, x)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("cannot read the findings: %w", err)
	}
	out := []string{}
	seen := map[string]bool{}
	for _, x := range rows {
		var aliases []string
		_ = json.Unmarshal([]byte(x.aliases), &aliases)
		for _, c := range scan.CVEsOf(scan.Finding{OSVID: x.osv, Aliases: aliases}) {
			if len(out) >= limit {
				return out, nil
			}
			if seen[c] || !cveID.MatchString(c) {
				continue
			}
			seen[c] = true
			var n int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cve_enrichment WHERE cve = ?`, c).Scan(&n); err != nil {
				return nil, fmt.Errorf("cannot read the enrichment data: %w", err)
			}
			if n == 0 {
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// RunOnDemand asks src about up to limit candidate CVEs and stores each
// answer in cve_enrichment (source_key = src.Key()). A CVE the source does
// not know is stored without data, so it is not asked again; a failure
// stores nothing and the CVE is retried next time. The run stops at the
// first rate limit and returns ErrRateLimited with the counts so far.
func RunOnDemand(ctx context.Context, deps Deps, src OnDemand, limit int) (fetched, notFound, failed int, err error) {
	db := deps.Store.DB()
	cves, err := Candidates(ctx, db, limit)
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
			if err := saveRecord(ctx, db, deps.Now(), CVERecord{CVE: cve}, name, src.Key()); err != nil {
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
			if err := saveRecord(ctx, db, deps.Now(), rec, name, src.Key()); err != nil {
				return fetched, notFound, failed, err
			}
			fetched++
		}
	}
	return fetched, notFound, failed, nil
}

// saveRecord writes one cve_enrichment row.
func saveRecord(ctx context.Context, db *sql.DB, now time.Time, rec CVERecord, cvssSource, key string) error {
	rec = rec.clean()
	cwe, _ := json.Marshal(rec.CWE)
	if rec.CVSSScore == 0 {
		cvssSource = ""
	}
	_, err := db.ExecContext(ctx, `INSERT INTO cve_enrichment (cve, cvss_score, cvss_vector, cvss_source, ssvc_exploitation,
		ssvc_automatable, ssvc_technical_impact, cwe, fetched_at, source_key) VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (cve) DO UPDATE SET cvss_score = excluded.cvss_score, cvss_vector = excluded.cvss_vector,
		cvss_source = excluded.cvss_source, ssvc_exploitation = excluded.ssvc_exploitation,
		ssvc_automatable = excluded.ssvc_automatable, ssvc_technical_impact = excluded.ssvc_technical_impact,
		cwe = excluded.cwe, fetched_at = excluded.fetched_at, source_key = excluded.source_key`,
		rec.CVE, rec.CVSSScore, rec.CVSSVector, cvssSource, rec.SSVCExploitation, rec.SSVCAutomatable,
		rec.SSVCTechnicalImpact, string(cwe), now.UTC().Truncate(time.Second).Format(time.RFC3339), key)
	if err != nil {
		return fmt.Errorf("cannot store the enrichment of %s: %w", rec.CVE, err)
	}
	return nil
}
