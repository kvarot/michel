// Package enrich reads the enrichment sources (CISA's Known Exploited
// Vulnerabilities list, FIRST's EPSS scores) into the store and applies them
// to the findings: the KEV mark, the exploitation score and an enriched CVSS
// are denormalised on each finding, matched in Go through its CVE aliases.
//
// What the sources send is untrusted data: it is size-capped, stripped of
// control characters, stored as plain values and never executed. Every
// request goes through the egress gateway (purpose source.enrich).
package enrich

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/store"
)

// Deps are the collaborators of the readers and of Apply. Client must come
// from egress.Gateway.Client(policy.PurposeEnrich).
type Deps struct {
	Store  *store.Store
	Audit  *audit.Logger
	Client *http.Client
	Now    func() time.Time
}

// Where the sources are read.
const (
	KEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	EPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
)

// Size caps: the KEV JSON, and the EPSS CSV once decompressed.
const (
	MaxKEVBytes  int64 = 50 << 20
	MaxEPSSBytes int64 = 200 << 20
)

// The URLs and caps the readers use; tests point them elsewhere.
var (
	kevURL       = KEVURL
	epssURL      = EPSSURL
	maxKEVBytes  = MaxKEVBytes
	maxEPSSBytes = MaxEPSSBytes
)

// ErrNotModified means the source answered 304 to the ETag of the last read:
// the stored data is current and was left as it is.
var ErrNotModified = errors.New("not modified since the last read")

// KEVEntry is what the lookup keeps of a KEV row.
type KEVEntry struct {
	Added string
}

// EPSSEntry is what the lookup keeps of an EPSS row.
type EPSSEntry struct {
	Score, Percentile float64
}

// Lookup holds the enrichment data in memory: the whole KEV list, and the
// EPSS scores and enriched CVSS of the CVEs asked for only.
type Lookup struct {
	KEV  map[string]KEVEntry
	EPSS map[string]EPSSEntry
	CVSS map[string]float64
}

// lookupChunk is how many CVEs one IN (...) query holds.
const lookupChunk = 500

// LoadLookup reads the KEV list and the EPSS and CVSS rows of cves.
func LoadLookup(ctx context.Context, db *sql.DB, cves []string) (Lookup, error) {
	return loadLookup(ctx, db, cves)
}

// querier is a *sql.DB or a *sql.Tx.
type querier interface {
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
}

func loadLookup(ctx context.Context, db querier, cves []string) (Lookup, error) {
	l := Lookup{KEV: map[string]KEVEntry{}, EPSS: map[string]EPSSEntry{}, CVSS: map[string]float64{}}
	rows, err := db.QueryContext(ctx, `SELECT cve, date_added FROM kev`)
	if err != nil {
		return Lookup{}, err
	}
	for rows.Next() {
		var cve string
		var e KEVEntry
		if err := rows.Scan(&cve, &e.Added); err != nil {
			rows.Close()
			return Lookup{}, err
		}
		l.KEV[cve] = e
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Lookup{}, err
	}
	for start := 0; start < len(cves); start += lookupChunk {
		part := cves[start:min(start+lookupChunk, len(cves))]
		marks := strings.TrimSuffix(strings.Repeat("?,", len(part)), ",")
		args := make([]any, len(part))
		for i, c := range part {
			args[i] = c
		}
		if err := each(ctx, db, `SELECT cve, score, percentile FROM epss WHERE cve IN (`+marks+`)`, args, func(r *sql.Rows) error {
			var cve string
			var e EPSSEntry
			if err := r.Scan(&cve, &e.Score, &e.Percentile); err != nil {
				return err
			}
			l.EPSS[cve] = e
			return nil
		}); err != nil {
			return Lookup{}, err
		}
		if err := each(ctx, db, `SELECT cve, cvss_score FROM cve_enrichment WHERE cvss_score > 0 AND cve IN (`+marks+`)`, args, func(r *sql.Rows) error {
			var cve string
			var s float64
			if err := r.Scan(&cve, &s); err != nil {
				return err
			}
			l.CVSS[cve] = s
			return nil
		}); err != nil {
			return Lookup{}, err
		}
	}
	return l, nil
}

func each(ctx context.Context, db querier, q string, args []any, fn func(*sql.Rows) error) error {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// entry is what l knows about one CVE (ok=false when nothing).
func (l Lookup) entry(cve string) (scan.Enrichment, bool) {
	var e scan.Enrichment
	k, kev := l.KEV[cve]
	p, epss := l.EPSS[cve]
	c, cvss := l.CVSS[cve]
	if !kev && !epss && !cvss {
		return e, false
	}
	e.KEV, e.KEVAdded = kev, k.Added
	e.EPSS, e.EPSSPercentile, e.CVSS = p.Score, p.Percentile, c
	return e, true
}

// Of combines what l knows about the CVE identifiers among aliases: KEV when
// one of them is listed (with the date of the first listed), the highest
// EPSS with its percentile, the highest CVSS (scan.CombineEnrichment).
func (l Lookup) Of(aliases []string) (kev bool, kevAdded string, epss, percentile, cvss float64) {
	ids := scan.CVEsOf(scan.Finding{Aliases: aliases})
	m := map[string]scan.Enrichment{}
	for _, id := range ids {
		if e, ok := l.entry(id); ok {
			m[id] = e
		}
	}
	e := scan.CombineEnrichment(m, ids)
	return e.KEV, e.KEVAdded, e.EPSS, e.EPSSPercentile, e.CVSS
}

// LookupFunc is the scan.LookupFunc over the store: each scan loads the KEV
// list and the rows of its own CVEs only.
func LookupFunc(db *sql.DB) scan.LookupFunc {
	return func(cves []string) (map[string]scan.Enrichment, error) {
		l, err := LoadLookup(context.Background(), db, cves)
		if err != nil {
			return nil, err
		}
		out := map[string]scan.Enrichment{}
		for _, c := range cves {
			if e, ok := l.entry(c); ok {
				out[c] = e
			}
		}
		return out, nil
	}
}
