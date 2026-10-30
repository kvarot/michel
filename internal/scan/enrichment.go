package scan

import (
	"fmt"
	"slices"
	"strings"
)

// Enrichment is what the enrichment sources (CISA KEV, FIRST EPSS, CVE
// records) know about one CVE.
type Enrichment struct {
	// KEV is true when the CVE is on CISA's Known Exploited Vulnerabilities
	// list; KEVAdded is the day CISA added it (YYYY-MM-DD).
	KEV      bool
	KEVAdded string
	// EPSS is FIRST's probability of exploitation within 30 days (0..1) and
	// EPSSPercentile the share of scored CVEs below it (0..1).
	EPSS, EPSSPercentile float64
	// CVSS is a base score read from a CVE record, 0 when none.
	CVSS float64
}

// LookupFunc returns the enrichment of each of cves that the sources know
// (CVEs they know nothing about are absent from the map). Package enrich
// implements it over the store; it is a function so that a scan loads only
// the rows of its own CVEs, never the whole EPSS table.
type LookupFunc func(cves []string) (map[string]Enrichment, error)

// IsCVE tells whether id looks like a CVE identifier (CVE-YYYY-N...), in any
// case.
func IsCVE(id string) bool {
	id = strings.ToUpper(strings.TrimSpace(id))
	if len(id) < len("CVE-2000-0") || len(id) > 32 || !strings.HasPrefix(id, "CVE-") || id[8] != '-' {
		return false
	}
	for i, r := range id[4:] {
		if i == 4 {
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// CVEsOf lists the CVE identifiers of f, upper-case, without duplicates: its
// OSV id when it is one, then its aliases, in order.
func CVEsOf(f Finding) []string {
	out := []string{}
	for _, id := range append([]string{f.OSVID}, f.Aliases...) {
		if !IsCVE(id) {
			continue
		}
		id = strings.ToUpper(strings.TrimSpace(id))
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// CombineEnrichment merges what m knows about the CVEs of ids (as CVEsOf
// returns them) into one: KEV when any of them is listed, with the date of
// the first listed; the highest EPSS (with its percentile) and the highest
// CVSS.
func CombineEnrichment(m map[string]Enrichment, ids []string) Enrichment {
	var out Enrichment
	for _, id := range ids {
		e, ok := m[id]
		if !ok {
			continue
		}
		if e.KEV && !out.KEV {
			out.KEV, out.KEVAdded = true, e.KEVAdded
		}
		if e.EPSS > out.EPSS {
			out.EPSS, out.EPSSPercentile = e.EPSS, e.EPSSPercentile
		}
		if e.CVSS > out.CVSS {
			out.CVSS = e.CVSS
		}
	}
	return out
}

// WithEnrichment returns f carrying e.
func WithEnrichment(f Finding, e Enrichment) Finding {
	f.KEV, f.KEVAdded, f.EPSS, f.EPSSPercentile, f.CVSSEnriched = e.KEV, e.KEVAdded, e.EPSS, e.EPSSPercentile, e.CVSS
	return f
}

// Severity sources, as EffectiveSeverity returns them.
const (
	SeverityFromOSV        = "osv"
	SeverityFromEnrichment = "enrichment"
	SeverityFromMalicious  = "malicious"
)

// EffectiveSeverity is the severity Michel shows and sorts by, with where it
// comes from. A malicious package is critical ("malicious"). An advisory
// without a severity ("unknown") takes the label of the enriched CVSS when
// there is one ("enrichment"). Otherwise it is the stored OSV label ("osv"):
// the stored label stays the OSV snapshot decisions compare against.
func EffectiveSeverity(f Finding) (label string, source string) {
	if f.Malicious {
		return "critical", SeverityFromMalicious
	}
	if f.SeverityLabel == "unknown" && f.CVSSEnriched > 0 {
		l, _ := SeverityLabel(fmt.Sprintf("%g", f.CVSSEnriched))
		return l, SeverityFromEnrichment
	}
	return f.SeverityLabel, SeverityFromOSV
}

// Urgent tells whether f is exploited in the wild (KEV) or a malicious
// package: it is listed first and must be fixed first.
func Urgent(f Finding) bool { return f.KEV || f.Malicious }
