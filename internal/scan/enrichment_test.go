package scan

import (
	"context"
	"slices"
	"testing"
)

// aliasedAdvisories gives ACME-2026-0001 the alias CVE-2026-1001.
var aliasedAdvisories = map[string]string{
	"ACME-2026-0001.json": `{"schema_version": "1.6.0", "id": "ACME-2026-0001", "modified": "2026-10-01T00:00:00Z",
		"aliases": ["GHSA-aaaa-bbbb-cccc", "cve-2026-1001"],
		"summary": "Remote code execution in acme/vuln",
		"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
		"affected": [{"package": {"ecosystem": "Packagist", "name": "acme/vuln"},
			"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}]}`,
}

// fakeLookup answers from known and records the CVEs it was asked about.
type fakeLookup struct {
	known map[string]Enrichment
	asked [][]string
}

func (l *fakeLookup) fn(cves []string) (map[string]Enrichment, error) {
	l.asked = append(l.asked, cves)
	return l.known, nil
}

func (e env) enrichmentOf(t *testing.T, osvID string) (kev int, added string, epss, pct float64) {
	t.Helper()
	if err := e.st.DB().QueryRow(`SELECT kev, kev_added, epss, epss_percentile FROM finding WHERE osv_id = ?`, osvID).
		Scan(&kev, &added, &epss, &pct); err != nil {
		t.Fatal(err)
	}
	return
}

func TestApplyScanWritesKEVFromLookup(t *testing.T) {
	e := newEnv(t, "project-a")
	db := buildOSVDBWith(t, aliasedAdvisories)
	l := &fakeLookup{known: map[string]Enrichment{}}
	scanWith := func(lookup LookupFunc) Result {
		t.Helper()
		r, err := Run(context.Background(), e.deps, e.proj, Options{OSVRoot: db, Lookup: lookup})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	scanWith(l.fn)
	if len(l.asked) != 1 || !slices.Equal(l.asked[0], []string{"CVE-2026-1001"}) {
		t.Fatalf("lookup asked %v, want one call with the CVE of the findings", l.asked)
	}
	if kev, _, _, _ := e.enrichmentOf(t, "ACME-2026-0001"); kev != 0 {
		t.Fatalf("kev = %d before the CVE is listed", kev)
	}
	e.decideFinding(t, "ACME-2026-0001", "ignore", "")

	l.known["CVE-2026-1001"] = Enrichment{KEV: true, KEVAdded: "2026-03-12", EPSS: 0.12, EPSSPercentile: 0.95}
	r := scanWith(l.fn)
	kev, added, epss, pct := e.enrichmentOf(t, "ACME-2026-0001")
	if kev != 1 || added != "2026-03-12" || epss != 0.12 || pct != 0.95 {
		t.Errorf("enrichment = %d %q %v %v", kev, added, epss, pct)
	}
	if r.Superseded != 1 {
		t.Errorf("superseded = %d", r.Superseded)
	}
	if at, reason := e.decisionState(t, "ACME-2026-0001"); at == "" || reason != ReasonKEVChanged {
		t.Errorf("decision: %q %q", at, reason)
	}
	if st := e.statuses(t); st["ACME-2026-0001"] != StatusPending {
		t.Errorf("statuses = %v", st)
	}
	evs := e.supersededEvents(t)
	if len(evs) != 1 || evs[0].evidence["reason"] != ReasonKEVChanged || evs[0].evidence["previous_action"] != "ignore" {
		t.Errorf("events = %+v", evs)
	}

	// Without a lookup the stored enrichment is kept.
	scanWith(nil)
	if kev, added, _, _ := e.enrichmentOf(t, "ACME-2026-0001"); kev != 1 || added != "2026-03-12" {
		t.Errorf("a scan without lookup dropped the enrichment: %d %q", kev, added)
	}
	fs, err := e.repo.ListFindings(context.Background(), e.proj.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 || fs[0].OSVID != "ACME-2026-0001" || !fs[0].KEV || fs[0].KEVAdded != "2026-03-12" || fs[0].EPSSPercentile != 0.95 {
		t.Errorf("first finding read back = %+v", fs[0])
	}
}

func TestSnapshotChangedOnKEV(t *testing.T) {
	fixed := []string{"1.0.1"}
	if changed, reason := SnapshotChanged("high", fixed, false, "high", fixed, true); !changed || reason != ReasonKEVChanged {
		t.Errorf("KEV appeared: %v %q", changed, reason)
	}
	if changed, reason := SnapshotChanged("high", fixed, true, "high", fixed, false); !changed || reason != ReasonKEVChanged {
		t.Errorf("KEV left: %v %q", changed, reason)
	}
	if changed, _ := SnapshotChanged("high", fixed, true, "high", fixed, true); changed {
		t.Error("unchanged KEV counted as a change")
	}
	// KEV is compared last.
	if _, reason := SnapshotChanged("high", fixed, false, "critical", fixed, true); reason != ReasonSeverityChanged {
		t.Errorf("severity and KEV: %q", reason)
	}
	if _, reason := SnapshotChanged("high", fixed, false, "high", []string{"1.0.2"}, true); reason != ReasonFixedVersionChanged {
		t.Errorf("fixed and KEV: %q", reason)
	}
}

func TestEffectiveSeverityUsesEnrichedCVSSOnlyWhenUnknown(t *testing.T) {
	cases := []struct {
		f             Finding
		label, source string
	}{
		{Finding{SeverityLabel: "unknown", CVSSEnriched: 9.8}, "critical", SeverityFromEnrichment},
		{Finding{SeverityLabel: "unknown", CVSSEnriched: 5}, "medium", SeverityFromEnrichment},
		{Finding{SeverityLabel: "unknown"}, "unknown", SeverityFromOSV},
		{Finding{SeverityLabel: "low", CVSS: 2, CVSSEnriched: 9.8}, "low", SeverityFromOSV},
		{Finding{SeverityLabel: "high", CVSS: 7.5}, "high", SeverityFromOSV},
		{Finding{SeverityLabel: "low", Malicious: true}, "critical", SeverityFromMalicious},
	}
	for _, c := range cases {
		if l, s := EffectiveSeverity(c.f); l != c.label || s != c.source {
			t.Errorf("EffectiveSeverity(%+v) = %s %s, want %s %s", c.f, l, s, c.label, c.source)
		}
	}
}

func TestCVEsOfAndCombine(t *testing.T) {
	f := Finding{OSVID: "GHSA-x", Aliases: []string{"GHSA-y", "cve-2024-1", "CVE-2024-0002", "CVE-2024-1", "CVE-24-1", "CVE-2024-12a"}}
	got := CVEsOf(f)
	if !slices.Equal(got, []string{"CVE-2024-1", "CVE-2024-0002"}) {
		t.Fatalf("CVEsOf = %v", got)
	}
	m := map[string]Enrichment{
		"CVE-2024-1":    {EPSS: 0.1, EPSSPercentile: 0.5, CVSS: 5},
		"CVE-2024-0002": {KEV: true, KEVAdded: "2024-05-01", EPSS: 0.4, EPSSPercentile: 0.9, CVSS: 4},
	}
	e := CombineEnrichment(m, got)
	if !e.KEV || e.KEVAdded != "2024-05-01" || e.EPSS != 0.4 || e.EPSSPercentile != 0.9 || e.CVSS != 5 {
		t.Errorf("combined = %+v", e)
	}
}
