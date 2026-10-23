// Package digest computes what changed since the last digest ("since
// yesterday") over every active project, and renders it as text, HTML or
// JSON. Computing reads the store and never writes to it; the CLI records a
// sent digest as a run (repo.go).
//
// A digest never holds code, absolute paths, the project's declared commands
// or secrets: only project names, packages, versions, advisory ids, counters
// and plain-language sentences.
package digest

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/explain"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/store"
)

// SchemaVersion is the version of the JSON rendering ("michel_digest").
const SchemaVersion = 1

// DueHorizon is how far ahead a deferral's date is listed.
const DueHorizon = 3 * 24 * time.Hour

// DefaultWindow is the window of the first digest, when no run was saved.
const DefaultWindow = 24 * time.Hour

// LabelWindow is the window beyond which the digest says since when it counts.
const LabelWindow = 36 * time.Hour

// StaleAfter is the age beyond which the offline database is called stale.
const StaleAfter = 7 * 24 * time.Hour

// DefaultAssistant is the assistant's name when the policy gives none.
const DefaultAssistant = "Michel"

// Package is the findings of one package, shown on one line.
type Package struct {
	Name          string   `json:"name"`
	Ecosystem     string   `json:"ecosystem"`
	Installed     string   `json:"installed"`
	Target        string   `json:"target"`
	WorstSeverity string   `json:"worst_severity"`
	OSVIDs        []string `json:"osv_ids"`
	FindingIDs    []string `json:"finding_ids"`
	// What is the "what" sentence of the most severe finding, in the
	// digest's language (new findings only).
	What string `json:"what,omitempty"`
}

// Superseded is a decision taken out of force in the window. A decision the
// user replaced (reason "redecided") is never listed.
type Superseded struct {
	Package        string `json:"package"`
	OSVID          string `json:"osv_id"`
	FindingID      string `json:"finding_id"`
	PreviousAction string `json:"previous_action"`
	Reason         string `json:"reason"`
	Justification  string `json:"justification"`
}

// Due is a deferral in force whose date is within DueHorizon.
type Due struct {
	Package       string `json:"package"`
	OSVID         string `json:"osv_id"`
	FindingID     string `json:"finding_id"`
	DueAt         string `json:"due_at"`
	Justification string `json:"justification"`
	// Overdue is true when due_at <= now.
	Overdue bool `json:"overdue"`
}

// ProjectDigest is the digest of one active project.
type ProjectDigest struct {
	Name       string       `json:"name"`
	New        []Package    `json:"new,omitempty"`
	Gone       []Package    `json:"gone,omitempty"`
	Superseded []Superseded `json:"superseded,omitempty"`
	Due        []Due        `json:"due,omitempty"`
	// ProvenFixed and ReportedFixed stay empty until fixes are tracked.
	ProvenFixed   []Package `json:"proven_fixed,omitempty"`
	ReportedFixed []Package `json:"reported_fixed,omitempty"`
	// Open counts the open findings (new, pending, decided fix or defer) by
	// severity; Decided counts the decisions in force by action; Total is
	// the open findings plus the ignored ones.
	Open                map[string]int `json:"open"`
	Decided             map[string]int `json:"decided"`
	Total               int            `json:"total"`
	DaysWithoutCritical int            `json:"days_without_critical"`
	CriticalOpen        int            `json:"critical_open"`
	// LastScanStatus is ok, partial, failed, interrupted, running or never.
	LastScanStatus string `json:"last_scan_status"`
	// Attention counts the new critical or high findings, the superseded
	// decisions and the due deferrals of the project.
	Attention int `json:"attention"`
}

// Digest is what changed between Since and Until.
type Digest struct {
	SchemaVersion  int             `json:"michel_digest"`
	Lang           i18n.Lang       `json:"lang"`
	Since          time.Time       `json:"since"`
	Until          time.Time       `json:"until"`
	SinceLabel     string          `json:"since_label,omitempty"`
	Assistant      string          `json:"assistant"`
	Title          string          `json:"title"`
	Word           string          `json:"word,omitempty"`
	Projects       []ProjectDigest `json:"projects"`
	NewTotal       int             `json:"new_total"`
	AttentionTotal int             `json:"attention_total"`
	OSVFetchedAt   time.Time       `json:"osv_fetched_at"`
	OSVStale       bool            `json:"osv_stale"`
	FailedScans    int             `json:"failed_scans"`
	PageURL        string          `json:"page_url,omitempty"`
}

// Options tunes Compute.
type Options struct {
	// Since starts the window; zero means the until of the last saved run,
	// else now minus DefaultWindow. There is no cap.
	Since     time.Time
	PageURL   string
	Assistant string
	// OSVRoot is the folder of the offline databases; "" skips freshness.
	OSVRoot string
}

// severities are the severity labels, most severe first.
var severities = []string{"critical", "high", "medium", "low", "unknown"}

func rank(label string) int {
	for i, s := range severities {
		if s == label {
			return i
		}
	}
	return len(severities) - 1
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// dateLayout is the Go layout of a calendar day in lang.
func dateLayout(lang i18n.Lang) string { return i18n.T(lang, "digest.date_layout") }

// Compute is pure: it reads the store and never writes (no status change, no audit event).
func Compute(ctx context.Context, s *store.Store, now time.Time, lang i18n.Lang, opt Options) (Digest, error) {
	if !lang.Valid() {
		return Digest{}, fmt.Errorf("language %q is not supported (use en or fr)", lang)
	}
	now = now.UTC()
	d := Digest{SchemaVersion: SchemaVersion, Lang: lang, Until: now, Assistant: opt.Assistant, PageURL: opt.PageURL, Projects: []ProjectDigest{}}
	if d.Assistant == "" {
		d.Assistant = DefaultAssistant
	}
	switch last, ok, err := NewRepo(s).Last(ctx); {
	case !opt.Since.IsZero():
		d.Since = opt.Since.UTC()
	case err != nil:
		return Digest{}, err
	case ok:
		d.Since = last.Until.UTC()
	default:
		d.Since = now.Add(-DefaultWindow)
	}
	if now.Sub(d.Since) > LabelWindow {
		d.SinceLabel = i18n.T(lang, "digest.since_label", d.Since.Format(dateLayout(lang)))
	}

	projects, err := project.NewRepo(s).List(ctx)
	if err != nil {
		return Digest{}, err
	}
	c := computer{s: s, now: now, since: d.Since, lang: lang}
	for _, p := range projects {
		if !p.Active {
			continue
		}
		pd, newN, attention, err := c.project(ctx, p)
		if err != nil {
			return Digest{}, err
		}
		d.Projects = append(d.Projects, pd)
		d.NewTotal += newN
		d.AttentionTotal += attention
		if pd.LastScanStatus == scan.ScanFailed || pd.LastScanStatus == scan.ScanInterrupted {
			d.FailedScans++
		}
	}

	if opt.OSVRoot != "" {
		sts, err := osvdb.Statuses(opt.OSVRoot)
		if err != nil {
			return Digest{}, err
		}
		for _, st := range sts {
			if st.Present && !st.FetchedAt.IsZero() && (d.OSVFetchedAt.IsZero() || st.FetchedAt.Before(d.OSVFetchedAt)) {
				d.OSVFetchedAt = st.FetchedAt.UTC()
			}
		}
		d.OSVStale = !d.OSVFetchedAt.IsZero() && now.Sub(d.OSVFetchedAt) > StaleAfter
	}

	retitle(&d)
	return d, nil
}

// retitle sets d's title and word from its counters.
func retitle(d *Digest) {
	lang := d.Lang
	if d.NewTotal > 0 {
		d.Title = i18n.N(lang, "digest.title.new", d.NewTotal, d.Assistant)
	} else {
		d.Title = i18n.T(lang, "digest.title.nothing_new", d.Assistant)
	}
	d.Word = ""
	if d.AttentionTotal > 0 {
		d.Title += i18n.N(lang, "digest.title.attention", d.AttentionTotal)
	} else if d.NewTotal == 0 {
		d.Word = i18n.T(lang, "digest.word.calm")
	}
}

// Filter returns d restricted to the projects named in names, with its
// counters (new, attention, failed scans), title and word recomputed. An
// empty names keeps d as it is. d is not changed.
func Filter(d Digest, names []string) Digest {
	if len(names) == 0 {
		return d
	}
	keep := map[string]bool{}
	for _, n := range names {
		keep[n] = true
	}
	out := d
	out.Projects = []ProjectDigest{}
	out.NewTotal, out.AttentionTotal, out.FailedScans = 0, 0, 0
	for _, p := range d.Projects {
		if !keep[p.Name] {
			continue
		}
		out.Projects = append(out.Projects, p)
		for _, pkg := range p.New {
			out.NewTotal += len(pkg.FindingIDs)
		}
		out.AttentionTotal += p.Attention
		if p.LastScanStatus == scan.ScanFailed || p.LastScanStatus == scan.ScanInterrupted {
			out.FailedScans++
		}
	}
	retitle(&out)
	return out
}

// computer holds what every project of one digest shares.
type computer struct {
	s          *store.Store
	now, since time.Time
	lang       i18n.Lang
}

// project computes the digest of p, the number of its new findings and of
// the items that need attention (new critical or high, superseded, due).
func (c computer) project(ctx context.Context, p project.Project) (ProjectDigest, int, int, error) {
	pd := ProjectDigest{Name: scan.SanitizeText(p.Name), Open: map[string]int{}, Decided: map[string]int{}, LastScanStatus: "never"}
	for _, s := range severities {
		pd.Open[s] = 0
	}
	for _, a := range []decide.Action{decide.Fix, decide.Defer, decide.Ignore} {
		pd.Decided[string(a)] = 0
	}
	list, err := scan.NewRepo(c.s).ListFindings(ctx, p.ID, "all")
	if err != nil {
		return ProjectDigest{}, 0, 0, err
	}
	changed, err := c.changedAt(ctx, p.ID)
	if err != nil {
		return ProjectDigest{}, 0, 0, err
	}
	decisions := decide.NewRepo(c.s)
	current, err := decisions.CurrentByProject(ctx, p.ID)
	if err != nil {
		return ProjectDigest{}, 0, 0, err
	}
	byID := map[string]scan.Finding{}
	var fresh, gone []scan.Finding
	var lastCritical time.Time
	attention := 0
	for _, f := range list {
		byID[f.ID] = f
		label := f.SeverityLabel
		if rank(label) == len(severities)-1 {
			label = "unknown"
		}
		first := parseTime(f.FirstSeenAt)
		if label == "critical" && first.After(lastCritical) {
			lastCritical = first
		}
		if f.Status == scan.StatusGone {
			if changed[f.ID].After(c.since) {
				gone = append(gone, f)
			}
			continue
		}
		if first.After(c.since) {
			fresh = append(fresh, f)
			if label == "critical" || label == "high" {
				attention++
			}
		}
		dec, decided := current[f.ID]
		if f.Status == scan.StatusDecided && decided {
			pd.Decided[string(dec.Action)]++
			if dec.Action == decide.Ignore {
				pd.Total++
				continue
			}
		}
		pd.Open[label]++
		pd.Total++
		if decided && dec.Action == decide.Defer && f.Status == scan.StatusDecided && !dec.DueAt.After(c.now.Add(DueHorizon)) {
			pd.Due = append(pd.Due, Due{Package: scan.SanitizeText(f.Package), OSVID: scan.SanitizeText(f.OSVID), FindingID: f.ID,
				DueAt: dec.DueAt.UTC().Format(time.RFC3339), Justification: dec.Justification, Overdue: !dec.DueAt.After(c.now)})
		}
	}
	pd.CriticalOpen = pd.Open["critical"]
	if pd.New, err = c.packages(ctx, p, fresh, true); err != nil {
		return ProjectDigest{}, 0, 0, err
	}
	if pd.Gone, err = c.packages(ctx, p, gone, false); err != nil {
		return ProjectDigest{}, 0, 0, err
	}
	sort.SliceStable(pd.Due, func(i, j int) bool {
		if pd.Due[i].DueAt != pd.Due[j].DueAt {
			return pd.Due[i].DueAt < pd.Due[j].DueAt
		}
		return pd.Due[i].FindingID < pd.Due[j].FindingID
	})

	superseded, err := decisions.List(ctx, p.ID, "superseded")
	if err != nil {
		return ProjectDigest{}, 0, 0, err
	}
	for _, dec := range superseded {
		if !dec.SupersededAt.After(c.since) || dec.SupersededReason == decide.Redecided {
			continue
		}
		f := byID[dec.FindingID]
		pd.Superseded = append(pd.Superseded, Superseded{Package: scan.SanitizeText(f.Package), OSVID: scan.SanitizeText(f.OSVID),
			FindingID: dec.FindingID, PreviousAction: string(dec.Action), Reason: string(dec.SupersededReason), Justification: dec.Justification})
	}
	sort.SliceStable(pd.Superseded, func(i, j int) bool {
		a, b := pd.Superseded[i], pd.Superseded[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.OSVID < b.OSVID
	})
	attention += len(pd.Superseded) + len(pd.Due)
	pd.Attention = attention

	first, status, err := c.scans(ctx, p.ID)
	if err != nil {
		return ProjectDigest{}, 0, 0, err
	}
	if status != "" {
		pd.LastScanStatus = status
	}
	from := lastCritical
	if from.IsZero() {
		from = first
	}
	if !from.IsZero() && c.now.After(from) {
		pd.DaysWithoutCritical = int(c.now.Sub(from) / (24 * time.Hour))
	}
	return pd, len(fresh), attention, nil
}

// changedAt maps finding id -> status_changed_at for the project.
func (c computer) changedAt(ctx context.Context, projectID string) (map[string]time.Time, error) {
	rows, err := c.s.DB().QueryContext(ctx, `SELECT id, status_changed_at FROM finding WHERE project_id = ?`, projectID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the findings: %w", err)
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id, at string
		if err := rows.Scan(&id, &at); err != nil {
			return nil, err
		}
		out[id] = parseTime(at)
	}
	return out, rows.Err()
}

// scans returns when the project was first scanned and the status of its
// newest scan ("" when never scanned).
func (c computer) scans(ctx context.Context, projectID string) (time.Time, string, error) {
	var first string
	if err := c.s.DB().QueryRowContext(ctx, `SELECT COALESCE(MIN(started_at), '') FROM scan WHERE project_id = ?`, projectID).Scan(&first); err != nil {
		return time.Time{}, "", fmt.Errorf("cannot read the scans: %w", err)
	}
	if first == "" {
		return time.Time{}, "", nil
	}
	var status string
	if err := c.s.DB().QueryRowContext(ctx, `SELECT status FROM scan WHERE project_id = ? ORDER BY started_at DESC, id DESC LIMIT 1`,
		projectID).Scan(&status); err != nil {
		return time.Time{}, "", fmt.Errorf("cannot read the scans: %w", err)
	}
	return parseTime(first), status, nil
}

// packages groups findings (most severe first, as ListFindings returns
// them) by (ecosystem, package). The first finding of a group is its most
// severe: it gives the versions and, when withWhat, the "what" sentence.
func (c computer) packages(ctx context.Context, p project.Project, findings []scan.Finding, withWhat bool) ([]Package, error) {
	type key struct{ eco, name string }
	index := map[key]int{}
	var out []Package
	for _, f := range findings {
		k := key{f.Ecosystem, f.Package}
		if i, ok := index[k]; ok {
			out[i].OSVIDs = append(out[i].OSVIDs, scan.SanitizeText(f.OSVID))
			out[i].FindingIDs = append(out[i].FindingIDs, f.ID)
			continue
		}
		a, has, err := analyze.NewRepo(c.s).Get(ctx, f.ID)
		if err != nil {
			return nil, err
		}
		target := a.Upgrade.Target
		if !has {
			target = analyze.PlanUpgrade(f.Ecosystem, f.InstalledVersion, f.FixedVersions, "").Target
		}
		label := f.SeverityLabel
		if rank(label) == len(severities)-1 {
			label = "unknown"
		}
		pkg := Package{Name: scan.SanitizeText(f.Package), Ecosystem: f.Ecosystem, Installed: scan.SanitizeText(f.InstalledVersion),
			Target: scan.SanitizeText(target), WorstSeverity: label, OSVIDs: []string{scan.SanitizeText(f.OSVID)}, FindingIDs: []string{f.ID}}
		if withWhat {
			facts := explain.FactsFrom(f, a, has)
			facts.FixLevel = p.FixLevel
			e, err := explain.Render(c.lang, facts)
			if err != nil {
				return nil, err
			}
			pkg.What = e.What
		}
		index[k] = len(out)
		out = append(out, pkg)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := rank(out[i].WorstSeverity), rank(out[j].WorstSeverity); ri != rj {
			return ri < rj
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Ecosystem < out[j].Ecosystem
	})
	return out, nil
}
