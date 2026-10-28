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
	srcreg "github.com/kvarot/michel/internal/source"
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

// EmptyReminder is how often the sentence about the projects with nothing to
// scan comes back when their number does not change.
const EmptyReminder = 7 * 24 * time.Hour

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
	// WhatForChannel is What without the call-site example (a relative
	// file:line): what the channels get (ForChannel). Never in JSON.
	WhatForChannel string `json:"-"`
	// Decided is the action of the decision in force on the line's most
	// severe finding when every finding of the line is decided (new findings
	// only), else "".
	Decided string `json:"decided,omitempty"`
}

// Superseded is a decision taken out of force in the window. A decision the
// user replaced (reason "redecided") is never listed.
type Superseded struct {
	Package        string `json:"package"`
	OSVID          string `json:"osv_id"`
	FindingID      string `json:"finding_id"`
	PreviousAction string `json:"previous_action"`
	Reason         string `json:"reason"`
	// Justification is the user's text; it stays out of every rendering.
	Justification string `json:"-"`
	// Severity is the finding's severity label now (critical, high, medium,
	// low or unknown).
	Severity string `json:"severity"`
}

// Due is a deferral in force whose date is within DueHorizon.
type Due struct {
	Package   string `json:"package"`
	OSVID     string `json:"osv_id"`
	FindingID string `json:"finding_id"`
	DueAt     string `json:"due_at"`
	// Justification is the user's text; it stays out of every rendering.
	Justification string `json:"-"`
	// Overdue is true when due_at <= now.
	Overdue bool `json:"overdue"`
	// Severity is the finding's severity label (critical, high, medium, low
	// or unknown).
	Severity string `json:"severity"`
}

// Exploited is an open finding exploited in the wild (on CISA's KEV list)
// or a malicious package: new, pending, or decided "fix". Such findings head
// the digest every day until they are fixed or decided otherwise.
type Exploited struct {
	Project   string `json:"project"`
	Package   string `json:"package"`
	Ecosystem string `json:"ecosystem"`
	OSVID     string `json:"osv_id"`
	FindingID string `json:"finding_id"`
	Installed string `json:"installed"`
	Target    string `json:"target"`
	// Status is the finding's status: new, pending or decided (to be fixed).
	Status    string `json:"status"`
	Malicious bool   `json:"malicious"`
	// KEVAdded is the day CISA listed it (YYYY-MM-DD), "" for a malicious
	// package not on the list.
	KEVAdded string `json:"kev_added"`
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
	// LastScanStatus is ok, partial, failed, interrupted, running, empty
	// (no lockfile to scan) or never.
	LastScanStatus string `json:"last_scan_status"`
	// Attention counts the new critical or high findings not decided yet,
	// the superseded decisions still to review and the due deferrals of the
	// project, and its open findings exploited in the wild or malicious that
	// are not decided yet, whatever their severity (counted once).
	Attention int `json:"attention"`
	// ExploitedDecided counts the findings exploited in the wild or
	// malicious whose decision in force is defer or ignore: the digest
	// recalls them in one line instead of listing them.
	ExploitedDecided int `json:"exploited_decided"`
}

// Digest is what changed between Since and Until.
type Digest struct {
	SchemaVersion int             `json:"michel_digest"`
	Lang          i18n.Lang       `json:"lang"`
	Since         time.Time       `json:"since"`
	Until         time.Time       `json:"until"`
	SinceLabel    string          `json:"since_label,omitempty"`
	Assistant     string          `json:"assistant"`
	Title         string          `json:"title"`
	Word          string          `json:"word,omitempty"`
	Projects      []ProjectDigest `json:"projects"`
	// Exploited heads the digest: the open findings of every project that
	// are exploited in the wild or malicious (see Exploited), whatever the
	// window. ExploitedTotal is its length; ExploitedDecided counts those
	// deferred or ignored, which are not listed.
	Exploited        []Exploited `json:"exploited"`
	ExploitedTotal   int         `json:"exploited_total"`
	ExploitedDecided int         `json:"exploited_decided"`
	NewTotal         int         `json:"new_total"`
	AttentionTotal   int         `json:"attention_total"`
	OSVFetchedAt     time.Time   `json:"osv_fetched_at"`
	OSVStale         bool        `json:"osv_stale"`
	FailedScans      int         `json:"failed_scans"`
	// EmptyProjects counts the projects whose last scan found no lockfile.
	// They are not failures; ShowEmpty says whether the digest mentions
	// them: when their number changed since the last run, or once every
	// EmptyReminder.
	EmptyProjects int    `json:"empty_projects"`
	ShowEmpty     bool   `json:"show_empty"`
	PageURL       string `json:"page_url,omitempty"`
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

// severityLabel maps any stored label to one of severities.
func severityLabel(label string) string { return severities[rank(label)] }

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
	d := Digest{SchemaVersion: SchemaVersion, Lang: lang, Until: now, Assistant: opt.Assistant, PageURL: opt.PageURL, Projects: []ProjectDigest{},
		Exploited: []Exploited{}}
	if d.Assistant == "" {
		d.Assistant = DefaultAssistant
	}
	last, hasLast, err := NewRepo(s).Last(ctx)
	if err != nil {
		return Digest{}, err
	}
	switch {
	case !opt.Since.IsZero():
		d.Since = opt.Since.UTC()
	case hasLast:
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
		pd, newN, attention, exploited, err := c.project(ctx, p)
		if err != nil {
			return Digest{}, err
		}
		d.Projects = append(d.Projects, pd)
		d.Exploited = append(d.Exploited, exploited...)
		d.ExploitedDecided += pd.ExploitedDecided
		d.NewTotal += newN
		d.AttentionTotal += attention
		switch pd.LastScanStatus {
		case scan.ScanFailed, scan.ScanInterrupted:
			d.FailedScans++
		case scan.ScanEmpty:
			d.EmptyProjects++
		}
	}
	if d.ShowEmpty, err = showEmpty(ctx, s, now, d.EmptyProjects, last, hasLast); err != nil {
		return Digest{}, err
	}

	if opt.OSVRoot != "" {
		ecos, err := osvdb.Enabled(ctx, srcreg.NewRepo(s), nil)
		if err != nil {
			return Digest{}, err
		}
		sts, err := osvdb.Statuses(opt.OSVRoot, ecos)
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

	d.ExploitedTotal = len(d.Exploited)
	retitle(&d)
	return d, nil
}

// showEmpty tells whether the digest mentions the n projects with nothing
// to scan: on the first digest, when n differs from the last run's, or when
// no run of the last EmptyReminder mentioned them.
func showEmpty(ctx context.Context, s *store.Store, now time.Time, n int, last Run, hasLast bool) (bool, error) {
	if n == 0 {
		return false, nil
	}
	if !hasLast || last.Summary["empty_projects"] != n {
		return true, nil
	}
	runs, err := NewRepo(s).List(ctx, 100)
	if err != nil {
		return false, err
	}
	for _, r := range runs {
		if now.Sub(r.CreatedAt) > EmptyReminder {
			break
		}
		if r.Summary["show_empty"] == 1 {
			return false, nil
		}
	}
	return true, nil
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
	switch {
	case len(d.Exploited) > 0:
		// The exploited ones are part of the attention count: the title
		// names them instead.
		d.Title += i18n.N(lang, "digest.title.exploited", len(d.Exploited))
	case d.AttentionTotal > 0:
		d.Title += i18n.N(lang, "digest.title.attention", d.AttentionTotal)
	case d.NewTotal == 0:
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
	out.NewTotal, out.AttentionTotal, out.FailedScans, out.EmptyProjects = 0, 0, 0, 0
	out.Exploited, out.ExploitedDecided = []Exploited{}, 0
	for _, e := range d.Exploited {
		if keep[e.Project] {
			out.Exploited = append(out.Exploited, e)
		}
	}
	out.ExploitedTotal = len(out.Exploited)
	for _, p := range d.Projects {
		if !keep[p.Name] {
			continue
		}
		out.Projects = append(out.Projects, p)
		out.ExploitedDecided += p.ExploitedDecided
		for _, pkg := range p.New {
			out.NewTotal += len(pkg.FindingIDs)
		}
		out.AttentionTotal += p.Attention
		switch p.LastScanStatus {
		case scan.ScanFailed, scan.ScanInterrupted:
			out.FailedScans++
		case scan.ScanEmpty:
			out.EmptyProjects++
		}
	}
	out.ShowEmpty = d.ShowEmpty && out.EmptyProjects > 0
	retitle(&out)
	return out
}

// ForChannel returns d as the channels get it (email, webhook, toast): the
// "what" sentences lose their call-site example, so a channel only receives
// projects, counters, packages, versions, advisory ids, due dates and the
// page link. d is not changed.
func ForChannel(d Digest) Digest {
	out := d
	out.Projects = make([]ProjectDigest, len(d.Projects))
	for i, p := range d.Projects {
		if p.New != nil {
			p.New = append([]Package(nil), p.New...)
			for j := range p.New {
				p.New[j].What = p.New[j].WhatForChannel
			}
		}
		out.Projects[i] = p
	}
	return out
}

// computer holds what every project of one digest shares.
type computer struct {
	s          *store.Store
	now, since time.Time
	lang       i18n.Lang
}

// project computes the digest of p, the number of its new findings and of
// the items that need attention (new critical or high, open exploited or
// malicious not decided, superseded, due), and its exploited findings to fix.
func (c computer) project(ctx context.Context, p project.Project) (ProjectDigest, int, int, []Exploited, error) {
	pd := ProjectDigest{Name: scan.SanitizeText(p.Name), Open: map[string]int{}, Decided: map[string]int{}, LastScanStatus: "never"}
	for _, s := range severities {
		pd.Open[s] = 0
	}
	for _, a := range []decide.Action{decide.Fix, decide.Defer, decide.Ignore} {
		pd.Decided[string(a)] = 0
	}
	list, err := scan.NewRepo(c.s).ListFindings(ctx, p.ID, "all")
	if err != nil {
		return ProjectDigest{}, 0, 0, nil, err
	}
	changed, err := c.changedAt(ctx, p.ID)
	if err != nil {
		return ProjectDigest{}, 0, 0, nil, err
	}
	decisions := decide.NewRepo(c.s)
	current, err := decisions.CurrentByProject(ctx, p.ID)
	if err != nil {
		return ProjectDigest{}, 0, 0, nil, err
	}
	byID := map[string]scan.Finding{}
	var fresh, gone []scan.Finding
	var lastCritical time.Time
	attention := 0
	exploited := []Exploited{}
	for _, f := range list {
		byID[f.ID] = f
		label, _ := scan.EffectiveSeverity(f)
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
		dec, decided := current[f.ID]
		counted := false
		if first.After(c.since) {
			fresh = append(fresh, f)
			// A new finding the user already decided on needs no attention.
			if (label == "critical" || label == "high") && !(decided && f.Status == scan.StatusDecided) {
				attention++
				counted = true
			}
		}
		if scan.Urgent(f) {
			open := f.Status == scan.StatusNew || f.Status == scan.StatusPending
			switch {
			case open || (f.Status == scan.StatusDecided && decided && dec.Action == decide.Fix):
				e, err := c.exploited(ctx, pd.Name, f)
				if err != nil {
					return ProjectDigest{}, 0, 0, nil, err
				}
				exploited = append(exploited, e)
				// Exploited in the wild or malicious: it needs attention
				// whatever its severity, until it is decided.
				if open && !counted {
					attention++
				}
			case f.Status == scan.StatusDecided && decided:
				pd.ExploitedDecided++
			}
		}
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
				DueAt: dec.DueAt.UTC().Format(time.RFC3339), Justification: dec.Justification, Overdue: !dec.DueAt.After(c.now), Severity: label})
		}
	}
	pd.CriticalOpen = pd.Open["critical"]
	if pd.New, err = c.packages(ctx, p, fresh, current); err != nil {
		return ProjectDigest{}, 0, 0, nil, err
	}
	if pd.Gone, err = c.packages(ctx, p, gone, nil); err != nil {
		return ProjectDigest{}, 0, 0, nil, err
	}
	sort.SliceStable(pd.Due, func(i, j int) bool {
		if pd.Due[i].DueAt != pd.Due[j].DueAt {
			return pd.Due[i].DueAt < pd.Due[j].DueAt
		}
		return pd.Due[i].FindingID < pd.Due[j].FindingID
	})

	superseded, err := decisions.List(ctx, p.ID, "superseded")
	if err != nil {
		return ProjectDigest{}, 0, 0, nil, err
	}
	for _, dec := range superseded {
		if !dec.SupersededAt.After(c.since) || dec.SupersededReason == decide.Redecided {
			continue
		}
		// The user decided again after the old decision was taken out of
		// force: nothing left to review.
		if cur, ok := current[dec.FindingID]; ok && !cur.CreatedAt.Before(dec.SupersededAt) {
			continue
		}
		f := byID[dec.FindingID]
		pd.Superseded = append(pd.Superseded, Superseded{Package: scan.SanitizeText(f.Package), OSVID: scan.SanitizeText(f.OSVID),
			FindingID: dec.FindingID, PreviousAction: string(dec.Action), Reason: string(dec.SupersededReason), Justification: dec.Justification,
			Severity: severityLabel(effective(f))})
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
		return ProjectDigest{}, 0, 0, nil, err
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
	sort.SliceStable(exploited, func(i, j int) bool {
		a, b := exploited[i], exploited[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.OSVID < b.OSVID
	})
	return pd, len(fresh), attention, exploited, nil
}

// exploited is the head-of-digest line of f, a finding of the project named
// projectName.
func (c computer) exploited(ctx context.Context, projectName string, f scan.Finding) (Exploited, error) {
	target, err := c.target(ctx, f)
	if err != nil {
		return Exploited{}, err
	}
	return Exploited{Project: projectName, Package: scan.SanitizeText(f.Package), Ecosystem: f.Ecosystem,
		OSVID: scan.SanitizeText(f.OSVID), FindingID: f.ID, Installed: scan.SanitizeText(f.InstalledVersion),
		Target: scan.SanitizeText(target), Status: f.Status, Malicious: f.Malicious, KEVAdded: scan.SanitizeText(f.KEVAdded)}, nil
}

// target is the version f should move to: the stored analysis's, else the
// plan from the finding alone.
func (c computer) target(ctx context.Context, f scan.Finding) (string, error) {
	a, has, err := analyze.NewRepo(c.s).Get(ctx, f.ID)
	if err != nil {
		return "", err
	}
	if has {
		return a.Upgrade.Target, nil
	}
	return analyze.PlanUpgrade(f.Ecosystem, f.InstalledVersion, f.FixedVersions, "").Target, nil
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
// severe: it gives the versions and, for new findings (current not nil), the
// "what" sentence and the decision in force.
func (c computer) packages(ctx context.Context, p project.Project, findings []scan.Finding, current map[string]decide.Decision) ([]Package, error) {
	withWhat := current != nil
	decidedAction := func(f scan.Finding) string {
		if dec, ok := current[f.ID]; ok && f.Status == scan.StatusDecided {
			return string(dec.Action)
		}
		return ""
	}
	type key struct{ eco, name string }
	index := map[key]int{}
	var out []Package
	for _, f := range findings {
		k := key{f.Ecosystem, f.Package}
		if i, ok := index[k]; ok {
			out[i].OSVIDs = append(out[i].OSVIDs, scan.SanitizeText(f.OSVID))
			out[i].FindingIDs = append(out[i].FindingIDs, f.ID)
			if decidedAction(f) == "" {
				out[i].Decided = ""
			}
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
		label, _ := scan.EffectiveSeverity(f)
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
			facts.Example = ""
			if e, err = explain.Render(c.lang, facts); err != nil {
				return nil, err
			}
			pkg.WhatForChannel = e.What
			pkg.Decided = decidedAction(f)
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

// effective is the effective severity label of f (scan.EffectiveSeverity).
func effective(f scan.Finding) string {
	l, _ := scan.EffectiveSeverity(f)
	return l
}
