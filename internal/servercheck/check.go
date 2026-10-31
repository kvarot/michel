// Package servercheck ties the server pieces together: one check of a server
// (connection, read-only collection, rules, operating system package
// matching, findings with their statuses), the scheduler that checks the due
// servers one at a time, and the offline rematch of the stored inventories
// after a database update.
//
// Nothing here logs what a server printed: the error output of a command
// (php-fpm -tt can show env[] values) never leaves package collect.
package servercheck

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/collect"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/serverrules"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
	"github.com/kvarot/michel/internal/vulnmatch"
)

const (
	auditActor = "michel"
	// osPackages is the manifest key of the operating system package
	// findings (vulnmatch.Findings).
	osPackages = "os-packages"
)

// CheckDeps are the services a check needs.
type CheckDeps struct {
	Repo  *target.Repo
	Store *store.Store
	// Audit records target.check, target.rematch and the decisions a check
	// supersedes; nil records nothing (tests).
	Audit   *audit.Logger
	SSH     sshx.Deps
	Collect collect.Deps
	// OSVRoot is the folder of the offline databases (osvdb).
	OSVRoot string
	// Sources is the source registry: a distribution database is used only
	// when its source is enabled.
	Sources *source.Repo
	// Rules returns the server rules; nil means serverrules.Rules.
	Rules func() (serverrules.Set, error)
	// Lookup gives the enrichment (KEV, EPSS) of the CVEs of the findings;
	// nil keeps what the stored findings already carry.
	Lookup scan.LookupFunc
	// Alert is told about new grave findings; nil tells no one.
	Alert func(ctx context.Context, a AlertInput)
	Now   func() time.Time
}

func (d CheckDeps) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

func (d CheckDeps) rules() (serverrules.Set, error) {
	if d.Rules != nil {
		return d.Rules()
	}
	return serverrules.Rules()
}

// CheckResult is the outcome of one check (or of the rematch of one server).
//
// Touched tells that the findings were stored: false when the check failed
// before (no connection, host key changed, collection stopped), and then no
// finding changed. Unseen counts what the collection could not read.
// SourceToEnable is the catalog key of the distribution database to turn on
// (or download) so the system packages can be judged. ReleaseKnown is false
// when the packages could not be judged against a database that knows the
// release; Unjudged counts the packages an advisory names whose state could
// not be decided; SkippedAdvisories counts unreadable advisory files. Zero
// findings is clean only when Clean says so.
type CheckResult struct {
	New, Still, Gone  int
	Unseen            int
	SourceToEnable    string
	Touched           bool
	Unjudged          int
	ReleaseKnown      bool
	SkippedAdvisories int
}

// Clean tells that the server was fully judged and nothing is open: the
// findings are stored, the release is known to the database, every package
// was judged, everything was read and no finding is new or still there.
func (r CheckResult) Clean() bool {
	return r.Touched && r.ReleaseKnown && r.Unjudged == 0 && r.Unseen == 0 && r.SourceToEnable == "" &&
		r.SkippedAdvisories == 0 && r.New == 0 && r.Still == 0
}

// Check connects to the server, collects its inventory read only, stores it,
// judges it (rules and distribution advisories) and stores the findings with
// their statuses. A failed connection or collection returns an error and
// changes no finding and no check date. New grave findings go to Alert.
func Check(ctx context.Context, d CheckDeps, targetID string) (CheckResult, error) {
	t, err := d.Repo.Get(ctx, targetID)
	if err != nil {
		return CheckResult{}, err
	}
	links, err := d.Repo.Links(ctx, t.ID)
	if err != nil {
		return CheckResult{}, err
	}
	c, err := sshx.Dial(ctx, d.SSH, t)
	if err != nil {
		return CheckResult{}, fmt.Errorf("cannot connect to server %s: %w", t.Name, err)
	}
	inv, err := collect.Run(ctx, d.Collect, c, t, links)
	if cerr := c.Close(); cerr != nil {
		err = errors.Join(err, cerr)
	}
	if err != nil {
		return CheckResult{}, fmt.Errorf("the check of server %s did not complete: %w", t.Name, err)
	}
	if err := d.Repo.SaveInventory(ctx, inv); err != nil {
		return CheckResult{}, err
	}
	res, err := judge(ctx, d, t, inv)
	if err != nil {
		return res, fmt.Errorf("cannot judge server %s: %w", t.Name, err)
	}
	if err := d.Repo.SetLastCheckAt(ctx, t.ID, d.now()); err != nil {
		return res, err
	}
	d.record(ctx, "target.check", t.ID, res)
	return res, nil
}

// Rematch judges again the latest stored inventory of every active server,
// without connecting to any: a database update can open (or close) findings.
// New grave findings go to Alert. It returns the number of new findings.
// A server whose rematch fails does not stop the others; the errors are
// joined.
func Rematch(ctx context.Context, d CheckDeps) (int, error) {
	all, err := d.Repo.List(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	var errs []error
	for _, t := range all {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		if !t.Active {
			continue
		}
		inv, ok, err := d.Repo.LatestInventory(ctx, t.ID)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !ok {
			continue
		}
		res, err := judge(ctx, d, t, inv)
		if err != nil {
			errs = append(errs, fmt.Errorf("cannot judge server %s again: %w", t.Name, err))
			continue
		}
		total += res.New
		d.record(ctx, "target.rematch", t.ID, res)
	}
	return total, errors.Join(errs...)
}

// judge evaluates inv, stores the findings of t and alerts on the new grave
// ones.
func judge(ctx context.Context, d CheckDeps, t target.Target, inv target.Inventory) (CheckResult, error) {
	res := CheckResult{Unseen: len(inv.Unseen)}
	set, err := d.rules()
	if err != nil {
		return res, err
	}
	m, unread, err := matchPackages(ctx, d, inv, &res)
	if err != nil {
		return res, err
	}
	open := map[string][]string{}
	for _, h := range m.Hits {
		ids := append([]string{h.OSVID}, h.Aliases...)
		for _, b := range h.Binaries {
			open[b] = append(open[b], ids...)
		}
	}
	fs := serverrules.EvaluateWith(t, inv, set, serverrules.Options{DistroOpen: open})
	fs = append(fs, vulnmatch.Findings(t, m)...)
	for _, u := range inv.Unseen {
		if u.Reason == collect.ReasonDirectives {
			// The settings of that binary were not read: absence proves nothing.
			unread = append(unread, "cli:"+u.What, "fpm:"+u.What)
		}
	}
	enriched := d.Lookup != nil
	if enriched {
		var cves []string
		for _, f := range fs {
			for _, c := range scan.CVEsOf(f) {
				if !slices.Contains(cves, c) {
					cves = append(cves, c)
				}
			}
		}
		known, err := d.Lookup(cves)
		if err != nil {
			return res, fmt.Errorf("cannot read the enrichment data (KEV, EPSS): %w", err)
		}
		for i := range fs {
			fs[i] = scan.WithEnrichment(fs[i], scan.CombineEnrichment(known, scan.CVEsOf(fs[i])))
		}
	}
	fresh, superseded, err := storeFindings(ctx, d, t, fs, unread, enriched, &res)
	if err != nil {
		return res, err
	}
	res.Touched = true
	for _, s := range superseded {
		if d.Audit == nil {
			break
		}
		if _, err := d.Audit.Record(context.WithoutCancel(ctx), audit.Event{Actor: auditActor, Action: "decision.superseded", Target: s.FindingID,
			Result: "ok", Evidence: map[string]any{"finding_id": s.FindingID, "project_id": s.ProjectID, "reason": s.Reason, "previous_action": s.Previous}}); err != nil {
			slog.Warn("servercheck: cannot record a superseded decision in the audit log", "err", err)
		}
	}
	alertNew(ctx, d, t, fresh)
	return res, nil
}

// matchPackages matches the system packages of inv against the
// distribution database. unread holds osPackages when they could not be
// judged, so their findings are kept as they are.
func matchPackages(ctx context.Context, d CheckDeps, inv target.Inventory, res *CheckResult) (vulnmatch.Result, []string, error) {
	keep := []string{osPackages}
	eco, ok := vulnmatch.Ecosystem(inv.OS)
	if !ok {
		return vulnmatch.Result{}, keep, nil
	}
	for _, u := range inv.Unseen {
		if u.What == "packages" {
			return vulnmatch.Result{}, keep, nil
		}
	}
	key := vulnmatch.CatalogKey(eco)
	if d.Sources == nil {
		res.SourceToEnable = key
		return vulnmatch.Result{}, keep, nil
	}
	enabled, err := osvdb.Enabled(ctx, d.Sources, nil)
	if err != nil {
		return vulnmatch.Result{}, nil, err
	}
	base, _, _ := strings.Cut(eco, ":")
	if !slices.Contains(enabled, base) {
		res.SourceToEnable = key
		return vulnmatch.Result{}, keep, nil
	}
	m, err := vulnmatch.Match(ctx, d.OSVRoot, eco, inv.Packages)
	var off vulnmatch.ErrSourceDisabled
	switch {
	case errors.As(err, &off):
		res.SourceToEnable = off.Key
		return vulnmatch.Result{}, keep, nil
	case err != nil:
		return vulnmatch.Result{}, nil, err
	}
	res.ReleaseKnown, res.Unjudged, res.SkippedAdvisories = m.ReleaseKnown, len(m.Unjudged), m.Skipped
	if !m.ReleaseKnown {
		// No advisory names this release: absence proves nothing.
		return m, keep, nil
	}
	return m, nil, nil
}

// record writes one audit event with the counts of res only.
func (d CheckDeps) record(ctx context.Context, action, targetID string, res CheckResult) {
	if d.Audit == nil {
		return
	}
	if _, err := d.Audit.Record(context.WithoutCancel(ctx), audit.Event{Actor: auditActor, Action: action, Target: targetID, Result: "ok",
		Evidence: map[string]any{"new": res.New, "still": res.Still, "gone": res.Gone, "unseen": res.Unseen, "unjudged": res.Unjudged,
			"release_known": res.ReleaseKnown, "source_to_enable": res.SourceToEnable}}); err != nil {
		slog.Warn("servercheck: cannot record the check in the audit log", "action", action, "err", err)
	}
}

func newRunID() string { return ulid.Make().String() }
