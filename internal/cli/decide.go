package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/spf13/cobra"
)

// decideAuthor is the author stored for decisions taken on the command line.
const decideAuthor = "cli"

// maxForDays bounds --for so the date stays representable.
const maxForDays = 36500

var (
	forPattern      = regexp.MustCompile(`^([0-9]+)d$`)
	decisionFilters = []string{"fix", "defer", "ignore", "superseded", "all"}
)

// dayText is the calendar day of t in UTC, the way dates are shown.
func dayText(t time.Time) string { return t.UTC().Format("2006-01-02") }

// oneLine turns stored free text into one table- and sentence-friendly line.
func oneLine(s string) string {
	return strings.Join(strings.Fields(safe(s)), " ")
}

// parseDue reads --until / --for for action. defaulted means a defer with
// neither, which Validate turns into decide.DefaultDefer.
func parseDue(deps *Deps, action decide.Action, until, forDays string, now time.Time) (due time.Time, defaulted bool, err error) {
	until, forDays = strings.TrimSpace(until), strings.TrimSpace(forDays)
	if until != "" && forDays != "" {
		return time.Time{}, false, deps.Errorf("cli.decide.until_and_for")
	}
	if (until != "" || forDays != "") && action != decide.Defer {
		return time.Time{}, false, deps.Errorf("cli.decide.date_not_defer")
	}
	switch {
	case until != "":
		t, err := time.Parse("2006-01-02", until)
		if err != nil {
			return time.Time{}, false, deps.Errorf("cli.decide.bad_until", until)
		}
		return t, false, nil
	case forDays != "":
		m := forPattern.FindStringSubmatch(forDays)
		if m == nil {
			return time.Time{}, false, deps.Errorf("cli.decide.bad_for", forDays)
		}
		n, err := strconv.Atoi(m[1])
		if err != nil || n < 1 || n > maxForDays {
			return time.Time{}, false, deps.Errorf("cli.decide.bad_for", forDays)
		}
		return now.Add(time.Duration(n) * 24 * time.Hour).Truncate(time.Second), false, nil
	}
	return time.Time{}, action == decide.Defer, nil
}

// validationError explains a decide.Validate refusal in the user's language.
func validationError(deps *Deps, d decide.Decision, why string, err error) error {
	switch {
	case errors.Is(err, decide.ErrJustificationRequired):
		return deps.Errorf("cli.decide.why_required")
	case errors.Is(err, decide.ErrJustificationTooLong):
		n := utf8.RuneCountInString(strings.TrimSpace(scan.SanitizeText(why)))
		return deps.Errorf("cli.decide.why_too_long", n, decide.MaxJustification)
	case errors.Is(err, decide.ErrDueInPast):
		return deps.Errorf("cli.decide.due_in_past", dayText(d.DueAt))
	}
	return err
}

// decideOne stores d on the finding fi of project p and writes its audit
// events: decision.superseded for the decision it replaces, then
// decision.set. It returns the stored decision, the one it replaced (if
// any) and the decision.set event id.
func decideOne(ctx context.Context, deps *Deps, repo *decide.Repo, d decide.Decision, fi scan.Finding, p project.Project) (decide.Decision, *decide.Decision, string, error) {
	pkg, osv := safe(fi.Package), safe(fi.OSVID)
	if err := decide.ValidateFor(fi, &d, deps.Now()); errors.Is(err, decide.ErrNoFixForExposure) {
		return decide.Decision{}, nil, "", deps.Errorf("cli.decide.exposure_no_fix")
	}
	d.FindingID = fi.ID
	stored, replaced, evID, err := decide.Apply(ctx, repo, deps.Audit, decideAuthor, d, fi.Package, fi.OSVID, deps.Now())
	var auditErr *decide.AuditError
	switch {
	case err == nil:
		return stored, replaced, evID, nil
	case errors.As(err, &auditErr):
		return stored, replaced, "", deps.Wrapf("cli.decide.audit_failed", auditErr.Err, pkg, osv)
	case errors.Is(err, decide.ErrFindingGone):
		return decide.Decision{}, nil, "", deps.Errorf("cli.decide.gone", pkg, osv, p.Name)
	}
	return decide.Decision{}, nil, "", deps.Wrapf("cli.decide.failed", err, pkg, osv)
}

// dueSentence says until when a defer holds, and whether the date is the default.
func dueSentence(deps *Deps, d decide.Decision, defaulted, plural bool) string {
	switch {
	case plural && defaulted:
		return deps.T("cli.decide.package_due_default", dayText(d.DueAt))
	case plural:
		return deps.T("cli.decide.package_due", dayText(d.DueAt))
	case defaulted:
		return deps.T("cli.decide.due_default", dayText(d.DueAt))
	}
	return deps.T("cli.decide.due", dayText(d.DueAt))
}

// decidedSentence is the one sentence saying what a decision on one finding did.
func decidedSentence(deps *Deps, d decide.Decision, replaced *decide.Decision, fi scan.Finding, p project.Project, defaulted bool) string {
	pkg, osv := safe(fi.Package), safe(fi.OSVID)
	var s string
	switch d.Action {
	case decide.Fix:
		s = deps.T("cli.decide.done.fix", pkg, osv, p.Name)
	case decide.Defer:
		s = deps.T("cli.decide.done.defer", pkg, osv, p.Name) + " " + dueSentence(deps, d, defaulted, false)
	default:
		s = deps.T("cli.decide.done.ignore", pkg, osv, p.Name, strings.TrimRight(oneLine(d.Justification), "."))
	}
	if replaced != nil {
		s += " " + deps.T("cli.decide.replaced", string(replaced.Action))
	}
	return s
}

func newDecideCmd(deps *Deps) *cobra.Command {
	var projectName, pkg, why, until, forDays string
	var force, verbose bool
	c := &cobra.Command{
		Use:   "decide <id-or-prefix> <fix|defer|ignore>",
		Short: "Decide what to do about a finding: fix, defer or ignore",
		Long: "Decide records what you will do about a finding: fix (you will update the package), defer (later, by default in 30 days) " +
			"or ignore (it does not matter to you; --why is required). The finding then leaves the list of findings to handle. " +
			"Michel asks again when the advisory changes (severity or fixed versions) or when a deferral date is reached. " +
			"With --project and --package, the decision applies to every finding of that package in the project that waits for a decision. " +
			"Every decision is written to the audit log; the project folder is never touched.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			byPackage := strings.TrimSpace(pkg) != ""
			if byPackage && projectName == "" {
				return deps.Errorf("cli.decide.package_needs_project")
			}
			var actionArg string
			switch {
			case byPackage && len(args) == 1:
				actionArg = args[0]
			case !byPackage && projectName == "" && len(args) == 2:
				actionArg = args[1]
			default:
				return deps.Errorf("cli.decide.usage")
			}
			action := decide.Action(strings.ToLower(strings.TrimSpace(actionArg)))
			if action != decide.Fix && action != decide.Defer && action != decide.Ignore {
				return deps.Errorf("cli.decide.unknown_action", actionArg)
			}
			now := deps.Now()
			due, defaulted, err := parseDue(deps, action, until, forDays, now)
			if err != nil {
				return err
			}
			d := decide.Decision{Action: action, Justification: why, DueAt: due, Author: decideAuthor}
			if err := decide.Validate(&d, now); err != nil {
				return validationError(deps, d, why, err)
			}
			repo := decide.NewRepo(deps.Store)
			if byPackage {
				return decidePackage(ctx, deps, repo, d, projectName, strings.TrimSpace(pkg), force, defaulted, verbose)
			}
			fi, p, err := resolveFinding(ctx, deps, args[0])
			if err != nil {
				return err
			}
			stored, replaced, evID, err := decideOne(ctx, deps, repo, d, fi, p)
			if err != nil {
				return err
			}
			fmt.Fprintln(deps.Stdout, decidedSentence(deps, stored, replaced, fi, p, defaulted))
			fmt.Fprintln(deps.Stdout, deps.T("cli.decide.audit_event", evID))
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&why, "why", "", "why you decide this (required for ignore, at most 1000 characters); kept in the audit log")
	f.StringVar(&until, "until", "", "for defer: the date to ask again, as YYYY-MM-DD")
	f.StringVar(&forDays, "for", "", "for defer: how long to wait, as a number of days such as 30d (default 30d)")
	f.StringVar(&projectName, "project", "", "with --package: the project whose findings to decide on")
	f.StringVar(&pkg, "package", "", "decide on every finding of this package in --project that waits for a decision")
	f.BoolVar(&force, "force", false, "with --package: also decide again on findings already decided")
	f.BoolVar(&verbose, "verbose", false, "with --package: print one line per finding with its audit event instead of the summary")
	return c
}

// decidePackage applies d to every finding of pkg in the project that waits
// for a decision (new or pending), and to decided ones with force.
func decidePackage(ctx context.Context, deps *Deps, repo *decide.Repo, d decide.Decision, projectName, pkg string, force, defaulted, verbose bool) error {
	p, err := projectRepo(deps).GetActive(ctx, projectName)
	if err != nil {
		if errors.Is(err, project.ErrNotFound) {
			return deps.Errorf("cli.decide.project_not_found", projectName)
		}
		return err
	}
	all, err := scan.NewRepo(deps.Store).ListFindings(ctx, p.ID, "all")
	if err != nil {
		return err
	}
	var targets []scan.Finding
	for _, f := range all {
		if f.Package != pkg {
			continue
		}
		if f.Status == scan.StatusNew || f.Status == scan.StatusPending || (force && f.Status == scan.StatusDecided) {
			targets = append(targets, f)
		}
	}
	if len(targets) == 0 {
		return deps.Errorf("cli.decide.package_none", safe(pkg), p.Name, p.Name)
	}
	type done struct{ osv, event string }
	var items []done
	var last decide.Decision
	for _, f := range targets {
		stored, _, evID, err := decideOne(ctx, deps, repo, d, f, p)
		if err != nil {
			return err
		}
		last = stored
		items = append(items, done{safe(f.OSVID), evID})
	}
	if verbose {
		s := deps.N("cli.decide.package_done", len(items), string(d.Action), safe(pkg), p.Name)
		if d.Action == decide.Defer {
			s += " " + dueSentence(deps, last, defaulted, len(items) > 1)
		}
		fmt.Fprintln(deps.Stdout, s)
		for _, it := range items {
			fmt.Fprintln(deps.Stdout, deps.T("cli.decide.package_item", it.osv, it.event))
		}
		return nil
	}
	n := len(items)
	var action string
	switch {
	case d.Action == decide.Fix:
		action = deps.N("cli.decide.package_action.fix", n)
	case d.Action == decide.Defer && defaulted:
		action = deps.N("cli.decide.package_action.defer_default", n, dayText(last.DueAt))
	case d.Action == decide.Defer:
		action = deps.N("cli.decide.package_action.defer", n, dayText(last.DueAt))
	default:
		action = deps.N("cli.decide.package_action.ignore", n)
	}
	events := items[0].event
	if n > 1 {
		events += " → " + items[n-1].event
	}
	fmt.Fprintln(deps.Stdout, deps.N("cli.decide.package_summary", n, safe(pkg), action, p.Name, events))
	return nil
}

func newDecisionsCmd(deps *Deps) *cobra.Command {
	var name, status string
	c := &cobra.Command{
		Use:   "decisions",
		Short: "List the decisions taken on the findings of a project",
		Long: "Decisions lists the decisions in force on the findings of a project, newest first. " +
			"--status narrows them to one action (fix, defer, ignore), shows the ones Michel or you replaced (superseded), or everything (all).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if name == "" {
				return deps.Errorf("cli.decisions.need_project")
			}
			if status != "" && !oneOf(status, decisionFilters) {
				return deps.Errorf("cli.decisions.unknown_status", status, strings.Join(decisionFilters, ", "))
			}
			p, err := projectRepo(deps).GetActive(ctx, name)
			if err != nil {
				if errors.Is(err, project.ErrNotFound) {
					return deps.Errorf("cli.decisions.not_found", name)
				}
				return err
			}
			list, err := decide.NewRepo(deps.Store).List(ctx, p.ID, status)
			if err != nil {
				return err
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(list)
			}
			if len(list) == 0 {
				fmt.Fprintln(deps.Stdout, deps.T("cli.decisions.none", p.Name, p.Name))
				return nil
			}
			findings, err := scan.NewRepo(deps.Store).ListFindings(ctx, p.ID, "all")
			if err != nil {
				return err
			}
			byID := make(map[string]scan.Finding, len(findings))
			for _, f := range findings {
				byID[f.ID] = f
			}
			history := status == "superseded" || status == "all"
			var table bytes.Buffer
			tw := tabwriter.NewWriter(&table, 0, 4, 2, ' ', 0)
			head := "package\tosv_id\taction\tdue\tauthor\tdecided_at"
			if history {
				head += "\tsuperseded"
			}
			fmt.Fprintln(tw, head+"\twhy")
			dash := func(s string) string {
				if s == "" {
					return "-"
				}
				return s
			}
			for _, d := range list {
				f := byID[d.FindingID]
				due := "-"
				if !d.DueAt.IsZero() {
					due = dayText(d.DueAt)
				}
				row := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s", dash(safe(f.Package)), dash(safe(f.OSVID)), safe(string(d.Action)), due, safe(d.Author), dayText(d.CreatedAt))
				if history {
					row += "\t" + dash(safe(string(d.SupersededReason)))
				}
				fmt.Fprintln(tw, row+"\t"+dash(oneLine(d.Justification)))
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			_, err = deps.Stdout.Write(table.Bytes())
			return err
		},
	}
	f := c.Flags()
	f.StringVar(&name, "project", "", "name of the project (required)")
	f.StringVar(&status, "status", "", "only these decisions: fix, defer, ignore, superseded (replaced) or all (default: every decision in force)")
	return c
}

// decisionCell is the decision column of 'michel findings'.
func decisionCell(d decide.Decision, ok bool) string {
	switch {
	case !ok:
		return "-"
	case d.Action == decide.Defer:
		return "defer " + dayText(d.DueAt)
	}
	return safe(string(d.Action))
}
