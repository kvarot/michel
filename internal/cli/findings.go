package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/explain"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/spf13/cobra"
)

var (
	validStatuses   = []string{"new", "pending", "decided", "gone", "all"}
	validSeverities = []string{"critical", "high", "medium", "low", "unknown"}
)

func oneOf(v string, list []string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// findingRow is one finding of 'michel findings --json' with the decision
// in force on it (null when there is none).
type findingRow struct {
	scan.Finding
	Decision *decide.Decision `json:"decision"`
}

func newFindingsCmd(deps *Deps) *cobra.Command {
	var name, status, severity string
	var explainRows bool
	c := &cobra.Command{
		Use:   "findings",
		Short: "List the vulnerabilities found in a project",
		Long:  "Findings lists what the last scans found. By default it hides findings that are gone (no longer seen at the last scan, not proof of a fix); use --status all to see them.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if name == "" {
				return deps.Errorf("cli.findings.need_project")
			}
			if status != "" && !oneOf(status, validStatuses) {
				return deps.Errorf("cli.findings.unknown_status", status, strings.Join(validStatuses, ", "))
			}
			if severity != "" && !oneOf(severity, validSeverities) {
				return deps.Errorf("cli.findings.unknown_severity", severity, strings.Join(validSeverities, ", "))
			}
			p, err := projectRepo(deps).GetActive(ctx, name)
			if err != nil {
				if errors.Is(err, project.ErrNotFound) {
					return deps.Errorf("cli.findings.not_found", name)
				}
				return err
			}
			all, err := scan.NewRepo(deps.Store).ListFindings(ctx, p.ID, status)
			if err != nil {
				return err
			}
			list := all[:0]
			for _, f := range all {
				if label, _ := scan.EffectiveSeverity(f); severity == "" || label == severity {
					list = append(list, f)
				}
			}
			decisions, err := decide.NewRepo(deps.Store).CurrentByProject(ctx, p.ID)
			if err != nil {
				return err
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				rows := make([]findingRow, 0, len(list))
				for _, f := range list {
					r := findingRow{Finding: f}
					if d, ok := decisions[f.ID]; ok {
						r.Decision = &d
					}
					rows = append(rows, r)
				}
				return json.NewEncoder(deps.Stdout).Encode(rows)
			}
			if len(list) == 0 {
				fmt.Fprintln(deps.Stdout, deps.T("cli.findings.none", p.Name, p.Name))
				return nil
			}
			var table bytes.Buffer
			tw := tabwriter.NewWriter(&table, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "severity\tpackage\tinstalled\tfixed\tosv_id\tmanifest\tstatus\tdecision")
			for _, f := range list {
				fixed := "-"
				if len(f.FixedVersions) > 0 {
					fixed = strings.Join(f.FixedVersions, ",")
				}
				d, ok := decisions[f.ID]
				// [KEV]: exploited in the wild (CISA list), to fix first.
				sev, _ := scan.EffectiveSeverity(f)
				if f.KEV {
					sev += " [KEV]"
				}
				// A plugin finding shows its tool, rule and location instead.
				what, id, where := scan.Ref(f)
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", safe(sev), safe(what), safe(f.InstalledVersion), safe(fixed), safe(id), safe(where), f.Status, decisionCell(d, ok))
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			rows := strings.Split(strings.TrimRight(table.String(), "\n"), "\n")
			fmt.Fprintln(deps.Stdout, rows[0])
			for i, f := range list {
				fmt.Fprintln(deps.Stdout, rows[i+1])
				if !explainRows {
					continue
				}
				_, _, facts, err := loadFacts(ctx, deps, p, f)
				if err != nil {
					return err
				}
				ex, err := explain.Render(explainLang(deps), facts)
				if err != nil {
					return err
				}
				fmt.Fprintf(deps.Stdout, "  %s\n", ex.What)
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&name, "project", "", "name of the project (required)")
	f.StringVar(&status, "status", "", "only this status: new, pending, decided (a decision is in force, see 'michel decisions'), gone (no longer seen at the last scan, not proof of a fix) or all (default: everything except gone)")
	f.BoolVar(&explainRows, "explain", false, "also print, for each finding, one plain sentence saying where your code uses the package")
	f.StringVar(&severity, "severity", "", "only this severity: critical, high, medium, low or unknown")
	return c
}
