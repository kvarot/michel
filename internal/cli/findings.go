package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/spf13/cobra"
)

var (
	validStatuses   = []string{"new", "pending", "gone", "all"}
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

func newFindingsCmd(deps *Deps) *cobra.Command {
	var name, status, severity string
	c := &cobra.Command{
		Use:   "findings",
		Short: "List the vulnerabilities found in a project",
		Long:  "Findings lists what the last scans found. By default it hides findings that are gone (no longer seen at the last scan, not proof of a fix); use --status all to see them.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if name == "" {
				return errors.New("Michel needs a project. Pass --project <name>; 'michel project list' shows the names.")
			}
			if status != "" && !oneOf(status, validStatuses) {
				return fmt.Errorf("Unknown status %q. Use one of %s.", status, strings.Join(validStatuses, ", "))
			}
			if severity != "" && !oneOf(severity, validSeverities) {
				return fmt.Errorf("Unknown severity %q. Use one of %s.", severity, strings.Join(validSeverities, ", "))
			}
			p, err := projectRepo(deps).Get(ctx, name)
			if err != nil {
				if errors.Is(err, project.ErrNotFound) {
					return fmt.Errorf("Cannot list findings for %s: no project has this name. Run 'michel project list' to see the registered names.", name)
				}
				return err
			}
			all, err := scan.NewRepo(deps.Store).ListFindings(ctx, p.ID, status)
			if err != nil {
				return err
			}
			list := all[:0]
			for _, f := range all {
				if severity == "" || f.SeverityLabel == severity {
					list = append(list, f)
				}
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(list)
			}
			if len(list) == 0 {
				fmt.Fprintf(deps.Stdout, "No findings to show for %s. Run 'michel scan --project %s' to refresh them.\n", p.Name, p.Name)
				return nil
			}
			tw := tabwriter.NewWriter(deps.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "severity\tpackage\tinstalled\tfixed\tosv_id\tmanifest\tstatus")
			for _, f := range list {
				fixed := "-"
				if len(f.FixedVersions) > 0 {
					fixed = strings.Join(f.FixedVersions, ",")
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", f.SeverityLabel, f.Package, f.InstalledVersion, fixed, f.OSVID, f.ManifestRelPath, f.Status)
			}
			return tw.Flush()
		},
	}
	f := c.Flags()
	f.StringVar(&name, "project", "", "name of the project (required)")
	f.StringVar(&status, "status", "", "only this status: new, pending, gone (no longer seen at the last scan, not proof of a fix) or all (default: everything except gone)")
	f.StringVar(&severity, "severity", "", "only this severity: critical, high, medium, low or unknown")
	return c
}
