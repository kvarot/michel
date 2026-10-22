package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/kvarot/michel/internal/buildinfo"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/spf13/cobra"
)

func newScanCmd(deps *Deps) *cobra.Command {
	var name string
	var all bool
	c := &cobra.Command{
		Use:   "scan",
		Short: "Scan a project's lockfiles against the offline databases",
		Long: "Scan reads composer.lock and package-lock.json files under the project folder and compares them " +
			"with the offline OSV databases. It never uses the network; run 'michel db update' to refresh the databases.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if (name == "") == !all {
				return errors.New("Michel needs to know what to scan. Pass --project <name> for one project, " +
					"or --all for every active project. 'michel project list' shows the names.")
			}
			repo := projectRepo(deps)
			var targets []project.Project
			if all {
				list, err := repo.List(ctx)
				if err != nil {
					return err
				}
				for _, p := range list {
					if p.Active {
						targets = append(targets, p)
					}
				}
				if len(targets) == 0 {
					return errors.New("There is no active project to scan. Register one with 'michel project add <path> --name <name>'.")
				}
			} else {
				p, err := repo.Get(ctx, name)
				if err != nil {
					if errors.Is(err, project.ErrNotFound) {
						return fmt.Errorf("Cannot scan %s: no project has this name. Run 'michel project list' to see the registered names.", name)
					}
					return err
				}
				targets = []project.Project{p}
			}
			root := dbRoot(cmd, deps)
			sdeps := scan.Deps{Store: deps.Store, Audit: deps.Audit, Gateway: deps.Gateway, Now: deps.Now, Version: buildinfo.Version}
			asJSON, _ := cmd.Flags().GetBool("json")

			var results []scan.Result
			var failures []string
			problems := false
			for _, p := range targets {
				r, err := scan.Run(ctx, sdeps, p, scan.Options{OSVRoot: root})
				if err != nil {
					if errors.Is(err, osvdb.ErrDatabaseMissing) && !all {
						return err
					}
					failures = append(failures, fmt.Sprintf("%s: %v", p.Name, err))
					problems = true
					continue
				}
				results = append(results, r)
				if len(r.Errors) > 0 {
					problems = true
				}
			}
			if asJSON {
				if err := json.NewEncoder(deps.Stdout).Encode(results); err != nil {
					return err
				}
			} else {
				printScan(deps, results)
				for _, r := range results {
					for _, e := range r.Errors {
						fmt.Fprintf(deps.Stderr, "warning: %s: %v. Fix or remove the file, then scan again; its earlier findings were kept.\n", r.Project, e)
					}
				}
				for _, f := range failures {
					fmt.Fprintf(deps.Stderr, "error: %s\n", f)
				}
			}
			if problems {
				return &ExitError{Code: 1, Quiet: true, Err: errors.New("the scan did not complete cleanly")}
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&name, "project", "", "name of the project to scan")
	f.BoolVar(&all, "all", false, "scan every active project")
	f.String("osv-db", "", "directory of the offline databases (default: from the policy)")
	return c
}

func printScan(deps *Deps, results []scan.Result) {
	tw := tabwriter.NewWriter(deps.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "project\tmanifests\tpackages\tfindings\tcritical/high/medium/low/unknown\tnew/gone")
	for _, r := range results {
		pk, fi := 0, 0
		for _, m := range r.Manifests {
			pk += m.Packages
			fi += m.Findings
		}
		b := r.BySeverity
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d/%d/%d/%d/%d\t%d/%d\n", r.Project, len(r.Manifests), pk, fi,
			b["critical"], b["high"], b["medium"], b["low"], b["unknown"], r.New, r.Gone)
	}
	tw.Flush()
	for _, r := range results {
		fmt.Fprintln(deps.Stdout, summarySentence(r))
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// summarySentence is the plain-language end of a scan, with the next action.
func summarySentence(r scan.Result) string {
	crit := r.BySeverity["critical"]
	var s strings.Builder
	switch {
	case len(r.Manifests) == 0:
		return fmt.Sprintf("Michel found no composer.lock or package-lock.json in %s. Next: michel project list", r.Project)
	case r.New == 0:
		fmt.Fprintf(&s, "Michel found no new findings in %s", r.Project)
		if r.Gone > 0 {
			fmt.Fprintf(&s, ", and %s fixed", plural(r.Gone, "finding is", "findings are"))
		}
		fmt.Fprintf(&s, ". Next: michel findings --project %s", r.Project)
		return s.String()
	}
	fmt.Fprintf(&s, "Michel found %s in %s", plural(r.New, "new finding", "new findings"), r.Project)
	if crit > 0 {
		fmt.Fprintf(&s, ", %d critical. Next: michel findings --project %s --severity critical", crit, r.Project)
	} else {
		fmt.Fprintf(&s, ". Next: michel findings --project %s --status new", r.Project)
	}
	return s.String()
}
