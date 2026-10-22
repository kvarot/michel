package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
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
				if !p.Active {
					return fmt.Errorf("Cannot scan %s: the project was removed, so Michel no longer scans it (its history is kept). "+
						"Register the folder again under another name with 'michel project add', or purge it with 'michel project remove %s --purge' and add it back.", p.Name, p.Name)
				}
				targets = []project.Project{p}
			}
			root := dbRoot(cmd, deps)
			dataDir, _ := cmd.Flags().GetString("data-dir")
			sdeps := scan.Deps{Store: deps.Store, Audit: deps.Audit, Gateway: deps.Gateway, Now: deps.Now,
				Version: buildinfo.Version, DataDir: dataDir}
			asJSON, _ := cmd.Flags().GetBool("json")

			results := []scan.Result{}
			type failure struct {
				Project string `json:"project"`
				Error   string `json:"error"`
			}
			failures := []failure{}
			problems := false
			for _, p := range targets {
				r, err := scan.Run(ctx, sdeps, p, scan.Options{OSVRoot: root})
				if err != nil {
					if errors.Is(err, osvdb.ErrDatabaseMissing) && !all {
						return err
					}
					msg := err.Error()
					if errors.Is(err, scan.ErrNoManifests) {
						msg = noManifestsMessage(p)
					}
					failures = append(failures, failure{Project: p.Name, Error: msg})
					problems = true
					continue
				}
				results = append(results, r)
				if len(r.Errors) > 0 {
					problems = true
				}
			}
			if asJSON {
				if err := json.NewEncoder(deps.Stdout).Encode(struct {
					Results  []scan.Result `json:"results"`
					Failures []failure     `json:"failures"`
				}{results, failures}); err != nil {
					return err
				}
			} else {
				printScan(deps, results)
				for _, r := range results {
					for _, w := range r.Warnings {
						fmt.Fprintln(deps.Stderr, ignoredConfigWarning(targets, r.Project, w))
					}
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

// noManifestsMessage explains a scan that found no lockfile: what, why, next.
func noManifestsMessage(p project.Project) string {
	return fmt.Sprintf("Michel found no composer.lock or package-lock.json under %s, so it scanned nothing and kept the earlier findings of %s. "+
		"Michel only scans lockfiles; the folder may be empty or unmounted, or the lockfiles may sit under an excluded folder (node_modules, vendor, .git). "+
		"Check the path with 'michel project list', or add the lockfile and scan again.", p.Path, p.Name)
}

// summarySentence is the plain-language end of a scan, with the next action.
func summarySentence(r scan.Result) string {
	crit := r.BySeverity["critical"]
	var s strings.Builder
	if r.New == 0 {
		fmt.Fprintf(&s, "Michel found no new findings in %s", r.Project)
	} else {
		fmt.Fprintf(&s, "Michel found %s in %s", plural(r.New, "new finding", "new findings"), r.Project)
		if crit > 0 {
			fmt.Fprintf(&s, ", %d critical", crit)
		}
	}
	if r.Reappeared > 0 {
		verb := "findings came back after being gone"
		if r.Reappeared == 1 {
			verb = "finding came back after being gone"
		}
		fmt.Fprintf(&s, "; %d %s", r.Reappeared, verb)
	}
	if r.Gone > 0 {
		fmt.Fprintf(&s, "; %s", plural(r.Gone, "finding is gone", "findings are gone"))
	}
	switch {
	case r.New > 0 && crit > 0:
		fmt.Fprintf(&s, ". Next: michel findings --project %s --severity critical", r.Project)
	case r.New > 0:
		fmt.Fprintf(&s, ". Next: michel findings --project %s --status new", r.Project)
	default:
		fmt.Fprintf(&s, ". Next: michel findings --project %s", r.Project)
	}
	return s.String()
}

// ignoredConfigWarning tells that an osv-scanner.toml in the project was not
// applied. rel is relative to the project folder; the line shows the full path.
func ignoredConfigWarning(projects []project.Project, name, rel string) string {
	path := rel
	for _, p := range projects {
		if p.Name == name {
			path = filepath.Join(p.Path, filepath.FromSlash(rel))
			break
		}
	}
	return fmt.Sprintf("Warning: %s contains osv-scanner ignore rules; Michel does not apply them. "+
		"Decide on findings with michel decide (plan 3) instead.", path)
}
