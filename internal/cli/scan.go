package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	var all, noAnalyze bool
	c := &cobra.Command{
		Use:   "scan",
		Short: "Scan a project's lockfiles against the offline databases",
		Long: "Scan reads composer.lock and package-lock.json files under the project folder and compares them " +
			"with the offline OSV databases. It never uses the network; run 'michel db update' to refresh the databases.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if (name == "") == !all {
				return deps.Errorf("cli.scan.need_target")
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
					return deps.Errorf("cli.scan.no_active")
				}
			} else {
				p, err := repo.Get(ctx, name)
				if err != nil {
					if errors.Is(err, project.ErrNotFound) {
						return deps.Errorf("cli.scan.not_found", name)
					}
					return err
				}
				if !p.Active {
					return deps.Errorf("cli.scan.removed", p.Name, p.Name)
				}
				targets = []project.Project{p}
			}
			root := dbRoot(cmd, deps)
			dataDir, _ := cmd.Flags().GetString("data-dir")
			sdeps := scan.Deps{Store: deps.Store, Audit: deps.Audit, Gateway: deps.Gateway, Now: deps.Now,
				Version: buildinfo.Version, DataDir: dataDir,
				// Scanner warnings (unknown config keys, unused ignores) reach the user.
				LogHandler: scannerLogHandler(deps.Stderr)}
			asJSON, _ := cmd.Flags().GetBool("json")

			results := []scan.Result{}
			analysis := map[string]string{} // project name -> summary suffix
			type failure struct {
				Project string `json:"project"`
				Error   string `json:"error"`
			}
			failures := []failure{}
			problems := false
			for _, p := range targets {
				r, err := scan.Run(ctx, sdeps, p, scan.Options{OSVRoot: root, Exclude: scan.EffectiveExclude(p)})
				if err != nil {
					if errors.Is(err, osvdb.ErrDatabaseMissing) && !all {
						return err
					}
					msg := err.Error()
					if errors.Is(err, scan.ErrNoManifests) {
						msg = deps.T("cli.scan.no_manifests", p.Path, p.Name)
					}
					failures = append(failures, failure{Project: p.Name, Error: msg})
					problems = true
					continue
				}
				results = append(results, r)
				if len(r.Errors) > 0 {
					problems = true
				}
				analysis[p.Name] = deps.T("cli.scan.summary.analysis_skipped")
				if noAnalyze || (r.Status != scan.ScanOK && r.Status != scan.ScanPartial) {
					continue
				}
				// Analysis problems are warnings: they never change the scan's exit code.
				ar, aerr := analyzeProject(cmd, deps, p, false)
				if aerr != nil {
					fmt.Fprintln(deps.Stderr, deps.T("cli.scan.warn_analysis_failed", p.Name, aerr, p.Name))
					continue
				}
				for _, e := range ar.Errors {
					fmt.Fprintln(deps.Stderr, deps.T("cli.scan.warn_analysis_error", p.Name, e, p.Name))
				}
				analysis[p.Name] = deps.N("cli.scan.summary.analyzed", ar.Analyzed+ar.Skipped)
			}
			if asJSON {
				if err := json.NewEncoder(deps.Stdout).Encode(struct {
					Results  []scan.Result `json:"results"`
					Failures []failure     `json:"failures"`
				}{results, failures}); err != nil {
					return err
				}
			} else {
				for _, r := range results {
					for _, w := range r.Warnings {
						fmt.Fprintln(deps.Stderr, ignoredConfigWarning(deps, targets, r.Project, w))
					}
					for _, e := range r.Errors {
						fmt.Fprintln(deps.Stderr, deps.T("cli.scan.warn_manifest_error", r.Project, e))
					}
				}
				for _, f := range failures {
					fmt.Fprintln(deps.Stderr, deps.T("cli.scan.error_line", f.Project, f.Error))
				}
				printScan(deps, results, analysis)
				switch {
				case len(results) == 0:
					fmt.Fprintln(deps.Stdout, deps.T("cli.scan.none_scanned"))
				case len(failures) > 0:
					fmt.Fprintln(deps.Stdout, deps.N("cli.scan.some_failed", len(failures)))
				}
			}
			if problems {
				return &ExitError{Code: 1, Quiet: true, Err: deps.Errorf("cli.scan.not_clean")}
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&name, "project", "", "name of the project to scan")
	f.BoolVar(&all, "all", false, "scan every active project")
	f.BoolVar(&noAnalyze, "no-analyze", false, "do not analyze the findings after the scan")
	f.String("osv-db", "", "directory of the offline databases (default: from the policy)")
	return c
}

// printScan prints the results table and one summary sentence per project.
// It prints nothing when there is no result.
func printScan(deps *Deps, results []scan.Result, analysis map[string]string) {
	if len(results) == 0 {
		return
	}
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
		fmt.Fprintln(deps.Stdout, summarySentence(deps, r, analysis[r.Project]))
	}
}

// summarySentence is the plain-language end of a scan, with the next action.
func summarySentence(deps *Deps, r scan.Result, analysis string) string {
	crit := r.BySeverity["critical"]
	var s strings.Builder
	if r.New == 0 {
		s.WriteString(deps.T("cli.scan.summary.no_new", r.Project))
	} else {
		s.WriteString(deps.N("cli.scan.summary.new", r.New, r.Project))
		if crit > 0 {
			s.WriteString(deps.N("cli.scan.summary.critical", crit))
		}
	}
	if r.Reappeared > 0 {
		s.WriteString(deps.N("cli.scan.summary.reappeared", r.Reappeared))
	}
	if r.Gone > 0 {
		s.WriteString(deps.N("cli.scan.summary.gone", r.Gone))
	}
	s.WriteString(analysis)
	switch {
	case r.New > 0 && crit > 0:
		s.WriteString(deps.T("cli.scan.summary.next_critical", r.Project))
	case r.New > 0:
		s.WriteString(deps.T("cli.scan.summary.next_new", r.Project))
	default:
		s.WriteString(deps.T("cli.common.next_findings", r.Project))
	}
	return s.String()
}

// ignoredConfigWarning tells that an osv-scanner.toml in the project was not
// applied. rel is relative to the project folder; the line shows the full path.
func ignoredConfigWarning(deps *Deps, projects []project.Project, name, rel string) string {
	path := rel
	for _, p := range projects {
		if p.Name == name {
			path = filepath.Join(p.Path, filepath.FromSlash(rel))
			break
		}
	}
	return deps.T("cli.scan.warn_ignored_config", path)
}

// scannerLogHandler passes osv-scanner warnings and errors to w and drops
// its informational chatter.
func scannerLogHandler(w io.Writer) slog.Handler {
	return slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelWarn})
}
