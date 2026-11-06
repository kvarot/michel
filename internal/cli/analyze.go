package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/buildinfo"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/spf13/cobra"
)

// analyzeDeps builds the collaborators of analyze.Run.
func analyzeDeps(deps *Deps) analyze.Deps {
	return analyze.Deps{Store: deps.Store, Audit: deps.Audit, Version: buildinfo.Version,
		Now: deps.Now, Risk: deps.Policy().Risk}
}

// analyzeProject analyzes the actionable (new or pending) findings of p.
func analyzeProject(cmd *cobra.Command, deps *Deps, p project.Project, force bool) (analyze.RunResult, error) {
	return analyzeProjectIn(cmd.Context(), deps, p, force)
}

// analyzeProjectIn is analyzeProject on a context of its own: a scan started
// from the page stops with michel serve, not with the command.
func analyzeProjectIn(ctx context.Context, deps *Deps, p project.Project, force bool) (analyze.RunResult, error) {
	findings, err := scan.NewRepo(deps.Store).ListFindings(ctx, p.ID, "actionable")
	if err != nil {
		return analyze.RunResult{}, err
	}
	// The analysis follows a package through the lockfiles: a plugin
	// finding (code, configuration) has none.
	kept := findings[:0]
	for _, f := range findings {
		if f.Kind == "" || f.Kind == scan.KindDependency {
			kept = append(kept, f)
		}
	}
	findings = kept
	return analyze.Run(ctx, analyzeDeps(deps), p, findings, analyze.Options{Force: force})
}

func newAnalyzeCmd(deps *Deps) *cobra.Command {
	var name string
	var all, force bool
	c := &cobra.Command{
		Use:   "analyze",
		Short: "Compute the offline facts behind each finding (path, upgrade, call sites, tests, changelog, risk)",
		Long: "Analyze reads the project's own files, never the network and never an AI, to work out for each new or pending " +
			"finding how the package is reached, what upgrade fixes it, where the code uses it, which tests cover it, " +
			"what the changelog says and the risk score. 'michel scan' runs it automatically.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if (name == "") == !all {
				return deps.Errorf("cli.analyze.need_target")
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
					return deps.Errorf("cli.analyze.no_active")
				}
			} else {
				p, err := repo.Get(ctx, name)
				if err != nil {
					if errors.Is(err, project.ErrNotFound) {
						return deps.Errorf("cli.analyze.not_found", name)
					}
					return err
				}
				if !p.Active {
					return deps.Errorf("cli.analyze.removed", p.Name)
				}
				targets = []project.Project{p}
			}
			type result struct {
				Project    string `json:"project"`
				Analyzed   int    `json:"analyzed"`
				Skipped    int    `json:"skipped"`
				Failed     int    `json:"failed"`
				DurationMS int64  `json:"duration_ms"`
			}
			type failure struct {
				Project string `json:"project"`
				Error   string `json:"error"`
			}
			results, failures := []result{}, []failure{}
			problems := false
			for _, p := range targets {
				r, err := analyzeProject(cmd, deps, p, force)
				if err != nil {
					failures = append(failures, failure{p.Name, err.Error()})
					problems = true
					continue
				}
				// Errors also carry audit-write failures: the run is then not clean
				// even if every analysis was saved.
				for _, e := range r.Errors {
					failures = append(failures, failure{p.Name, e.Error()})
					problems = true
				}
				if r.Failed > 0 {
					problems = true
				}
				results = append(results, result{p.Name, r.Analyzed, r.Skipped, r.Failed, r.Duration.Milliseconds()})
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				if err := json.NewEncoder(deps.Stdout).Encode(struct {
					Results  []result  `json:"results"`
					Failures []failure `json:"failures"`
				}{results, failures}); err != nil {
					return err
				}
			} else {
				for _, f := range failures {
					fmt.Fprintln(deps.Stderr, deps.T("cli.analyze.error_line", f.Project, f.Error, f.Project))
				}
				if len(results) > 0 {
					tw := tabwriter.NewWriter(deps.Stdout, 0, 4, 2, ' ', 0)
					fmt.Fprintln(tw, "project\tanalyzed\tskipped\tfailed\tduration")
					for _, r := range results {
						fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\n", r.Project, r.Analyzed, r.Skipped, r.Failed,
							(time.Duration(r.DurationMS) * time.Millisecond).String())
					}
					tw.Flush()
				}
				for _, r := range results {
					fmt.Fprintln(deps.Stdout, analyzeSentence(deps, r.Project, r.Analyzed, r.Skipped, r.Failed))
				}
				if len(results) == 0 {
					fmt.Fprintln(deps.Stdout, deps.T("cli.analyze.none"))
				}
			}
			if problems {
				return &ExitError{Code: 1, Quiet: true, Err: deps.Errorf("cli.analyze.not_clean")}
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&name, "project", "", "name of the project to analyze")
	f.BoolVar(&all, "all", false, "analyze every active project")
	f.BoolVar(&force, "force", false, "recompute analyses that are still fresh")
	return c
}

// analyzeSentence is the plain-language end of an analysis, with the next action.
func analyzeSentence(deps *Deps, project string, analyzed, skipped, failed int) string {
	s := deps.N("cli.analyze.summary", analyzed, project)
	switch {
	case skipped > 0 && failed > 0:
		s += deps.T("cli.analyze.summary.skipped_failed", skipped, failed)
	case skipped > 0:
		s += deps.T("cli.analyze.summary.skipped", skipped)
	case failed > 0:
		s += deps.T("cli.analyze.summary.failed", failed)
	}
	return s + deps.T("cli.common.next_findings", project)
}
