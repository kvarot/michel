package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/kvarot/michel/internal/buildinfo"
	"github.com/kvarot/michel/internal/enrich"
	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/plugin"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sourceupdate"
	"github.com/spf13/cobra"
)

func newScanCmd(deps *Deps) *cobra.Command {
	var name string
	var all, noAnalyze, digestToo, update bool
	c := &cobra.Command{
		Use:   "scan",
		Short: "Scan a project's lockfiles against the offline databases",
		Long: "Scan reads composer.lock, package-lock.json, yarn.lock and pnpm-lock.yaml files under the project folder " +
			"and compares them with the offline OSV databases of the enabled ecosystems ('michel source list --kind osv'). " +
			"The scan itself never uses the network; run 'michel db update' to refresh the databases, or add --update to read every " +
			"enabled source first (as 'michel source update'; a source that cannot be read does not stop the scan). A folder without any lockfile " +
			"is reported as having nothing to scan: an error with --project, not with --all. After the scan and the analysis of a project, every enabled plugin " +
			"set to run (michel source list --kind plugin) runs on it, as michel source run does; a plugin that fails is a warning. " +
			"Then the applied fixes are settled: only the tool that reported a flaw, if it looked in this scan, can prove its fix.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if (name == "") == !all {
				return deps.Errorf("cli.scan.need_target")
			}
			if digestToo && !all {
				return deps.Errorf("cli.scan.digest_needs_all")
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
			asJSON, _ := cmd.Flags().GetBool("json")
			problems := false
			// The sources are read before the scans, so they use fresh
			// data; a failed read keeps the previous data and the scans go on.
			var updated *sourceupdate.Report
			if update {
				rep, err := sourceUpdate(cmd, deps, nil, "")
				if err != nil && !errors.Is(err, sourceupdate.ErrSomeFailed) {
					return err
				}
				updated = &rep
				if !asJSON {
					printSourceUpdate(deps, rep)
				}
				if err != nil {
					problems = true
					if !asJSON {
						fmt.Fprintln(deps.Stdout, deps.T("cli.scan.update_continues"))
					}
				}
				if !asJSON {
					fmt.Fprintln(deps.Stdout)
				}
			}
			env, err := newScanEnv(ctx, cmd, deps, noAnalyze)
			if err != nil {
				return err
			}

			results := []scan.Result{}
			analysis := map[string]string{} // project name -> summary suffix
			empties := map[string]string{}  // project name -> folder, for the scans with nothing to scan
			type failure struct {
				Project string `json:"project"`
				Error   string `json:"error"`
			}
			failures := []failure{}
			for _, p := range targets {
				r, summary, err := env.runOne(ctx, cmd, deps, p, all)
				if err != nil {
					if errors.Is(err, osvdb.ErrDatabaseMissing) && !all {
						return err
					}
					msg := err.Error()
					if errors.Is(err, scan.ErrScanRunning) {
						msg = deps.T("cli.scan.already_running", p.Name)
					}
					failures = append(failures, failure{Project: p.Name, Error: msg})
					problems = true
					continue
				}
				results = append(results, r)
				if r.Status == scan.ScanEmpty {
					// Not a failure with --all: the project may have no
					// dependencies yet. With --project the user aimed at it.
					empties[p.Name] = p.Path
					if !all {
						problems = true
					}
					continue
				}
				// A lockfile left out because its ecosystem is disabled is the
				// user's choice, not a problem: it keeps the scan partial in
				// the store but neither warns nor changes the exit code.
				if len(manifestProblems(r)) > 0 {
					problems = true
				}
				analysis[p.Name] = summary
			}
			if asJSON {
				if err := json.NewEncoder(deps.Stdout).Encode(struct {
					Results  []scan.Result        `json:"results"`
					Failures []failure            `json:"failures"`
					Plugins  []pluginRunView      `json:"plugins"`
					Update   *sourceupdate.Report `json:"update,omitempty"`
				}{results, failures, env.plugins, updated}); err != nil {
					return err
				}
			} else {
				for _, r := range results {
					for _, w := range r.Warnings {
						fmt.Fprintln(deps.Stderr, ignoredConfigWarning(deps, targets, r.Project, w))
					}
					for _, e := range manifestProblems(r) {
						fmt.Fprintln(deps.Stderr, deps.T("cli.scan.warn_manifest_error", r.Project, e))
					}
				}
				for _, f := range failures {
					fmt.Fprintln(deps.Stderr, deps.T("cli.scan.error_line", f.Project, f.Error))
				}
				scanned := []scan.Result{}
				for _, r := range results {
					if r.Status == scan.ScanEmpty {
						fmt.Fprintln(deps.Stdout, deps.T("cli.scan.empty", r.Project, empties[r.Project]))
						continue
					}
					scanned = append(scanned, r)
				}
				printScan(deps, scanned, analysis)
				for _, l := range env.pluginLines {
					fmt.Fprintln(deps.Stdout, l)
				}
				switch {
				case len(results) == 0:
					fmt.Fprintln(deps.Stdout, deps.T("cli.scan.none_scanned"))
				case len(failures) > 0:
					fmt.Fprintln(deps.Stdout, deps.N("cli.scan.some_failed", len(failures)))
				}
			}
			// The digest goes out even when a project could not be scanned:
			// it reports the failed scans.
			if digestToo {
				opt, err := digestOptions(cmd, deps, "")
				if err != nil {
					return err
				}
				// One digest a day, shared with michel serve: one already sent
				// today is not sent again, and a digest nobody received is not
				// recorded, so the next one covers the same period.
				res, err := sendDigest(ctx, cmd, deps, opt, true, nil)
				if err != nil {
					return err
				}
				if res.State == digestSkipped {
					if !asJSON {
						fmt.Fprintln(deps.Stdout)
						fmt.Fprintln(deps.Stdout, deps.T("cli.digest.already_sent"))
					}
				} else {
					if !asJSON {
						fmt.Fprintln(deps.Stdout)
						if err := printDigest(deps, res.Digest, false, false); err != nil {
							return err
						}
					}
					if res.State == digestHeld {
						// Nobody got it: the count of the failed channels would say it
						// is recorded, which it is not.
						if reportChannelLines(deps, res.Deliveries) > 0 {
							problems = true
						}
						fmt.Fprintln(deps.Stderr, heldMessage(deps, res.Deliveries))
					} else if reportChannels(deps, res.Deliveries) > 0 {
						problems = true
					}
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
	f.BoolVar(&digestToo, "digest", false, "with --all, send the digest after the scan (as 'michel digest --send')")
	f.BoolVar(&update, "update", false, "read every enabled source before scanning (as 'michel source update')")
	f.String("osv-db", "", "directory of the offline databases (default: from the policy)")
	return c
}

// scanEnv is what the scans of one michel scan share, and what they leave for
// its report: the plugin runs.
type scanEnv struct {
	sdeps         scan.Deps
	root          string
	ecos          []string
	pluginEntries []source.Entry
	noAnalyze     bool
	plugins       []pluginRunView
	pluginLines   []string
}

func newScanEnv(ctx context.Context, cmd *cobra.Command, deps *Deps, noAnalyze bool) (*scanEnv, error) {
	root := dbRoot(cmd, deps)
	ecos, err := osvdb.Enabled(ctx, source.NewRepo(deps.Store), deps.allowed)
	if err != nil {
		return nil, err
	}
	dataDir, _ := cmd.Flags().GetString("data-dir")
	sdeps := scan.Deps{Store: deps.Store, Audit: deps.Audit, Gateway: deps.Gateway, Now: deps.Now,
		Version: buildinfo.Version, DataDir: dataDir,
		// Scanner warnings (unknown config keys, unused ignores) reach the user.
		LogHandler: scannerLogHandler(deps.Stderr)}
	// The plugins run after each project's scan and analysis; a
	// plugin that fails is a warning, as the analysis.
	pluginEntries, err := source.NewRepo(deps.Store).List(ctx, source.KindPlugin, false)
	if err != nil {
		return nil, err
	}
	return &scanEnv{sdeps: sdeps, root: root, ecos: ecos, pluginEntries: pluginEntries, noAnalyze: noAnalyze,
		plugins: []pluginRunView{}, pluginLines: []string{}}, nil
}

// scanOneProject is one pass on one project, the same as michel scan: the scan,
// the analysis, the plugins, then the proof of the applied fixes, and the queue
// of the automatic fixes when queue is true. Warnings go to deps.Stderr, as in
// michel scan; it prints nothing else. It returns the scan and the end of its
// summary sentence (the analysis). A failed plugin or analysis is a warning; an
// error means the scan itself failed.
func scanOneProject(ctx context.Context, cmd *cobra.Command, deps *Deps, p project.Project, queue bool) (scan.Result, string, error) {
	env, err := newScanEnv(ctx, cmd, deps, false)
	if err != nil {
		return scan.Result{}, "", err
	}
	return env.runOne(ctx, cmd, deps, p, queue)
}

// runOne is the body of scanOneProject. michel scan calls it directly: its
// report needs the plugin runs kept in e, and it reads the databases once.
func (e *scanEnv) runOne(ctx context.Context, cmd *cobra.Command, deps *Deps, p project.Project, queue bool) (scan.Result, string, error) {
	// The enrichment (KEV, EPSS) is read from the store for the CVEs of
	// each scan only.
	r, err := scan.Run(ctx, e.sdeps, p, scan.Options{OSVRoot: e.root, Exclude: scan.EffectiveExclude(p), Ecosystems: e.ecos,
		Lookup: enrich.LookupFunc(deps.Store.DB())})
	if err != nil {
		return r, "", err
	}
	if r.Status == scan.ScanEmpty {
		// A folder without lockfile still has code and settings to check.
		// The scan read nothing: it settles no fix of a dependency.
		looked := e.runPlugins(ctx, cmd, deps, p)
		proveFixes(ctx, deps, scanFixDeps(cmd, deps), p, fix.Pass{Sources: looked})
		return r, "", nil
	}
	analysis := deps.T("cli.scan.summary.analysis_skipped")
	if !e.noAnalyze && (r.Status == scan.ScanOK || r.Status == scan.ScanPartial) {
		// Analysis problems are warnings: they never change the scan's exit code.
		ar, aerr := analyzeProjectIn(ctx, deps, p, false)
		if aerr != nil {
			fmt.Fprintln(deps.Stderr, deps.T("cli.scan.warn_analysis_failed", p.Name, aerr, p.Name))
		} else {
			for _, line := range ar.Errors {
				fmt.Fprintln(deps.Stderr, deps.T("cli.scan.warn_analysis_error", p.Name, line, p.Name))
			}
			analysis = deps.N("cli.scan.summary.analyzed", ar.Analyzed+ar.Skipped)
		}
	}
	looked := e.runPlugins(ctx, cmd, deps, p)
	// The applied fixes of the project are settled by this pass
	// (proven when merged and gone), and its eligible findings
	// queued for michel serve at level 2.
	fd := scanFixDeps(cmd, deps)
	proveFixes(ctx, deps, fd, p, fix.Pass{Scanned: true, Sources: looked})
	if queue {
		if _, err := fix.QueueEligible(ctx, fd, p.ID); err != nil {
			fmt.Fprintln(deps.Stderr, deps.T("cli.scan.warn_fix_failed", p.Name, err))
		}
	}
	return r, analysis, nil
}

// runPlugins returns the plugins that ran without any failure: the
// only ones whose word settles a fix (fix.Prove).
func (e *scanEnv) runPlugins(ctx context.Context, cmd *cobra.Command, deps *Deps, p project.Project) map[string]bool {
	looked := map[string]bool{}
	for _, s := range scanPlugins(e.pluginEntries, deps.allowed, p.Name) {
		res, err := plugin.RunPlugin(ctx, pluginDeps(cmd, deps), s, p, "")
		if err != nil {
			fmt.Fprintln(deps.Stderr, deps.T("cli.scan.warn_plugin_failed", p.Name, pluginErr(deps, s, p.Name, err), s.Key, p.Name))
			if !errors.Is(err, plugin.ErrAudit) {
				continue
			}
		} else {
			looked[s.Key] = true
		}
		e.plugins = append(e.plugins, pluginRunView{Project: p.Name, Key: s.Key, RunResult: res})
		e.pluginLines = append(e.pluginLines, pluginSummary(deps, s, p.Name, res))
	}
	return looked
}

// proveFixes settles the applied fixes of the project, once every tool
// of this pass has run: a plugin's findings change in runPlugins.
func proveFixes(ctx context.Context, deps *Deps, fd fix.Deps, p project.Project, pass fix.Pass) {
	if _, err := fix.Prove(ctx, fd, p.ID, pass); err != nil {
		fmt.Fprintln(deps.Stderr, deps.T("cli.scan.warn_fix_failed", p.Name, err))
	}
}

// manifestProblems are the errors of r except the lockfiles left out because
// their ecosystem is disabled.
func manifestProblems(r scan.Result) []error {
	var out []error
	for _, e := range r.Errors {
		if !errors.Is(e, scan.ErrEcosystemDisabled) {
			out = append(out, e)
		}
	}
	return out
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

// scanFixDeps builds the fix deps of a scan: proving and queueing read the
// store and the user's repository only, so the secret store is not opened
// (a scan creates nothing in the data folder besides its own rows).
func scanFixDeps(cmd *cobra.Command, deps *Deps) fix.Deps {
	actor := "cli"
	if cmd.Name() == "serve" {
		actor = "serve"
	}
	return fixDeps(cmd, deps, nil, actor)
}
