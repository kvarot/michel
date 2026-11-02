package cli

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sourceupdate"
	"github.com/spf13/cobra"

	// The readers of each kind of source register themselves.
	_ "github.com/kvarot/michel/internal/sourceupdate/readers"
)

func newSourceUpdateCmd(deps *Deps) *cobra.Command {
	var kind string
	c := &cobra.Command{
		Use:   "update [key...]",
		Short: "Read the enabled sources now: OSV databases, enrichments, feeds, repositories",
		Long: "Update reads every enabled source once, in a fixed order: the OSV databases, the enrichments (KEV, EPSS, then the " +
			"on-demand ones) applied to the findings, the feeds, then the repositories of the skills, MCP servers and plugins. " +
			"A source still waiting for your consent is not contacted. A source that cannot be read keeps its previous data and " +
			"does not stop the others; the command then exits with code 1. Give keys to read only those sources.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			k := source.Kind(kind)
			if kind != "" && !k.Valid() {
				return deps.Errorf("cli.source.bad_kind", kind)
			}
			rep, err := sourceUpdate(cmd, deps, args, k)
			if err != nil && !errors.Is(err, sourceupdate.ErrSomeFailed) {
				return err
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				if jerr := json.NewEncoder(deps.Stdout).Encode(rep); jerr != nil {
					return jerr
				}
			} else {
				printSourceUpdate(deps, rep)
			}
			if err != nil {
				return &ExitError{Code: 1, Quiet: true, Err: deps.Errorf("cli.source.update.failed_exit")}
			}
			return nil
		},
	}
	c.Flags().StringVar(&kind, "kind", "", "only this kind: osv, enrichment, feed, plugin, skill or mcp")
	c.Flags().String("osv-db", "", "directory of the offline databases (default: from the policy)")
	return c
}

// sourceUpdate runs sourceupdate.Run with the command's dependencies. An
// unknown key is refused before anything is read. The error is
// sourceupdate.ErrSomeFailed when a source could not be read.
func sourceUpdate(cmd *cobra.Command, deps *Deps, keys []string, kind source.Kind) (sourceupdate.Report, error) {
	ctx := cmd.Context()
	repo := source.NewRepo(deps.Store)
	for _, k := range keys {
		if _, err := repo.Get(ctx, k); err != nil {
			return sourceupdate.Report{}, sourceErr(deps, k, err)
		}
	}
	dir, _ := cmd.Flags().GetString("data-dir")
	secrets, err := secret.Open(dir)
	if err != nil {
		return sourceupdate.Report{}, deps.Wrapf("cli.secret.open_failed", err, dir)
	}
	return sourceupdate.Run(ctx, sourceupdate.Deps{Store: deps.Store, Repo: repo, Audit: deps.Audit, Gateway: deps.Gateway,
		Secrets: secrets, OSVRoot: dbRoot(cmd, deps), Now: deps.Now, Budget: sourceupdate.BudgetFor(secrets), Actor: "cli",
		Rematch: serverRematch(cmd, deps)},
		keys, kind)
}

// printSourceUpdate prints one line per source, in the order they were read.
func printSourceUpdate(deps *Deps, rep sourceupdate.Report) {
	lines := map[string]string{}
	for _, k := range rep.Updated {
		lines[k] = deps.N("cli.source.update.ok", rep.Items[k], k)
	}
	for _, k := range rep.WaitingConsent {
		lines[k] = deps.T("cli.source.update.waiting_consent", k)
	}
	for _, k := range rep.Failed {
		lines[k] = deps.T("cli.source.update.failed", k, rep.Errors[k])
	}
	for _, k := range rep.Skipped {
		switch rep.SkipReasons[k] {
		case sourceupdate.SkipNotModified:
			lines[k] = deps.T("cli.source.update.not_modified", k)
		case sourceupdate.SkipRateBudget:
			lines[k] = deps.T("cli.source.update.rate_budget", k)
		case sourceupdate.SkipRateLimited:
			lines[k] = deps.N("cli.source.update.rate_limited", rep.Items[k], k)
		case sourceupdate.SkipPartial:
			lines[k] = deps.N("cli.source.update.partial", rep.Items[k], k)
		case sourceupdate.SkipNoRepoConsent:
			lines[k] = deps.T("cli.source.update.no_repo_consent", k)
		case sourceupdate.SkipOff:
			lines[k] = deps.T("cli.source.update.off", k)
		default:
			lines[k] = deps.T("cli.source.update.no_reader", k)
		}
	}
	if len(lines) == 0 {
		fmt.Fprintln(deps.Stdout, deps.T("cli.source.update.nothing"))
		return
	}
	for _, k := range rep.Order {
		fmt.Fprintln(deps.Stdout, lines[k])
	}
	for _, v := range rep.NewVersions {
		fmt.Fprintln(deps.Stdout, deps.T("cli.source.update.new_version", v.Key, safe(v.To), safe(v.From)))
	}
	if rep.Apply.Ran && rep.Apply.Updated > 0 {
		fmt.Fprintln(deps.Stdout, deps.N("cli.source.update.applied", rep.Apply.Updated))
	}
	if rep.Apply.Superseded > 0 {
		fmt.Fprintln(deps.Stdout, deps.N("cli.source.update.superseded", rep.Apply.Superseded))
	}
	if rep.ApplyError != "" {
		fmt.Fprintln(deps.Stdout, deps.T("cli.source.update.apply_failed", rep.ApplyError))
	}
	if len(rep.Failed) > 0 {
		fmt.Fprintln(deps.Stdout, deps.N("cli.source.update.some_failed", len(rep.Failed)))
	}
}
