package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/kvarot/michel/internal/collect"
	"github.com/kvarot/michel/internal/enrich"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/target"
)

// serverCheckInterval is how often michel serve looks for the servers due
// for a check (each one has its own interval, 24 h by default).
const serverCheckInterval = 15 * time.Minute

// serverCheckDeps are the services of a server check for this command. The
// SSH agent is the system one (its pipe setting comes later).
func serverCheckDeps(cmd *cobra.Command, deps *Deps) servercheck.CheckDeps {
	return servercheck.CheckDeps{
		Repo:    target.NewRepo(deps.Store),
		Store:   deps.Store,
		Audit:   deps.Audit,
		SSH:     sshx.Deps{Gateway: deps.Gateway, Audit: deps.Audit, Now: deps.Now},
		Collect: collect.Deps{Now: deps.Now, Audit: deps.Audit, Gateway: deps.Gateway},
		OSVRoot: dbRoot(cmd, deps),
		Sources: source.NewRepo(deps.Store),
		Lookup:  enrich.LookupFunc(deps.Store.DB()),
		Now:     deps.Now,
	}
}

// serverRematch judges the stored server inventories again, offline.
func serverRematch(cmd *cobra.Command, deps *Deps) func(ctx context.Context) (int, error) {
	return func(ctx context.Context) (int, error) {
		return servercheck.Rematch(ctx, serverCheckDeps(cmd, deps))
	}
}
