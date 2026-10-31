package cli

import (
	"context"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/collect"
	"github.com/kvarot/michel/internal/enrich"
	"github.com/kvarot/michel/internal/notify"
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
		Alert:   serverAlert(cmd, deps),
		Now:     deps.Now,
	}
}

// serverPageURL is the link to a server's page: the policy's page link and
// the page route #/servers/<id> (the route itself comes with the servers
// page). It holds the server's id only, never its name or address.
func serverPageURL(base, id string) string {
	if base == "" {
		return ""
	}
	return strings.TrimRight(base, "/") + "/#/servers/" + id
}

// serverAlert tells the notification channels about a server: a short text,
// an SMS only for an urgent alert. A channel's failure is audited and never
// stops the check.
func serverAlert(cmd *cobra.Command, deps *Deps) func(context.Context, servercheck.AlertInput) {
	return func(ctx context.Context, in servercheck.AlertInput) {
		if len(deps.Policy.Notify.Channels) == 0 {
			return
		}
		nd, err := notifyDeps(cmd, deps, true)
		if err != nil {
			return
		}
		nd.SMSCounter = notify.StoreCounter{S: deps.Store}
		ns, err := notify.Build(deps.Policy.Notify, nd)
		if err != nil {
			return
		}
		now := deps.Now().UTC()
		for _, dl := range notify.SendServerAlert(ctx, ns, in, serverPageURL(deps.Policy.Notify.PageURL, in.Target.ID), now) {
			// Never the body: the channel, where it went, how it ended, its size.
			_, _ = deps.Audit.Record(ctx, audit.Event{Actor: "servercheck", Action: "notify.send", Target: dl.Name, Result: dl.Result,
				Evidence: map[string]any{"channel": dl.Name, "type": dl.Type, "host": dl.Host, "result": dl.Result, "bytes": dl.Bytes,
					"kind": in.Kind, "server": in.Target.ID}})
		}
	}
}

// serverRematch judges the stored server inventories again, offline.
func serverRematch(cmd *cobra.Command, deps *Deps) func(ctx context.Context) (int, error) {
	return func(ctx context.Context) (int, error) {
		return servercheck.Rematch(ctx, serverCheckDeps(cmd, deps))
	}
}
