package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/collect"
	"github.com/kvarot/michel/internal/enrich"
	"github.com/kvarot/michel/internal/notify"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/target"
)

// serverCheckInterval is how often michel serve looks for the servers due
// for a check (each one has its own interval, 24 h by default).
const serverCheckInterval = 15 * time.Minute

// sshDeps is the SSH client of every command that reaches a server (the
// checks, the fixes, the host key reading, michel serve and michel mcp): the
// gateway, the audit, and the SSH agent the policy names (ssh.agent_pipe), else
// the system one.
func sshDeps(deps *Deps) sshx.Deps {
	return sshx.Deps{Gateway: deps.Gateway, Audit: deps.Audit, Now: deps.Now, Agent: sshAgent(deps.Policy.SSH.AgentPipe)}
}

// sshAgent opens the SSH agent at path, "" for the system one. Replaced in
// tests, which never reach the real agent.
var sshAgent = sshx.SystemAgent

// serverCheckDeps are the services of a server check for this command.
func serverCheckDeps(cmd *cobra.Command, deps *Deps) servercheck.CheckDeps {
	return servercheck.CheckDeps{
		Repo:    target.NewRepo(deps.Store),
		Store:   deps.Store,
		Audit:   deps.Audit,
		SSH:     sshDeps(deps),
		Collect: collect.Deps{Now: deps.Now, Audit: deps.Audit, Gateway: deps.Gateway},
		OSVRoot: dbRoot(cmd, deps),
		Sources: source.NewRepo(deps.Store),
		Lookup:  enrich.LookupFunc(deps.Store.DB()),
		Alert:   serverAlert(cmd, deps),
		Now:     deps.Now,
	}
}

// siteCheckMax bounds what the site check reads of the page.
const siteCheckMax = 1 << 20

// siteCheck is the GET of a server fix's check_site, from this computer
// through the gateway (purpose target.http): the site answers when its
// status is 2xx or 3xx and its page is not empty. Nothing of the page is
// kept.
func siteCheck(deps *Deps) func(ctx context.Context, url string) error {
	return func(ctx context.Context, url string) error {
		if deps.Gateway == nil {
			return errors.New("no network gateway")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := deps.Gateway.Client(policy.PurposeTargetHTTP).Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			return fmt.Errorf("the site answered %d", resp.StatusCode)
		}
		n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, siteCheckMax))
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("the site sent an empty page")
		}
		return nil
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
	build := func() ([]notify.Notifier, error) {
		nd, err := notifyDeps(cmd, deps, true)
		if err != nil {
			return nil, err
		}
		nd.SMSCounter = notify.StoreCounter{S: deps.Store}
		return notify.Build(deps.Policy.Notify, nd)
	}
	return func(ctx context.Context, in servercheck.AlertInput) {
		if len(deps.Policy.Notify.Channels) == 0 {
			return
		}
		sendServerAlert(ctx, deps, build, in)
	}
}

// recordAlert writes the audit row of an alert delivery. The alert is not
// retried, so a row the audit log refuses is at least a warning in the log.
func recordAlert(ctx context.Context, deps *Deps, server string, e audit.Event) {
	if _, err := deps.Audit.Record(ctx, e); err != nil {
		slog.Warn("serve: cannot write the audit row of an alert", "actor", e.Actor, "server", server, "result", e.Result, "err", err)
	}
}

// sendServerAlert builds the channels and sends the alert. When the channels
// cannot be built the failure is audited (the error holds no secret): the
// alert is not retried, so it must not vanish without a trace.
func sendServerAlert(ctx context.Context, deps *Deps, build func() ([]notify.Notifier, error), in servercheck.AlertInput) {
	ns, err := build()
	if err != nil {
		recordAlert(context.WithoutCancel(ctx), deps, in.Target.ID, audit.Event{Actor: "servercheck", Action: "notify.send", Target: in.Target.ID, Result: "error",
			Evidence: map[string]any{"kind": in.Kind, "server": in.Target.ID, "error": scan.SanitizeText(err.Error())}})
		return
	}
	now := deps.Now().UTC()
	for _, dl := range notify.SendServerAlert(ctx, ns, in, serverPageURL(deps.Policy.Notify.PageURL, in.Target.ID), now) {
		// Never the body: the channel, where it went, how it ended, its size.
		recordAlert(ctx, deps, in.Target.ID, audit.Event{Actor: "servercheck", Action: "notify.send", Target: dl.Name, Result: dl.Result,
			Evidence: map[string]any{"channel": dl.Name, "type": dl.Type, "host": dl.Host, "result": dl.Result, "bytes": dl.Bytes,
				"kind": in.Kind, "server": in.Target.ID}})
	}
}

// serverRematch judges the stored server inventories again, offline.
func serverRematch(cmd *cobra.Command, deps *Deps) func(ctx context.Context) (int, error) {
	return func(ctx context.Context) (int, error) {
		return servercheck.Rematch(ctx, serverCheckDeps(cmd, deps))
	}
}
