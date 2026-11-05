package cli

import (
	"context"
	"log/slog"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/notify"
	"github.com/kvarot/michel/internal/serverlog"
	"github.com/spf13/cobra"
)

// serverLogAlert tells the notification channels about the errors of a
// server's logs. An SMS goes out only when the server's own log setting ticks
// it (off until then). A channel's failure is audited and never stops the
// read. The scheduler marks what it handed over as told whether or not a
// channel delivered it: the digest still carries those errors.
func serverLogAlert(cmd *cobra.Command, deps *Deps, repo *serverlog.Repo) func(context.Context, serverlog.AlertInput) {
	build := func() ([]notify.Notifier, error) {
		nd, err := notifyDeps(cmd, deps, true)
		if err != nil {
			return nil, err
		}
		nd.SMSCounter = notify.StoreCounter{S: deps.Store}
		return notify.Build(deps.Policy.Notify, nd)
	}
	return func(ctx context.Context, in serverlog.AlertInput) {
		if len(deps.Policy.Notify.Channels) == 0 {
			return
		}
		smsAllowed := false
		if st, err := repo.Settings(ctx, in.Target.ID); err != nil {
			slog.Warn("serve: cannot read the log settings of a server, no sms", "target", in.Target.ID)
		} else {
			smsAllowed = st.SMS
		}
		sendServerLogAlert(ctx, deps, build, in, smsAllowed)
	}
}

// sendServerLogAlert builds the channels and sends the alert, with one audit
// line per channel: where it went, how it ended, its size, never the body.
func sendServerLogAlert(ctx context.Context, deps *Deps, build func() ([]notify.Notifier, error), in serverlog.AlertInput, smsAllowed bool) {
	ns, err := build()
	if err != nil {
		recordAlert(context.WithoutCancel(ctx), deps, in.Target.ID, audit.Event{Actor: "serverlog", Action: "notify.send", Target: in.Target.ID, Result: "error",
			Evidence: map[string]any{"kind": in.Kind, "server": in.Target.ID, "error": "channels not built"}})
		return
	}
	now := deps.Now().UTC()
	for _, dl := range notify.SendLogAlert(ctx, ns, in, smsAllowed, serverPageURL(deps.Policy.Notify.PageURL, in.Target.ID), now) {
		recordAlert(ctx, deps, in.Target.ID, audit.Event{Actor: "serverlog", Action: "notify.send", Target: dl.Name, Result: dl.Result,
			Evidence: map[string]any{"channel": dl.Name, "type": dl.Type, "host": dl.Host, "result": dl.Result, "bytes": dl.Bytes,
				"kind": in.Kind, "server": in.Target.ID}})
	}
}
