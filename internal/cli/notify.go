package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/buildinfo"
	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/notify"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/secret"
	"github.com/spf13/cobra"
)

func newNotifyCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{
		Use:   "notify",
		Short: "List the notification channels and send a test message",
		Long: "Notify shows the channels of the notify section of the policy (email, webhook, desktop notification) " +
			"and sends a fixed test message on one of them. The digest itself goes out with 'michel digest --send'.",
	}
	c.AddCommand(newNotifyListCmd(deps), newNotifyTestCmd(deps))
	return c
}

// notifyDeps returns what the channels need; the secret store is opened
// only when a channel may read it.
func notifyDeps(cmd *cobra.Command, deps *Deps, needSecrets bool) (notify.Deps, error) {
	nd := notify.Deps{Gateway: deps.Gateway, Version: buildinfo.Version, Now: deps.Now, Lang: deps.Lang}
	if needSecrets {
		st, err := openSecrets(cmd, deps)
		if err != nil {
			return notify.Deps{}, err
		}
		nd.Secrets = st
	}
	return nd, nil
}

// channelTarget is what a channel contacts, without any url path: host:port
// for email, the host for a webhook, "local" for a toast.
func channelTarget(c policy.ChannelConfig) string {
	host, _, _ := policy.ChannelTarget(c)
	switch c.Type {
	case policy.ChannelEmail:
		return net.JoinHostPort(host, strconv.Itoa(c.Port))
	case policy.ChannelToast:
		return "local"
	}
	return host
}

// channelLine is one channel in notify list.
type channelLine struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Enabled  bool     `json:"enabled"`
	Target   string   `json:"target"`
	Projects []string `json:"projects"`
}

func newNotifyListCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the notification channels of the policy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			lines := []channelLine{}
			for _, c := range deps.Policy.Notify.Channels {
				projects := c.Projects
				if projects == nil {
					projects = []string{}
				}
				lines = append(lines, channelLine{Name: c.Name, Type: c.Type, Enabled: c.IsEnabled(), Target: channelTarget(c), Projects: projects})
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(lines)
			}
			if len(lines) == 0 {
				cfgPath, _ := cmd.Flags().GetString("config")
				fmt.Fprintln(deps.Stdout, deps.T("cli.notify.list_empty", cfgPath))
				return nil
			}
			tw := tabwriter.NewWriter(deps.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "name\ttype\tenabled\ttarget\tprojects")
			for _, l := range lines {
				projects := strings.Join(l.Projects, ",")
				if projects == "" {
					projects = deps.T("cli.notify.all_projects")
				}
				fmt.Fprintf(tw, "%s\t%s\t%t\t%s\t%s\n", l.Name, l.Type, l.Enabled, l.Target, projects)
			}
			return tw.Flush()
		},
	}
}

func newNotifyTestCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "test <name>",
		Short: "Send a fixed test message on one channel (no data about your projects)",
		Long: "Test sends a fixed message, holding no data about your projects, on the channel name, even when it is " +
			"disabled, and records a notify.test event in the audit log.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			var ch *policy.ChannelConfig
			for i, c := range deps.Policy.Notify.Channels {
				if c.Name == name {
					ch = &deps.Policy.Notify.Channels[i]
					break
				}
			}
			if ch == nil {
				return deps.Errorf("cli.notify.unknown_channel", scan.SanitizeText(name))
			}
			if !ch.IsEnabled() {
				fmt.Fprintln(deps.Stderr, deps.T("cli.notify.test_disabled", ch.Name))
			}
			nd, err := notifyDeps(cmd, deps, ch.Type != policy.ChannelToast)
			if err != nil {
				return err
			}
			n, err := notify.New(*ch, nd)
			if err != nil {
				return deps.Wrapf("cli.notify.config_error", err, ch.Name)
			}
			dl := notify.TestOne(cmd.Context(), n)
			ev := map[string]any{"channel": dl.Name, "type": dl.Type, "host": dl.Host, "result": dl.Result}
			if _, err := deps.Audit.Record(cmd.Context(), audit.Event{Actor: "cli", Action: "notify.test", Target: dl.Name, Result: dl.Result,
				Evidence: ev}); err != nil {
				return deps.Wrapf("cli.notify.audit_failed", err)
			}
			if dl.Result != notify.ResultOK {
				fmt.Fprintln(deps.Stderr, channelMessage(deps, dl))
				return &ExitError{Code: 1, Quiet: true, Err: deps.Errorf("cli.notify.test_failed", dl.Name)}
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.notify.test_sent", dl.Name, deps.T("notify.type."+dl.Type)))
			return nil
		},
	}
}

// sendChannels sends d on every enabled channel of the policy.
func sendChannels(ctx context.Context, cmd *cobra.Command, deps *Deps, d digest.Digest) ([]notify.Delivery, error) {
	cfg := deps.Policy.Notify
	needSecrets := false
	for _, c := range cfg.Channels {
		if c.IsEnabled() && c.Type != policy.ChannelToast {
			needSecrets = true
		}
	}
	nd, _ := notifyDeps(cmd, deps, false)
	if needSecrets {
		// A secret store that cannot be opened fails only the channels that
		// read a secret; the others are still sent and the run still saved.
		dir, _ := cmd.Flags().GetString("data-dir")
		st, err := secret.Open(dir)
		if err != nil {
			st = unavailableSecrets{err: err}
		}
		nd.Secrets = st
	}
	ns, err := notify.Build(cfg, nd)
	if err != nil {
		return nil, deps.Wrapf("cli.notify.channels_invalid", err)
	}
	return notify.Deliver(ctx, ns, d), nil
}

// unavailableSecrets is the secret store when it cannot be opened: every
// read fails with the reason, in English.
type unavailableSecrets struct{ err error }

func (u unavailableSecrets) Set(string, []byte) error   { return u.fail() }
func (u unavailableSecrets) Get(string) ([]byte, error) { return nil, u.fail() }
func (u unavailableSecrets) Delete(string) error        { return u.fail() }
func (u unavailableSecrets) List() ([]string, error)    { return nil, u.fail() }
func (u unavailableSecrets) fail() error {
	return fmt.Errorf("the secret store cannot be opened: %w", u.err)
}

// reportChannels prints one line per channel on stderr, then how many did not
// get the digest (the digest is recorded anyway), and returns that number.
func reportChannels(deps *Deps, deliveries []notify.Delivery) int {
	failed := reportChannelLines(deps, deliveries)
	if failed > 0 {
		fmt.Fprintln(deps.Stderr, deps.N("cli.digest.channels_failed", failed))
	}
	return failed
}

// reportChannelLines prints one line per channel on stderr and returns how many
// failed.
func reportChannelLines(deps *Deps, deliveries []notify.Delivery) int {
	failed := 0
	for _, dl := range deliveries {
		switch dl.Result {
		case notify.ResultOK:
			fmt.Fprintln(deps.Stderr, deps.T("cli.notify.sent", dl.Name, deps.T("notify.type."+dl.Type)))
		case notify.ResultSkipped:
			fmt.Fprintln(deps.Stderr, deps.T("cli.notify.skipped", dl.Name))
		default:
			failed++
			fmt.Fprintln(deps.Stderr, channelMessage(deps, dl))
		}
	}
	return failed
}

// channelMessage says what failed on a channel, why, and what to do.
func channelMessage(deps *Deps, dl notify.Delivery) string {
	kind := deps.T("notify.type." + dl.Type)
	var denied *notify.DeniedError
	var missing *notify.SecretMissingError
	switch {
	case errors.As(dl.Err, &denied):
		return deps.T("cli.notify.failed_rule", dl.Name, kind, denied.Host, denied.Purpose)
	case errors.As(dl.Err, &missing):
		return deps.T("cli.notify.failed_secret", dl.Name, kind, missing.Name)
	}
	return deps.T("cli.notify.failed_other", dl.Name, kind, scan.SanitizeText(dl.Error))
}
