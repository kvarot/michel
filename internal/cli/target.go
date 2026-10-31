package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/servererr"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/target"
)

// userHomeDir is the folder discovery reads .ssh/config from; replaced in
// tests, which never read the real one.
var userHomeDir = os.UserHomeDir

func newTargetCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{
		Use:   "target",
		Short: "Register the servers Michel checks over SSH",
		Long: "Target registers the servers Michel reads over SSH, read only: it signs in with the keys of your SSH agent " +
			"(never a password, never a private key file), checks the server's fingerprint strictly, and compares what it " +
			"finds with its rules and the distributions' advisories. Adding a server is your consent for the network rules " +
			"it needs (SSH to its host, the GET of its site): Michel writes them in the policy file. Nothing is changed on a " +
			"server by these commands.",
	}
	c.AddCommand(newTargetListCmd(deps), newTargetDiscoverCmd(deps), newTargetAddCmd(deps), newTargetTrustCmd(deps),
		newTargetCheckCmd(deps), newTargetSetCmd(deps), newTargetRemoveCmd(deps))
	return c
}

// targetFailure is the message of an error of the registry, of SSH or of a
// check, in the user's language, with its hint when it has one. The errors
// themselves can hold a socket path or an address: only the sentence of
// their key is printed; an error that is none of them is wrapped under key
// fallback.
func targetFailure(deps *Deps, err error, reach bool) error {
	key := servererr.Key(err)
	if key == "" && reach {
		key = servererr.Unreachable
	}
	if key == "" {
		return deps.Wrapf("cli.target.failed", err)
	}
	msg := deps.T(key)
	if i18n.Has(key + "_hint") {
		msg += " " + deps.T(key+"_hint")
	}
	return errors.New(msg)
}

func targetRecord(cmd *cobra.Command, deps *Deps, action, id, result string, ev map[string]any) error {
	if _, err := deps.Audit.Record(cmd.Context(), audit.Event{Actor: "cli", Action: action, Target: id, Result: result, Evidence: ev}); err != nil {
		return deps.Wrapf("cli.target.audit_failed", err)
	}
	return nil
}

// targetRef finds the server named by arg (its id or its name).
func targetRef(cmd *cobra.Command, deps *Deps, arg string) (target.Target, error) {
	t, err := target.NewRepo(deps.Store).Get(cmd.Context(), arg)
	if err != nil {
		return target.Target{}, targetFailure(deps, err, false)
	}
	return t, nil
}

func asJSON(cmd *cobra.Command) bool {
	j, _ := cmd.Flags().GetBool("json")
	return j
}

func newTargetListCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the registered servers",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			list, err := target.NewRepo(deps.Store).List(cmd.Context())
			if err != nil {
				return targetFailure(deps, err, false)
			}
			if asJSON(cmd) {
				type row struct {
					ID, Name, Host string
					Port           int
					User           string
					Kind, Env      string
					FixLevel       int
					CheckInterval  string
					HostKeyPinned  bool
					Active         bool
					LastCheckAt    time.Time
				}
				rows := []row{}
				for _, t := range list {
					rows = append(rows, row{t.ID, t.Name, t.Host, t.Port, t.User, string(t.Kind), string(t.Env), t.FixLevel,
						target.IntervalText(t.CheckInterval), t.HostKey != "", t.Active, t.LastCheckAt})
				}
				return json.NewEncoder(deps.Stdout).Encode(rows)
			}
			if len(list) == 0 {
				fmt.Fprintln(deps.Stdout, deps.T("cli.target.list.empty"))
				return nil
			}
			tw := tabwriter.NewWriter(deps.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "name\tid\thost\tkind\tenv\tfix_level\tinterval\tactive\tfingerprint\tlast_check")
			for _, t := range list {
				last := "-"
				if !t.LastCheckAt.IsZero() {
					last = t.LastCheckAt.UTC().Format(time.RFC3339)
				}
				pinned := "no"
				if t.HostKey != "" {
					pinned = "yes"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s:%d\t%s\t%s\t%d\t%s\t%t\t%s\t%s\n", t.Name, t.ID, t.Host, t.Port, t.Kind, t.Env, t.FixLevel,
					target.IntervalText(t.CheckInterval), t.Active, pinned, last)
			}
			return tw.Flush()
		},
	}
}

// discover reads the servers of the SSH configuration and of the PhpStorm
// files of the active projects (read only).
func discover(cmd *cobra.Command, deps *Deps) ([]target.Candidate, error) {
	ctx := cmd.Context()
	home, _ := userHomeDir()
	projects, err := project.NewRepo(deps.Store).List(ctx)
	if err != nil {
		return nil, err
	}
	active := projects[:0:0]
	for _, p := range projects {
		if p.Active {
			active = append(active, p)
		}
	}
	existing, err := target.NewRepo(deps.Store).List(ctx)
	if err != nil {
		return nil, err
	}
	return target.Discover(ctx, home, active, existing)
}

func newTargetDiscoverCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "discover",
		Short: "Find the servers on this computer: the SSH configuration and the PhpStorm files of your projects",
		Long: "Discover reads ~/.ssh/config and the PhpStorm deployment files of the registered projects, and lists the servers " +
			"they name. It only reads: nothing is added until you run 'michel target add'.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cands, err := discover(cmd, deps)
			if err != nil {
				return deps.Wrapf("cli.target.discover_failed", err)
			}
			names := map[string]string{}
			if ps, err := project.NewRepo(deps.Store).List(cmd.Context()); err == nil {
				for _, p := range ps {
					names[p.ID] = p.Name
				}
			}
			type row struct {
				Alias, Host string
				Port        int
				User        string
				From        []string
				Projects    []string
				Known       bool
			}
			rows := []row{}
			for _, c := range cands {
				r := row{Alias: c.Alias, Host: c.Host, Port: c.Port, User: c.User, From: c.From, Known: c.Known, Projects: []string{}}
				if r.Port == 0 {
					r.Port = 22
				}
				for _, l := range c.Projects {
					if n := names[l.ProjectID]; n != "" {
						r.Projects = append(r.Projects, n+"="+l.RemoteDir)
					}
				}
				rows = append(rows, r)
			}
			if asJSON(cmd) {
				return json.NewEncoder(deps.Stdout).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(deps.Stdout, deps.T("cli.target.discover.empty"))
				return nil
			}
			tw := tabwriter.NewWriter(deps.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "alias\thost\tport\tuser\tfound_in\tprojects\tadded")
			for _, r := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%t\n", r.Alias, r.Host, r.Port, r.User, strings.Join(r.From, ","), strings.Join(r.Projects, ","), r.Known)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.target.discover.next"))
			return nil
		},
	}
}

// allowTarget writes the network rules the server needs into the policy file
// and hands them to the gateway: adding a server is the user's opt-in.
func allowTarget(cmd *cobra.Command, deps *Deps, t target.Target) (int, error) {
	sd := sourceDeps(cmd, deps)
	n, err := policy.AddAllowRules(sd.PolicyPath, target.AllowRules(t)...)
	if err != nil {
		return 0, err
	}
	p, err := sd.Reload()
	if err != nil {
		return n, err
	}
	deps.Gateway.SetRules(p.Sovereignty.Network.Allow)
	return n, nil
}

func newTargetAddCmd(deps *Deps) *cobra.Command {
	var name, user, kind, env, executor, sudo, siteURL, interval, preprod string
	var port, level int
	c := &cobra.Command{
		Use:   "add <alias|host>",
		Short: "Add a server, from what 'michel target discover' found or by hand",
		Long: "Add registers a server. The argument is the alias or the host of a server 'michel target discover' lists (its " +
			"host, port, user and projects are taken from there; a flag overrides them), or a host you type, which needs " +
			"--user. A new server is checked every 24 hours (--interval manual to check it by hand only) and Michel only " +
			"reports (--level sets how far it may go, 0 to 3). Adding writes the network rules the server needs in the " +
			"policy file. Next, confirm its fingerprint with 'michel target trust'.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, arg := cmd.Context(), strings.TrimSpace(args[0])
			repo := target.NewRepo(deps.Store)
			fl := cmd.Flags()
			t := target.Target{Host: arg, Name: name, User: user, Port: port, Kind: target.Kind(kind), Env: target.Env(env),
				Executor: target.Executor(executor), Sudo: target.SudoMode(sudo), SiteURL: strings.TrimSpace(siteURL), FixLevel: 1}
			var links []target.Link
			if cands, err := discover(cmd, deps); err == nil {
				for _, c := range cands {
					if !strings.EqualFold(c.Alias, arg) && !strings.EqualFold(c.Host, arg) {
						continue
					}
					t.Alias, t.Host = c.Alias, c.Host
					if !fl.Changed("port") && c.Port != 0 {
						t.Port = c.Port
					}
					if !fl.Changed("user") {
						t.User = c.User
					}
					for _, l := range c.Projects {
						links = append(links, target.Link{ProjectID: l.ProjectID, RemoteDir: l.RemoteDir})
					}
					break
				}
			}
			if t.Name == "" {
				t.Name = t.Alias
			}
			if t.Name == "" {
				t.Name = t.Host
			}
			if strings.TrimSpace(t.User) == "" {
				return deps.Errorf("cli.target.add.need_user", arg)
			}
			if t.Kind == "" {
				t.Kind = target.KindVPS
			}
			if fl.Changed("level") {
				t.FixLevel = level
			}
			var err error
			if t.CheckInterval, err = target.ParseInterval(interval); err != nil {
				return targetFailure(deps, err, false)
			}
			if err := target.ValidateSiteURL(t.SiteURL); err != nil {
				return targetFailure(deps, err, false)
			}
			if t.PreprodID, err = repo.ResolvePreprod(ctx, t, preprod); err != nil {
				return targetFailure(deps, err, false)
			}
			added, err := repo.Add(ctx, t)
			if err != nil {
				return targetFailure(deps, err, false)
			}
			for _, l := range links {
				l.TargetID = added.ID
				if err := repo.Link(ctx, l); err != nil {
					_ = repo.Remove(ctx, added.ID)
					return targetFailure(deps, err, false)
				}
			}
			n, err := allowTarget(cmd, deps, added)
			if err != nil {
				_ = repo.Remove(ctx, added.ID)
				return deps.Wrapf("cli.target.add.allow_failed", err)
			}
			if err := targetRecord(cmd, deps, "target.add", added.ID, "ok", map[string]any{"name": added.Name, "kind": string(added.Kind),
				"env": string(added.Env), "fix_level": added.FixLevel, "links": len(links), "rules_written": n}); err != nil {
				return err
			}
			if asJSON(cmd) {
				return json.NewEncoder(deps.Stdout).Encode(added)
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.target.add.done", added.Name, added.User, added.Host, added.Port, added.Kind, added.Env,
				added.FixLevel, target.IntervalText(added.CheckInterval)))
			fmt.Fprintln(deps.Stdout, deps.T("cli.target.add.next", added.Name, added.Name))
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&name, "name", "", "name of the server in Michel (default: its alias, else its host)")
	f.StringVar(&user, "user", "", "SSH user (default: the one of the SSH configuration)")
	f.IntVar(&port, "port", 22, "SSH port")
	f.StringVar(&kind, "kind", "vps", "kind of server: vps, shared or hds (a server that hosts health data)")
	f.StringVar(&env, "env", "prod", "role of the server: prod, preprod or dev")
	f.IntVar(&level, "level", 1, "how far Michel may go to fix a finding, 0 to 3")
	f.StringVar(&executor, "executor", "user", "who runs a fix on the server: user or michel")
	f.StringVar(&sudo, "sudo", "none", "whether the SSH user may use sudo without a password: none or nopasswd")
	f.StringVar(&siteURL, "site-url", "", "address of the site, which Michel checks answers after a fix")
	f.StringVar(&interval, "interval", "", "time between two checks: a duration such as 12h, or manual (default 24h)")
	f.StringVar(&preprod, "preprod", "", "the preprod server a fix is tried on first (its name or id)")
	return c
}

func newTargetTrustCmd(deps *Deps) *cobra.Command {
	var fingerprint string
	c := &cobra.Command{
		Use:   "trust <id>",
		Short: "Show a server's fingerprint, or confirm it with --fingerprint",
		Long: "Trust connects to the server without signing in and reads the fingerprint of its host key. Without --fingerprint " +
			"it only shows it: compare it with the one your host gives. With --fingerprint, Michel reads it again and saves it " +
			"only if it is the same; from then on it connects to this key only.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			t, err := targetRef(cmd, deps, args[0])
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			fp, typ, err := sshx.FingerprintKey(ctx, sshDeps(deps), t)
			if err != nil {
				return targetFailure(deps, err, true)
			}
			repo := target.NewRepo(deps.Store)
			fingerprint = strings.TrimSpace(fingerprint)
			if fingerprint == "" {
				fmt.Fprintln(deps.Stdout, deps.T("cli.target.trust.show", t.Name, typ, fp))
				fmt.Fprintln(deps.Stdout, deps.T("cli.target.trust.next", t.Name, fp))
				return nil
			}
			if fingerprint != fp {
				_ = targetRecord(cmd, deps, "target.hostkey", t.ID, "refused", map[string]any{"name": t.Name, "reason": "fingerprint mismatch"})
				return deps.Errorf("cli.target.trust.mismatch", t.Name)
			}
			if err := repo.SetHostKey(cmd.Context(), t.ID, fp); err != nil {
				return targetFailure(deps, err, false)
			}
			if err := targetRecord(cmd, deps, "target.hostkey", t.ID, "ok", map[string]any{"name": t.Name, "fingerprint": fp,
				"replaced": t.HostKey != "" && t.HostKey != fp}); err != nil {
				return err
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.target.trust.done", t.Name))
			return nil
		},
	}
	c.Flags().StringVar(&fingerprint, "fingerprint", "", "the fingerprint you read and compared (SHA256:...)")
	return c
}

func newTargetCheckCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "check <id>",
		Short: "Check a server now: read it over SSH and judge what Michel finds",
		Long: "Check connects to the server, reads its system, its PHP and its web server (read only), keeps what it read and " +
			"compares it with its rules and the distributions' advisories. Findings that are new, still open or gone are " +
			"counted; a server never checked has its fingerprint to confirm first ('michel target trust').",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := targetRef(cmd, deps, args[0])
			if err != nil {
				return err
			}
			res, err := servercheck.Check(cmd.Context(), serverCheckDeps(cmd, deps), t.ID)
			if err != nil {
				return targetFailure(deps, err, true)
			}
			if asJSON(cmd) {
				return json.NewEncoder(deps.Stdout).Encode(res)
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.target.check.done", t.Name, res.New, res.Still, res.Gone))
			if res.Unseen > 0 {
				fmt.Fprintln(deps.Stdout, deps.N("cli.target.check.unseen", res.Unseen))
			}
			if res.SourceToEnable != "" {
				fmt.Fprintln(deps.Stdout, deps.T("cli.target.check.source_hint", res.SourceToEnable, res.SourceToEnable))
			}
			if res.Clean() {
				fmt.Fprintln(deps.Stdout, deps.T("cli.target.check.clean"))
			}
			return nil
		},
	}
}

func newTargetSetCmd(deps *Deps) *cobra.Command {
	var executor, sudo, siteURL, interval, preprod string
	var level int
	var active bool
	c := &cobra.Command{
		Use:   "set <id>",
		Short: "Change the settings of a server",
		Long: "Set changes only the settings you pass: --level (0 to 3), --executor (user or michel), --sudo (none or nopasswd), " +
			"--site-url, --interval (a duration such as 12h, or manual) and --preprod (a server's name or id, or '' for none).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			t, err := targetRef(cmd, deps, args[0])
			if err != nil {
				return err
			}
			repo := target.NewRepo(deps.Store)
			fl := cmd.Flags()
			var fields []string
			for _, f := range []string{"level", "executor", "sudo", "site-url", "interval", "preprod", "active"} {
				if fl.Changed(f) {
					fields = append(fields, f)
				}
			}
			if len(fields) == 0 {
				return deps.Errorf("cli.target.set.nothing")
			}
			old := t
			if fl.Changed("level") {
				t.FixLevel = level
			}
			if fl.Changed("executor") {
				t.Executor = target.Executor(executor)
			}
			if fl.Changed("sudo") {
				t.Sudo = target.SudoMode(sudo)
			}
			if fl.Changed("site-url") {
				t.SiteURL = strings.TrimSpace(siteURL)
			}
			if fl.Changed("active") {
				t.Active = active
			}
			if fl.Changed("interval") {
				if t.CheckInterval, err = target.ParseInterval(interval); err != nil {
					return targetFailure(deps, err, false)
				}
			}
			if err := target.ValidateSiteURL(t.SiteURL); err != nil {
				return targetFailure(deps, err, false)
			}
			if fl.Changed("preprod") {
				if t.PreprodID, err = repo.ResolvePreprod(ctx, t, preprod); err != nil {
					return targetFailure(deps, err, false)
				}
			}
			if err := repo.Update(ctx, t); err != nil {
				return targetFailure(deps, err, false)
			}
			rules := 0
			if t.SiteURL != old.SiteURL {
				if rules, err = allowTarget(cmd, deps, t); err != nil {
					return deps.Wrapf("cli.target.set.allow_failed", err)
				}
			}
			if err := targetRecord(cmd, deps, "target.update", t.ID, "ok", map[string]any{"name": t.Name, "changed": fields, "rules_written": rules}); err != nil {
				return err
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.target.set.done", t.Name, strings.Join(fields, ", ")))
			return nil
		},
	}
	f := c.Flags()
	f.IntVar(&level, "level", 1, "how far Michel may go to fix a finding, 0 to 3")
	f.StringVar(&executor, "executor", "", "who runs a fix on the server: user or michel")
	f.StringVar(&sudo, "sudo", "", "whether the SSH user may use sudo without a password: none or nopasswd")
	f.StringVar(&siteURL, "site-url", "", "address of the site, which Michel checks answers after a fix ('' for none)")
	f.StringVar(&interval, "interval", "", "time between two checks: a duration such as 12h, or manual ('' for the default, 24h)")
	f.StringVar(&preprod, "preprod", "", "the preprod server a fix is tried on first (its name or id; '' for none)")
	f.BoolVar(&active, "active", true, "false stops Michel from checking the server")
	return c
}

func newTargetRemoveCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <id>",
		Short: "Take a server out of Michel (nothing is done on the server)",
		Long: "Remove deletes the server from Michel's registry with its links and its stored inventories. Its findings and " +
			"fixes stay as history. Nothing is done on the server itself.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			t, err := targetRef(cmd, deps, args[0])
			if err != nil {
				return err
			}
			for _, st := range []fix.State{fix.StateRunning, fix.StatePreparing} {
				list, err := fix.NewRepo(deps.Store).ListAttempts(ctx, t.ID, string(st))
				if err != nil {
					return targetFailure(deps, err, false)
				}
				if len(list) > 0 {
					return deps.Errorf("cli.target.remove.busy", t.Name)
				}
			}
			if err := target.NewRepo(deps.Store).Remove(ctx, t.ID); err != nil {
				return targetFailure(deps, err, false)
			}
			if err := targetRecord(cmd, deps, "target.remove", t.ID, "ok", map[string]any{"name": t.Name}); err != nil {
				return err
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.target.remove.done", t.Name))
			return nil
		},
	}
}
