package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/source"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newSourceCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{
		Use:   "source",
		Short: "Manage where Michel reads its data: OSV databases, enrichments, feeds, plugins, skills, MCP servers",
	}
	c.AddCommand(newSourceListCmd(deps), newSourceShowCmd(deps), newSourceEnableCmd(deps), newSourceDisableCmd(deps),
		newSourceAddCmd(deps), newSourceRemoveCmd(deps), newSourceResetCmd(deps), newSourceUpdateCmd(deps), newSourceItemsCmd(deps),
		newSourceReadCmd(deps), newSourceInstallCmd(deps), newSourceUpgradeCmd(deps), newSourceDiscoverCmd(deps), newSourceRunCmd(deps))
	return c
}

// sourceDeps wires the consent dependencies: the policy file of --config is
// the one that receives the allow rules, and a reload updates deps.Policy.
func sourceDeps(cmd *cobra.Command, deps *Deps) source.Deps {
	cfg, _ := cmd.Flags().GetString("config")
	dir, _ := cmd.Flags().GetString("data-dir")
	return source.Deps{
		Repo: source.NewRepo(deps.Store), Audit: deps.Audit, Gateway: deps.Gateway, PolicyPath: cfg, Now: deps.Now, Actor: "cli",
		Reload: func() (policy.Policy, error) {
			p, src, err := policy.Load(cfg, dir)
			if err == nil {
				err = policy.Validate(p)
			}
			if err == nil {
				deps.Policy, deps.PolicySource = p, src
			}
			return p, err
		},
	}
}

func (d *Deps) allowed(host, purpose string) bool {
	ok, _ := d.Gateway.Allowed(host, purpose)
	return ok
}

// sourceErr turns a registry error into a message in the user's language.
func sourceErr(deps *Deps, key string, err error) error {
	switch {
	case errors.Is(err, source.ErrNotFound):
		return deps.Errorf("cli.source.not_found", key)
	case errors.Is(err, source.ErrInstalled):
		return deps.Errorf("cli.source.remove.installed", key)
	}
	return deps.Wrapf("cli.source.failed", err, key)
}

// recordSource writes an audit event of the source commands; it never holds
// content, only keys and counts.
func recordSource(cmd *cobra.Command, deps *Deps, action, target, result string, ev map[string]any) error {
	if _, err := deps.Audit.Record(cmd.Context(), audit.Event{
		Actor: "cli", Action: action, Target: target, Result: result, Evidence: ev,
	}); err != nil {
		return deps.Wrapf("cli.source.audit_failed", err, target)
	}
	return nil
}

// sourceView is an entry with its computed state, for --json.
type sourceView struct {
	source.Entry
	State source.State `json:"state"`
}

func newSourceListCmd(deps *Deps) *cobra.Command {
	var kind string
	var all bool
	c := &cobra.Command{
		Use:   "list",
		Short: "List the sources with their kind and state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			k := source.Kind(kind)
			if kind != "" && !k.Valid() {
				return deps.Errorf("cli.source.bad_kind", kind)
			}
			list, err := source.NewRepo(deps.Store).List(cmd.Context(), k, all)
			if err != nil {
				return err
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				views := make([]sourceView, 0, len(list))
				for _, e := range list {
					views = append(views, sourceView{Entry: e, State: e.State(deps.allowed)})
				}
				return json.NewEncoder(deps.Stdout).Encode(views)
			}
			if len(list) == 0 {
				fmt.Fprintln(deps.Stdout, deps.T("cli.source.list.empty"))
				return nil
			}
			tw := tabwriter.NewWriter(deps.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, deps.T("cli.source.list.header"))
			for _, e := range list {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Key, deps.T("source.kind."+string(e.Kind)),
					deps.T("source.state."+string(e.State(deps.allowed))), e.Name)
			}
			return tw.Flush()
		},
	}
	c.Flags().StringVar(&kind, "kind", "", "only this kind: osv, enrichment, feed, plugin, skill, mcp or reference")
	c.Flags().BoolVar(&all, "all", false, "also list the hidden sources")
	return c
}

func newSourceShowCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "show <key>",
		Short: "Show a source: hosts, network rule, settings and last read",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			e, err := source.NewRepo(deps.Store).Get(cmd.Context(), key)
			if err != nil {
				return sourceErr(deps, key, err)
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(sourceView{Entry: e, State: e.State(deps.allowed)})
			}
			out := deps.Stdout
			fmt.Fprintln(out, deps.T("cli.source.show.title", e.Name, e.Key))
			fmt.Fprintln(out, deps.T("cli.source.show.kind", deps.T("source.kind."+string(e.Kind))))
			if e.Origin == source.OriginUser {
				fmt.Fprintln(out, deps.T("cli.source.show.origin_user"))
			} else {
				fmt.Fprintln(out, deps.T("cli.source.show.origin_catalog"))
			}
			fmt.Fprintln(out, deps.T("cli.source.show.state", deps.T("source.state."+string(e.State(deps.allowed)))))
			if e.URL != "" {
				fmt.Fprintln(out, deps.T("cli.source.show.url", e.URL))
			}
			if len(e.Hosts) == 0 {
				fmt.Fprintln(out, deps.T("cli.source.show.no_host"))
			}
			for _, h := range e.Hosts {
				if deps.allowed(h, e.Purpose) {
					fmt.Fprintln(out, deps.T("cli.source.show.host_allowed", h, e.Purpose))
				} else {
					fmt.Fprintln(out, deps.T("cli.source.show.host_missing", h, e.Purpose))
				}
			}
			if len(e.Tech) > 0 {
				fmt.Fprintln(out, deps.T("cli.source.show.tech", strings.Join(e.Tech, ", ")))
			}
			merged := e.Config.Merged()
			names := make([]string, 0, len(merged))
			for k := range merged {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				fmt.Fprintln(out, deps.T("cli.source.show.config", k, merged[k]))
			}
			if e.LastReadAt.IsZero() {
				fmt.Fprintln(out, deps.T("cli.source.show.never_read"))
			} else {
				fmt.Fprintln(out, deps.T("cli.source.show.last_read", e.LastReadAt.Local().Format(time.DateTime), e.LastReadResult, e.LastReadItems))
				if e.LastReadError != "" {
					fmt.Fprintln(out, deps.T("cli.source.show.last_error", e.LastReadError))
				}
			}
			printRepoStatus(deps, e)
			if note := source.NoteKey(e.Key); e.Origin == source.OriginCatalog && i18n.Has(note) {
				fmt.Fprintln(out, deps.T("cli.source.show.note", deps.T(note)))
			}
			return nil
		},
	}
}

// stdinTerminal returns the reader of the commands and whether it is a terminal.
func stdinTerminal(deps *Deps) (*bufio.Reader, bool) {
	in := deps.Stdin
	if in == nil {
		in = os.Stdin
	}
	f, ok := in.(*os.File)
	return bufio.NewReader(in), ok && term.IsTerminal(int(f.Fd()))
}

// yes reports whether an answer accepts (y, yes, o, oui).
func yes(answer string) bool {
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes", "o", "oui":
		return true
	}
	return false
}

func newSourceEnableCmd(deps *Deps) *cobra.Command {
	var assumeYes bool
	c := &cobra.Command{
		Use:   "enable <key>",
		Short: "Turn a source on, after your consent to the hosts it contacts",
		Long: "Enable shows which host the source contacts and why, asks y/N, then writes the matching rule in " +
			"sovereignty.network.allow of the policy file (a copy of the previous file is kept as .bak). " +
			"--yes gives the consent without asking, for scripts. Without a terminal and without --yes, " +
			"Michel refuses (exit code 3) and prints the text to read.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, key := cmd.Context(), args[0]
			sd := sourceDeps(cmd, deps)
			e, texts, err := source.Enable(ctx, sd, key, assumeYes)
			if errors.Is(err, source.ErrConsentRequired) {
				for _, t := range texts {
					fmt.Fprintln(deps.Stderr, deps.T(t.What, t.Host))
					fmt.Fprintln(deps.Stderr, deps.T("cli.source.enable.rule", sd.PolicyPath, t.Host, t.Purpose))
				}
				in, tty := stdinTerminal(deps)
				if !tty {
					if rerr := recordSource(cmd, deps, "source.enable", key, "denied", map[string]any{"key": key, "reason": "consent needed, no terminal and no --yes"}); rerr != nil {
						return rerr
					}
					return &ExitError{Code: ExitCodePolicy, Err: deps.Errorf("cli.source.enable.needs_yes", key, key)}
				}
				fmt.Fprint(deps.Stderr, deps.T("cli.source.enable.prompt"))
				answer, rerr := in.ReadString('\n')
				if rerr != nil && answer == "" {
					return deps.Wrapf("cli.source.enable.read_failed", rerr)
				}
				if !yes(answer) {
					if rerr := recordSource(cmd, deps, "source.enable", key, "denied", map[string]any{"key": key, "reason": "consent refused"}); rerr != nil {
						return rerr
					}
					return &ExitError{Code: ExitCodePolicy, Err: deps.Errorf("cli.source.enable.refused", key)}
				}
				e, texts, err = source.Enable(ctx, sd, key, true)
			}
			if err != nil {
				return sourceErr(deps, key, err)
			}
			switch {
			case len(texts) > 0:
				hosts := make([]string, 0, len(texts))
				for _, t := range texts {
					hosts = append(hosts, t.Host)
				}
				fmt.Fprintln(deps.Stdout, deps.T("cli.source.enable.done_rules", e.Key, strings.Join(hosts, ", "), sd.PolicyPath))
			case len(e.Hosts) > 0:
				shared, _ := source.SharedWith(ctx, sd.Repo, e)
				if len(shared) > 0 {
					fmt.Fprintln(deps.Stdout, deps.T("cli.source.enable.already_shared", e.Key, strings.Join(e.Hosts, ", "), strings.Join(shared, ", ")))
				} else {
					fmt.Fprintln(deps.Stdout, deps.T("cli.source.enable.already_policy", e.Key, strings.Join(e.Hosts, ", ")))
				}
			default:
				fmt.Fprintln(deps.Stdout, deps.T("cli.source.enable.done", e.Key))
			}
			return nil
		},
	}
	c.Flags().BoolVar(&assumeYes, "yes", false, "give the consent without asking (for scripts)")
	return c
}

func newSourceDisableCmd(deps *Deps) *cobra.Command {
	var forget bool
	c := &cobra.Command{
		Use:   "disable <key>",
		Short: "Turn a source off; --forget also removes its network rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, key := cmd.Context(), args[0]
			sd := sourceDeps(cmd, deps)
			err := source.Disable(ctx, sd, key, forget)
			var shared source.ErrRuleShared
			if errors.As(err, &shared) {
				return deps.Errorf("cli.source.disable.shared", key, shared.Key, shared.Key)
			}
			if err != nil {
				return sourceErr(deps, key, err)
			}
			e, err := sd.Repo.Get(ctx, key)
			if err != nil {
				return sourceErr(deps, key, err)
			}
			switch {
			case len(e.Hosts) == 0:
				fmt.Fprintln(deps.Stdout, deps.T("cli.source.disable.done", key))
			case forget:
				fmt.Fprintln(deps.Stdout, deps.T("cli.source.disable.forgotten", key, sd.PolicyPath))
			default:
				fmt.Fprintln(deps.Stdout, deps.T("cli.source.disable.rule_kept", key, key))
			}
			return nil
		},
	}
	c.Flags().BoolVar(&forget, "forget", false, "also remove the network rule from the policy file (refused if another enabled source needs it)")
	return c
}

// addRefusal is the message of a refused user entry (source.NewUserEntry).
func addRefusal(deps *Deps, r *source.Refusal) error {
	switch r.Code {
	case "bad_tag":
		return deps.Errorf("cli.tech.bad_tag", r.Args...)
	case "bad_url":
		return deps.Errorf("cli.source.add.bad_url", r.Args...)
	case "bad_format":
		return deps.Errorf("cli.source.add.bad_format", r.Args...)
	case "bad_repo":
		return deps.Errorf("cli.source.add.bad_repo", r.Args...)
	case "feed_target":
		return deps.Errorf("cli.source.add.feed_target")
	case "no_ecosystem":
		return deps.Errorf("cli.source.add.no_ecosystem")
	case "bad_ecosystem":
		return deps.Errorf("cli.source.add.bad_ecosystem", r.Args...)
	case "no_format":
		return deps.Errorf("cli.source.add.no_format")
	case "bad_tool":
		return deps.Errorf("cli.source.add.bad_tool", r.Args...)
	case "no_name":
		return deps.Errorf("cli.source.add.no_name")
	case "bad_input":
		return deps.Errorf("cli.source.add.bad_input")
	case "no_repo":
		return deps.Errorf("cli.source.add.no_repo", r.Args...)
	case "bad_pin":
		return deps.Errorf("cli.source.add.bad_pin", r.Args...)
	case "bad_path":
		return deps.Errorf("cli.source.add.bad_path", r.Args...)
	case "bad_kind":
		return deps.Errorf("cli.source.add.bad_kind", r.Args...)
	}
	return deps.Wrapf("cli.source.add.invalid", errors.New(r.Code))
}

func newSourceAddCmd(deps *Deps) *cobra.Command {
	var kind, name, rawURL, format, repo, ecosystem, input, tool, path, pin string
	var tech []string
	c := &cobra.Command{
		Use:   "add --kind <kind> ...",
		Short: "Add a source of your own (feed, osv, plugin, skill or mcp); it starts off",
		Long: "Add registers a source of your own. It starts off: michel source enable asks for your consent.\n" +
			"  feed:   --name and --url https://... [--format auto|rss|atom|page], or --repo owner/name --format github_advisories\n" +
			"  osv:    --ecosystem <folder name of the OSV database, for example PyPI>\n" +
			"  plugin: --name and --format sarif|trivy_json [--tool generic|trivy|semgrep|codeql|zap] [--input <report>]\n" +
			"  skill, mcp: --repo owner/name --pin <40-character commit> [--path <folder>] [--name ...]\n" +
			"--tech (repeatable) tags the source with technologies, for the \"to read\" filter.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			req := source.UserEntryRequest{Kind: source.Kind(kind), Name: name, URL: rawURL, Format: format, Repo: repo,
				Ecosystem: ecosystem, Tool: tool, Path: path, Pin: pin, Tech: tech}
			if input != "" {
				// A relative report path is the caller's folder.
				abs, err := filepath.Abs(input)
				if err != nil {
					abs = input
				}
				req.Input = abs
			}
			e, refusal := source.NewUserEntry(req)
			if refusal != nil {
				return addRefusal(deps, refusal)
			}
			repoR := source.NewRepo(deps.Store)
			if _, err := repoR.Get(ctx, e.Key); err == nil {
				return deps.Errorf("cli.source.add.exists", e.Key)
			} else if !errors.Is(err, source.ErrNotFound) {
				return sourceErr(deps, e.Key, err)
			}
			added, err := repoR.Upsert(ctx, e)
			if err != nil {
				return deps.Wrapf("cli.source.add.invalid", err)
			}
			if err := recordSource(cmd, deps, "source.add", added.Key, "ok", map[string]any{"key": added.Key, "kind": string(added.Kind)}); err != nil {
				return err
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.source.add.done", added.Key, added.Key))
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&kind, "kind", "", "kind of the source: feed, osv, plugin, skill or mcp (required)")
	f.StringVar(&name, "name", "", "name shown in the lists; the key is made from it")
	f.StringVar(&rawURL, "url", "", "feed: https address of the feed or page")
	f.StringVar(&format, "format", "", "feed: auto, rss, atom, page or github_advisories; plugin: sarif or trivy_json")
	f.StringVar(&repo, "repo", "", "GitHub repository owner/name (feed of advisories, skill, mcp)")
	f.StringVar(&ecosystem, "ecosystem", "", "osv: folder name of the OSV database, for example PyPI")
	f.StringVar(&input, "input", "", "plugin: report file read by default")
	f.StringVar(&tool, "tool", "", "plugin: generic, trivy, semgrep, codeql or zap (default generic)")
	f.StringVar(&path, "path", "", "skill: folder of the skill inside the repository")
	f.StringVar(&pin, "pin", "", "skill, mcp: full 40-character commit to install")
	f.StringArrayVar(&tech, "tech", nil, "technology tag of the source, for example nginx (repeatable)")
	return c
}

func newSourceRemoveCmd(deps *Deps) *cobra.Command {
	var assumeYes bool
	c := &cobra.Command{
		Use:   "remove <key>",
		Short: "Remove a source: yours is deleted, a catalog one is hidden (reset brings it back)",
		Long: "Remove deletes a source of yours, or hides a catalog source (michel source reset brings it back). An installed " +
			"skill is uninstalled first, after y/N: Michel removes its folder only when it carries Michel's marker for this " +
			"source. --yes confirms without asking, for scripts.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, key := cmd.Context(), args[0]
			r := source.NewRepo(deps.Store)
			e, err := r.Get(ctx, key)
			if err != nil {
				return sourceErr(deps, key, err)
			}
			if e.Config.Str("installed_sha") != "" {
				if err := uninstallSkill(cmd, deps, e, assumeYes); err != nil {
					return err
				}
			}
			mode := "hidden"
			if e.Origin == source.OriginUser {
				mode = "deleted"
				err = r.Delete(ctx, key)
			} else {
				err = r.SetHidden(ctx, key, true)
			}
			if err != nil {
				return sourceErr(deps, key, err)
			}
			if err := recordSource(cmd, deps, "source.remove", key, "ok", map[string]any{"key": key, "mode": mode}); err != nil {
				return err
			}
			if mode == "deleted" {
				fmt.Fprintln(deps.Stdout, deps.T("cli.source.remove.deleted", key))
			} else {
				fmt.Fprintln(deps.Stdout, deps.T("cli.source.remove.hidden", key, key))
			}
			return nil
		},
	}
	c.Flags().BoolVar(&assumeYes, "yes", false, "confirm the uninstallation without asking (for scripts)")
	return c
}

func newSourceResetCmd(deps *Deps) *cobra.Command {
	var all, purgeUser, assumeYes bool
	c := &cobra.Command{
		Use:   "reset [<key> | --all [--purge-user [--yes]]]",
		Short: "Put catalog sources back as the catalog has them",
		Long: "Reset puts a catalog source (or, with --all, every catalog source) back to its catalog state: " +
			"enabled by default or not, shown again, catalog technologies, your settings cleared. Your own sources are kept, " +
			"unless --purge-user is given with --all: Michel then lists them and asks y/N (--yes answers for scripts; " +
			"without a terminal and without --yes, Michel refuses with exit code 3). Network rules and installed skills stay as they are.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if (len(args) == 1) == all {
				return deps.Errorf("cli.source.reset.usage")
			}
			if purgeUser && !all {
				return deps.Errorf("cli.source.reset.purge_needs_all")
			}
			key, target := "", "all"
			if len(args) == 1 {
				key, target = args[0], args[0]
			}
			if purgeUser && !assumeYes {
				if err := confirmPurge(cmd, deps); err != nil {
					return err
				}
			}
			n, err := source.Reset(ctx, source.NewRepo(deps.Store), key, all, purgeUser)
			if errors.Is(err, source.ErrUserEntry) {
				return deps.Errorf("cli.source.reset.user", key, key)
			}
			if err != nil {
				return sourceErr(deps, target, err)
			}
			if err := recordSource(cmd, deps, "source.reset", target, "ok", map[string]any{"key": target, "purge_user": purgeUser, "count": n}); err != nil {
				return err
			}
			fmt.Fprintln(deps.Stdout, deps.N("cli.source.reset.done", n))
			fmt.Fprintln(deps.Stdout, deps.T("cli.source.reset.kept"))
			return nil
		},
	}
	c.Flags().BoolVar(&all, "all", false, "reset every catalog source")
	c.Flags().BoolVar(&purgeUser, "purge-user", false, "with --all, also delete the sources you added (asks for confirmation)")
	c.Flags().BoolVar(&assumeYes, "yes", false, "with --purge-user, confirm without asking (for scripts)")
	return c
}

// confirmPurge lists the user sources that --purge-user deletes and asks y/N
// on a terminal. Without a terminal it refuses (exit code 3): --yes is the
// only way to confirm from a script. It returns nil when the user agrees or
// there is nothing to delete.
func confirmPurge(cmd *cobra.Command, deps *Deps) error {
	list, err := source.NewRepo(deps.Store).List(cmd.Context(), "", true)
	if err != nil {
		return sourceErr(deps, "all", err)
	}
	var keys []string
	for _, e := range list {
		if e.Origin == source.OriginUser {
			keys = append(keys, e.Key)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	fmt.Fprintln(deps.Stderr, deps.N("cli.source.reset.purge_list", len(keys), strings.Join(keys, ", ")))
	refuse := func(reason string) error {
		return recordSource(cmd, deps, "source.reset", "all", "denied", map[string]any{"key": "all", "purge_user": true, "reason": reason})
	}
	in, tty := stdinTerminal(deps)
	if !tty {
		if err := refuse("purge needs confirmation, no terminal and no --yes"); err != nil {
			return err
		}
		return &ExitError{Code: ExitCodePolicy, Err: deps.Errorf("cli.source.reset.purge_needs_yes")}
	}
	fmt.Fprint(deps.Stderr, deps.T("cli.source.enable.prompt"))
	answer, rerr := in.ReadString('\n')
	if rerr != nil && answer == "" {
		return deps.Wrapf("cli.source.enable.read_failed", rerr)
	}
	if !yes(answer) {
		if err := refuse("purge refused"); err != nil {
			return err
		}
		return &ExitError{Code: ExitCodePolicy, Err: deps.Errorf("cli.source.reset.purge_refused")}
	}
	return nil
}
