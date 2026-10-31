package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/notify"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/workcopy"
	"github.com/spf13/cobra"
)

// fixDeps wires the fix service: the store, the audit log, the secret
// store, the gateway, the policy file of --config (the consent writes its
// rules there and a reload hands them to the gateway), the data folder,
// and michel mcp as the agent's only MCP server (this executable with the
// same --data-dir and --config). Proposals waiting for the user are
// announced on the policy's channels.
func fixDeps(cmd *cobra.Command, deps *Deps, secrets secret.Store, actor string) fix.Deps {
	cfg, _ := cmd.Flags().GetString("config")
	dataDir, _ := cmd.Flags().GetString("data-dir")
	exe, err := os.Executable()
	if err != nil {
		exe = "michel"
	}
	mcp := []string{exe, "mcp", "--data-dir", dataDir, "--config", cfg}
	if lang, _ := cmd.Flags().GetString("lang"); lang != "" {
		mcp = append(mcp, "--lang", lang)
	}
	d := fix.Deps{
		Store: deps.Store, Audit: deps.Audit, Secrets: secrets, Gateway: deps.Gateway,
		Policy: deps.Policy, PolicyPath: cfg,
		Reload: func() (policy.Policy, error) {
			p, src, err := policy.Load(cfg, dataDir)
			if err == nil {
				err = policy.Validate(p)
			}
			if err == nil {
				deps.Policy, deps.PolicySource = p, src
			}
			return p, err
		},
		DataDir: dataDir, OSVRoot: dbRoot(cmd, deps), Lang: deps.Lang,
		MCPCommand: mcp, Work: workcopy.Deps{DataDir: dataDir},
		Now: deps.Now, Actor: actor,
		// A session ends at its time limit or at its turn cap (spec § 7.1).
		MaxTurns: fix.DefaultMaxTurns,
	}
	d.Notify = func(ctx context.Context, waiting int) {
		nd, err := notifyDeps(cmd, deps, false)
		if err != nil {
			return
		}
		nd.Secrets = secrets
		ns, err := notify.Build(deps.Policy.Notify, nd)
		if err != nil {
			return
		}
		notify.SendFixWaiting(ctx, ns, waiting, deps.Policy.Notify.PageURL)
	}
	return d
}

func newFixCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{
		Use:   "fix",
		Short: "Prepare, follow, approve or refuse the fixes Claude Code prepares for a finding",
		Long: "Fix drives the fix agent from the command line, like the Fix page of michel serve: prepare starts Claude Code on " +
			"a copy of the project and follows it, status shows an attempt and its proposal, approve creates the branch " +
			"michel/fix-<id> in your repository from the proposal status showed, refuse ends an attempt, clean removes the " +
			"copies Michel no longer needs, and consent gives a project's AI consent. None of them is needed to use the page.",
	}
	c.AddCommand(newFixPrepareCmd(deps), newFixStatusCmd(deps), newFixApproveCmd(deps), newFixRefuseCmd(deps),
		newFixCleanCmd(deps), newFixConsentCmd(deps))
	return c
}

// fixService is the fix service of a command: the shared wiring with the
// secret store opened and this process's own agents.
func fixService(cmd *cobra.Command, deps *Deps) (fix.Deps, error) {
	secrets, err := openSecrets(cmd, deps)
	if err != nil {
		return fix.Deps{}, err
	}
	d := fixDeps(cmd, deps, secrets, "cli")
	d.Sessions = fix.NewSessions()
	return d, nil
}

// fixError is a refusal of the fix service in the user's language, hint
// added, or err itself.
func fixError(deps *Deps, err error, hint string) error {
	if fix.ErrorKey(err) == "" {
		return err
	}
	msg := fix.Explain(deps.Lang, err)
	if hint != "" {
		msg += " " + hint
	}
	return &wrapError{msg: msg, err: err}
}

// resolveAttempt finds an attempt by its id or a unique start of it.
func resolveAttempt(ctx context.Context, deps *Deps, idOrPrefix string) (fix.Attempt, error) {
	repo := fix.NewRepo(deps.Store)
	idOrPrefix = strings.TrimSpace(idOrPrefix)
	if a, err := repo.GetAttempt(ctx, idOrPrefix); err == nil {
		return a, nil
	} else if !errors.Is(err, fix.ErrNotFound) {
		return fix.Attempt{}, err
	}
	list, err := repo.ListAttempts(ctx, "", "")
	if err != nil {
		return fix.Attempt{}, err
	}
	var match []fix.Attempt
	for _, a := range list {
		if idOrPrefix != "" && strings.HasPrefix(strings.ToLower(a.ID), strings.ToLower(idOrPrefix)) {
			match = append(match, a)
		}
	}
	switch len(match) {
	case 1:
		return match[0], nil
	case 0:
		return fix.Attempt{}, deps.Errorf("cli.fix.not_found", scan.SanitizeText(idOrPrefix))
	default:
		return fix.Attempt{}, deps.Errorf("cli.fix.ambiguous", scan.SanitizeText(idOrPrefix), len(match))
	}
}

// shownFile keeps the hash of the proposal michel fix status last showed
// for an attempt: michel fix approve without --hash approves that one.
func shownFile(cmd *cobra.Command, attemptID string) string {
	dataDir, _ := cmd.Flags().GetString("data-dir")
	return filepath.Join(dataDir, "fix-shown", strings.ToLower(attemptID))
}

// roleLabel is how the terminal names the author of a message.
func roleLabel(deps *Deps, role string) string {
	switch role {
	case fix.RoleUser:
		return deps.T("cli.fix.role.user")
	case fix.RoleAgent:
		return deps.T("cli.fix.role.agent")
	case fix.RoleTool:
		return deps.T("cli.fix.role.tool")
	}
	return deps.T("cli.fix.role.michel")
}

func testsLabel(deps *Deps, status string) string {
	switch status {
	case workcopy.TestsPassed:
		return deps.T("cli.fix.tests.passed")
	case workcopy.TestsFailed:
		return deps.T("cli.fix.tests.failed")
	}
	return deps.T("cli.fix.tests.not_run")
}

// printMessage prints one line of the conversation, indented.
func printMessage(deps *Deps, m fix.Message) {
	text := strings.ReplaceAll(scan.SanitizeText(m.Text), "\n", "\n    ")
	fmt.Fprintf(deps.Stdout, "  [%s] %s\n", roleLabel(deps, m.Role), text)
}

// printAttempt prints an attempt, its current proposal and its
// conversation; the hash of a proposal waiting for the user is kept for
// michel fix approve.
func printAttempt(cmd *cobra.Command, deps *Deps, a fix.Attempt, withDiff bool) error {
	ctx := context.WithoutCancel(cmd.Context())
	repo := fix.NewRepo(deps.Store)
	prop, hasProp, err := repo.CurrentProposal(ctx, a.ID)
	if err != nil {
		return err
	}
	msgs, err := repo.ListMessages(ctx, a.ID)
	if err != nil {
		return err
	}
	if hasProp && a.State == fix.StateProposed {
		if err := writeFileAtomic(shownFile(cmd, a.ID), []byte(prop.Hash+"\n")); err != nil {
			return err
		}
	}
	if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
		out := map[string]any{"attempt": a, "proposal": nil, "messages": msgs}
		if hasProp {
			out["proposal"] = prop
		}
		return json.NewEncoder(deps.Stdout).Encode(out)
	}
	w := deps.Stdout
	fmt.Fprintln(w, deps.T("cli.fix.status.head", a.ID, a.State))
	if fi, err := scan.NewRepo(deps.Store).FindByIDPrefix(ctx, a.FindingID); err == nil && len(fi) > 0 {
		name := ""
		if p, err := project.NewRepo(deps.Store).Get(ctx, a.ProjectID); err == nil {
			name = p.Name
		}
		fmt.Fprintln(w, deps.T("cli.fix.status.finding", scan.SanitizeText(fi[0].Package), scan.SanitizeText(fi[0].OSVID),
			scan.SanitizeText(fi[0].InstalledVersion), name))
	}
	if a.Cause != "" {
		fmt.Fprintln(w, deps.T("cli.fix.status.cause", scan.SanitizeText(a.Cause)))
	}
	if hasProp {
		fmt.Fprintln(w, deps.T("cli.fix.status.proposal", scan.SanitizeText(prop.Summary)))
		fmt.Fprintln(w, deps.T("cli.fix.status.files", strings.Join(scan.SanitizeAll(prop.Files), ", ")))
		rescan := deps.T("cli.fix.status.rescan_dirty")
		if prop.RescanClean {
			rescan = deps.T("cli.fix.status.rescan_clean")
		}
		fmt.Fprintln(w, deps.T("cli.fix.status.tests", testsLabel(deps, prop.TestsStatus), rescan))
		if a.State == fix.StateProposed {
			fmt.Fprintln(w, deps.T("cli.fix.status.hash", prop.Hash, a.ID))
		}
		if withDiff {
			fmt.Fprintln(w, scan.SanitizeText(prop.Diff))
		}
	}
	switch a.State {
	case fix.StateApplied, fix.StateProvenFixed, fix.StateInconclusive:
		fmt.Fprintln(w, deps.T("cli.fix.status.branch", fix.Branch(a.ID)))
	}
	if len(msgs) > 0 {
		fmt.Fprintln(w, deps.T("cli.fix.status.messages"))
		for _, m := range msgs {
			printMessage(deps, m)
		}
	}
	return nil
}

func newFixPrepareCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "prepare <finding-id-or-prefix>",
		Short: "Start Claude Code on a copy of the project to fix one finding, and follow it",
		Long: "Prepare starts a fix attempt like the Fix button of the page: Michel copies the project into its data folder, " +
			"runs its own update, and starts Claude Code on the copy with the brief of the finding. It then prints the " +
			"conversation as it comes, until the agent ends (Ctrl+C stops the agent). The project needs its AI consent " +
			"first (michel fix consent). Nothing is written in your project: michel fix approve does that.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			fi, p, err := resolveFinding(ctx, deps, args[0])
			if err != nil {
				return err
			}
			d, err := fixService(cmd, deps)
			if err != nil {
				return err
			}
			a, err := fix.Start(ctx, d, fi.ID, fix.OriginAgent)
			if err != nil {
				hint := ""
				if errors.Is(err, fix.ErrConsentRequired) {
					hint = deps.T("cli.fix.consent_hint", p.Name)
				}
				if a.ID != "" && fix.ErrorKey(err) == "" {
					// The attempt exists and failed: its cause says why.
					if perr := printAttempt(cmd, deps, a, false); perr != nil {
						return perr
					}
				}
				return fixError(deps, err, hint)
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.fix.prepare.started", a.ID, scan.SanitizeText(fi.Package), p.Name))
			repo := fix.NewRepo(deps.Store)
			seen := map[string]bool{}
			show := func() {
				msgs, err := repo.ListMessages(context.WithoutCancel(ctx), a.ID)
				if err != nil {
					return
				}
				for _, m := range msgs {
					if !seen[m.ID] {
						seen[m.ID] = true
						printMessage(deps, m)
					}
				}
			}
			for {
				show()
				if d.Sessions.Wait(a.ID, time.Second) {
					break
				}
				if ctx.Err() != nil {
					d.Sessions.Close(a.ID)
					break
				}
			}
			show()
			fmt.Fprintln(deps.Stdout, deps.T("cli.fix.prepare.ended"))
			got, err := repo.GetAttempt(context.WithoutCancel(ctx), a.ID)
			if err != nil {
				return err
			}
			return printAttempt(cmd, deps, got, false)
		},
	}
}

func newFixStatusCmd(deps *Deps) *cobra.Command {
	var diff bool
	c := &cobra.Command{
		Use:   "status [<attempt-id-or-prefix>]",
		Short: "List the fix attempts, or show one with its proposal and its conversation",
		Long: "Status without an argument lists the fix attempts, newest first. With an attempt, it shows its state, its " +
			"current proposal (summary, files, tests, re-scan, hash) and its conversation; --diff adds the change. The " +
			"proposal it shows is the one michel fix approve approves without --hash.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if len(args) == 1 {
				a, err := resolveAttempt(ctx, deps, args[0])
				if err != nil {
					return err
				}
				return printAttempt(cmd, deps, a, diff)
			}
			list, err := fix.NewRepo(deps.Store).ListAttempts(ctx, "", "")
			if err != nil {
				return err
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(list)
			}
			if len(list) == 0 {
				fmt.Fprintln(deps.Stdout, deps.T("cli.fix.status.none"))
				return nil
			}
			names := map[string]string{}
			for _, a := range list {
				pkg, osv := "", ""
				if fi, err := scan.NewRepo(deps.Store).FindByIDPrefix(ctx, a.FindingID); err == nil && len(fi) > 0 {
					pkg, osv = scan.SanitizeText(fi[0].Package), scan.SanitizeText(fi[0].OSVID)
				}
				if _, ok := names[a.ProjectID]; !ok {
					if p, err := project.NewRepo(deps.Store).Get(ctx, a.ProjectID); err == nil {
						names[a.ProjectID] = p.Name
					}
				}
				fmt.Fprintln(deps.Stdout, deps.T("cli.fix.status.row", a.ID, a.State, names[a.ProjectID], pkg, osv))
			}
			return nil
		},
	}
	c.Flags().BoolVar(&diff, "diff", false, "also print the change of the proposal")
	return c
}

func newFixApproveCmd(deps *Deps) *cobra.Command {
	var hash string
	c := &cobra.Command{
		Use:   "approve <attempt-id-or-prefix>",
		Short: "Approve the proposal michel fix status showed, and create its branch in your repository",
		Long: "Approve records your approval of the proposal and creates the branch michel/fix-<id> in your repository " +
			"(objects and a ref in its .git: no checkout, no merge, your working tree is untouched). Without --hash it " +
			"approves the proposal michel fix status last showed, and refuses when the agent replaced it since. Merge the " +
			"branch, then deploy as usual.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := resolveAttempt(ctx, deps, args[0])
			if err != nil {
				return err
			}
			hash := strings.TrimSpace(hash)
			if hash == "" {
				b, err := os.ReadFile(shownFile(cmd, a.ID))
				if err != nil {
					return deps.Errorf("cli.fix.approve.status_first", a.ID)
				}
				hash = strings.TrimSpace(string(b))
			}
			d, err := fixService(cmd, deps)
			if err != nil {
				return err
			}
			if err := fix.Approve(ctx, d, a.ID, hash); err != nil {
				hint := ""
				if errors.Is(err, fix.ErrStaleProposal) {
					hint = deps.T("cli.fix.approve.stale_hint", a.ID)
				}
				return fixError(deps, err, hint)
			}
			if err := fix.Apply(ctx, d, a.ID); err != nil {
				if fix.ErrorKey(err) != "" {
					return fixError(deps, err, "")
				}
				return deps.Wrapf("cli.fix.approve.apply_failed", err)
			}
			_ = os.Remove(shownFile(cmd, a.ID))
			fmt.Fprintln(deps.Stdout, deps.T("fix.msg.applied", fix.Branch(a.ID)))
			return nil
		},
	}
	c.Flags().StringVar(&hash, "hash", "", "the hash of the proposal to approve (default: the one michel fix status showed)")
	return c
}

func newFixRefuseCmd(deps *Deps) *cobra.Command {
	var reason string
	c := &cobra.Command{
		Use:   "refuse <attempt-id-or-prefix>",
		Short: "Refuse a fix attempt: the agent stops and the finding goes back to your decisions",
		Long: "Refuse ends the attempt: its agent stops, its copy is removed and nothing is applied. The finding is not " +
			"ignored: it waits for your decision as before. --reason is kept as the cause of the attempt.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := resolveAttempt(ctx, deps, args[0])
			if err != nil {
				return err
			}
			d, err := fixService(cmd, deps)
			if err != nil {
				return err
			}
			if err := fix.Refuse(ctx, d, a.ID, reason); err != nil {
				return fixError(deps, err, "")
			}
			_ = os.Remove(shownFile(cmd, a.ID))
			fmt.Fprintln(deps.Stdout, deps.T("cli.fix.refuse.done", a.ID))
			return nil
		},
	}
	c.Flags().StringVar(&reason, "reason", "", "why you refuse (kept as the cause of the attempt)")
	return c
}

func newFixCleanCmd(deps *Deps) *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "clean",
		Short: "Remove the copies and temporary files of the fixes that are over",
		Long: "Clean removes from Michel's data folder the copies, mirrors and temporary files of the finished fix " +
			"attempts, the agents' generated files, and the conversations older than 30 days; an attempt left preparing " +
			"by a stopped Michel ends failed. It refuses while an agent may be working (michel serve or michel fix " +
			"prepare running): stop them first, or pass --force.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			d, err := fixService(cmd, deps)
			if err != nil {
				return err
			}
			if !force {
				preparing, err := fix.NewRepo(deps.Store).ListAttempts(ctx, "", string(fix.StatePreparing))
				if err != nil {
					return err
				}
				if len(preparing) > 0 {
					return deps.Errorf("cli.fix.clean.busy", preparing[0].ID)
				}
				// The token of a session lives while its agent runs.
				names, err := d.Secrets.List()
				if err != nil {
					return err
				}
				for _, n := range names {
					if id, ok := strings.CutPrefix(n, "fix-token-"); ok {
						return deps.Errorf("cli.fix.clean.busy", strings.ToUpper(id))
					}
				}
			}
			if err := fix.Sweep(ctx, d); err != nil {
				return deps.Wrapf("cli.serve.fix_sweep_failed", err)
			}
			dataDir, _ := cmd.Flags().GetString("data-dir")
			_ = os.RemoveAll(filepath.Join(dataDir, "fix-shown"))
			fmt.Fprintln(deps.Stdout, deps.T("cli.fix.clean.done"))
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "clean even if an agent may still be working")
	return c
}

func newFixConsentCmd(deps *Deps) *cobra.Command {
	var yes bool
	c := &cobra.Command{
		Use:   "consent <project>",
		Short: "Show, then give with --yes, a project's AI consent for the fix agent",
		Long: "Consent prints what the fix agent sends out of your computer and what runs on it for this project. With " +
			"--yes it records your consent: the allow rules of Claude Code and of the package registries are written in " +
			"the policy file (--config), external AI providers are turned on, and the consent is audited. A project " +
			"classified health, or a strict_local policy, is refused.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			p, err := project.NewRepo(deps.Store).Get(ctx, args[0])
			if errors.Is(err, project.ErrNotFound) {
				return deps.Errorf("cli.fix.project_not_found", scan.SanitizeText(args[0]))
			}
			if err != nil {
				return err
			}
			if p.Classification == policy.ClassHealth {
				return fixError(deps, fix.ErrHealthForbidden, "")
			}
			if deps.Policy.Sovereignty.Mode == policy.ModeStrictLocal {
				return fixError(deps, fix.ErrStrictLocal, "")
			}
			_, _, consented, err := fix.NewRepo(deps.Store).Consent(ctx, p.ID)
			if err != nil {
				return err
			}
			lines := fix.ConsentNeeded(p, deps.Policy, consented)
			if consented && len(lines) == 0 {
				fmt.Fprintln(deps.Stdout, deps.T("cli.fix.consent.already", p.Name))
				return nil
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.fix.consent.head", p.Name))
			for _, l := range lines {
				text := deps.T(l.What)
				if l.Host != "" {
					text = deps.T(l.What, l.Host)
				}
				fmt.Fprintln(deps.Stdout, "  - "+text)
			}
			if !yes {
				fmt.Fprintln(deps.Stdout, deps.T("cli.fix.consent.confirm"))
				return nil
			}
			if err := fix.GiveConsent(ctx, fixDeps(cmd, deps, nil, "cli"), p.ID); err != nil {
				return fixError(deps, err, "")
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.fix.consent.given", p.Name))
			return nil
		},
	}
	c.Flags().BoolVar(&yes, "yes", false, "give the consent (without it, Michel only shows what you would accept)")
	return c
}
