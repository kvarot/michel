package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func newProjectCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{Use: "project", Short: "Register the projects Michel watches"}
	c.AddCommand(newProjectAddCmd(deps), newProjectListCmd(deps), newProjectRemoveCmd(deps), newProjectSetCmd(deps))
	return c
}

func projectRepo(deps *Deps) *project.Repo {
	r := project.NewRepo(deps.Store)
	r.DefaultClassification = deps.Policy().Sovereignty.DataClassification
	return r
}

// addDenialMessage turns a refusal of project.Register into a plain-language
// message in deps.Lang. The audit keeps the key of the reason.
func addDenialMessage(deps *Deps, path, name string, re *project.RefusalError) string {
	switch re.Key {
	case "api.project.bad_name":
		if name == "" {
			return deps.T("cli.project.add.empty_name")
		}
		return deps.T("cli.project.add.refused", deps.T(re.Key), deps.T(re.Key+"_hint"))
	case "api.project.relative_path", "api.project.forbidden_path":
		return deps.T("cli.project.add.refused", deps.T(re.Key), deps.T(re.Key+"_hint"))
	case "api.project.not_dir":
		return deps.T("cli.project.add.not_dir", scan.SanitizeText(path))
	case "api.project.duplicate":
		if errors.Is(re, project.ErrDuplicateFolder) {
			return deps.T("cli.project.add.duplicate_folder")
		}
		return deps.T("cli.project.add.duplicate", name, name)
	case "cli.project.add.bad_fix_level":
		return deps.T("cli.project.add.bad_fix_level")
	case "cli.project.add.bad_classification":
		return deps.T("cli.project.add.bad_classification")
	case "cli.project.add.bad_exclude":
		return deps.T("cli.project.add.bad_exclude", re.Err)
	case "cli.project.add.bad_tech":
		return deps.T("cli.project.add.bad_tech", re.Err)
	}
	return deps.T("cli.project.add.invalid", re)
}

// addFailure is the error michel project add shows for a failure of
// project.Register, which has already written its trace (or says it could not).
func addFailure(deps *Deps, path, name string, err error) error {
	var re *project.RefusalError
	var ae *project.AuditError
	unaudited := errors.As(err, &ae)
	msg := ""
	switch {
	case errors.As(err, &re):
		msg = addDenialMessage(deps, path, name, re)
	case unaudited && ae.After == nil:
		// Added, then purged: no project without its trace.
		return deps.Wrapf("cli.project.add.audit_failed", ae.Err, name)
	case unaudited:
		msg = deps.T("cli.project.add.save_failed", ae.After)
	default:
		msg = deps.T("cli.project.add.save_failed", err)
	}
	if unaudited {
		return deps.Wrapf("cli.common.audit_also", ae.Err, msg)
	}
	return errors.New(msg)
}

func newProjectAddCmd(deps *Deps) *cobra.Command {
	var name, class, testCmd, installCmd string
	var corePkgs, exclude, tech []string
	var fixLevel int
	var autoFixMinor bool
	c := &cobra.Command{
		Use:   "add <path>",
		Short: "Register a local project folder",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			// The one difference with the page: a relative path is made
			// absolute first.
			path, err := filepath.Abs(args[0])
			if err != nil {
				path = args[0]
			}
			dataDir, _ := cmd.Flags().GetString("data-dir")
			if abs, err := filepath.Abs(dataDir); err == nil && dataDir != "" {
				dataDir = abs
			}
			home, _ := userHomeDir()
			added, err := project.Register(ctx, projectRepo(deps), deps.Audit, project.RegisterRequest{
				Actor: "cli", Name: name, Path: path, Classification: policy.Classification(class),
				FixLevel: fixLevel, FixLevelSet: cmd.Flags().Changed("fix-level"),
				AutoFixMinor: autoFixMinor,
				TestCmd:      testCmd, InstallCmd: installCmd,
				CorePackages: cleanList(corePkgs), Exclude: cleanList(exclude), Tech: cleanList(tech),
				Folders: project.Folders{DataDir: dataDir, Home: home},
			})
			if err != nil {
				return addFailure(deps, path, strings.TrimSpace(name), err)
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(added)
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.project.add.done", added.Name, added.Path, added.Classification, added.FixLevel))
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&name, "name", "", "unique name of the project (required)")
	f.StringVar(&class, "classification", "", "data classification: public, internal, confidential, sensitive, health (default: from the policy)")
	f.IntVar(&fixLevel, "fix-level", 1, "how far Michel may go to fix a finding, 0 to 3")
	f.BoolVar(&autoFixMinor, "auto-fix-minor", false, "let Michel start fixes alone for minor and patch updates (needs --fix-level 2)")
	f.StringVar(&testCmd, "test-cmd", "", "command that runs the project's tests")
	f.StringVar(&installCmd, "install-cmd", "", "command that installs the project's dependencies")
	f.StringArrayVar(&corePkgs, "core-package", nil, "package whose upgrade is riskier for this project (repeatable)")
	f.StringArrayVar(&exclude, "exclude", nil, "folder name that scans and analyses skip, at any depth, besides node_modules, vendor and .git (repeatable)")
	f.StringArrayVar(&tech, "tech", nil, "technology the project runs on, for example nginx or postgresql (repeatable)")
	return c
}

func newProjectListCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered projects",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			list, err := projectRepo(deps).List(cmd.Context())
			if err != nil {
				return err
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(list)
			}
			tw := tabwriter.NewWriter(deps.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "name\tclassification\tfix_level\tactive\tpath")
			for _, p := range list {
				fmt.Fprintf(tw, "%s\t%s\t%d\t%t\t%s\n", p.Name, p.Classification, p.FixLevel, p.Active, p.Path)
			}
			return tw.Flush()
		},
	}
}

func newProjectRemoveCmd(deps *Deps) *cobra.Command {
	var purge bool
	c := &cobra.Command{
		Use:   "remove <name>",
		Short: "Stop watching a project (its folder is not touched)",
		Long: "Remove deactivates a project: it is no longer scanned by 'michel scan --all', and its scans and findings " +
			"are kept as history. With --purge, the project and its whole history (scans and findings) are deleted for good.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, arg := cmd.Context(), args[0]
			mode := "deactivate"
			if purge {
				mode = "purge"
			}
			repo := projectRepo(deps)
			var p project.Project
			var err error
			if purge {
				// What the fix service keeps outside the tables goes first
				// (the attempts are still listed): mask tables, tokens,
				// copies, mirrors, briefs.
				if p0, gerr := repo.Get(ctx, arg); gerr == nil {
					// The rule of its Git service goes before all that, and needs no
					// secret: once the row is deleted, nobody would own it.
					if rerr := fix.ReleaseProjectRule(ctx, fixDeps(cmd, deps, nil, "cli"), p0.ID); rerr != nil {
						msg := deps.T("cli.project.remove.rule_failed", p0.Name, rerr)
						if _, aerr := deps.Audit.Record(ctx, audit.Event{
							Actor: "cli", Action: "project.remove", Target: arg, Result: "error",
							Evidence: map[string]any{"mode": mode, "reason": i18n.T(i18n.EN, "cli.project.remove.rule_failed", p0.Name, rerr)},
						}); aerr != nil {
							return deps.Wrapf("cli.common.audit_also", aerr, msg)
						}
						return errors.New(msg)
					}
					secrets, serr := openSecrets(cmd, deps)
					if serr == nil {
						serr = fix.PurgeProject(ctx, fixDeps(cmd, deps, secrets, "cli"), p0.ID)
					}
					if serr != nil {
						fmt.Fprintln(deps.Stderr, deps.T("cli.project.remove.fix_files_failed", p0.Name, serr))
					}
				}
				p, err = repo.Purge(ctx, arg)
			} else {
				p, err = repo.Remove(ctx, arg)
			}
			if err != nil {
				// The audit log keeps the English reason; the user reads it in their language.
				result := "error"
				reason, msg := i18n.T(i18n.EN, "cli.project.remove.failed", arg, err), deps.T("cli.project.remove.failed", arg, err)
				if errors.Is(err, project.ErrNotFound) {
					result = "not_found"
					reason, msg = i18n.T(i18n.EN, "cli.project.remove.not_found", arg), deps.T("cli.project.remove.not_found", arg)
				}
				if _, aerr := deps.Audit.Record(ctx, audit.Event{
					Actor: "cli", Action: "project.remove", Target: arg, Result: result,
					Evidence: map[string]any{"mode": mode, "reason": reason},
				}); aerr != nil {
					return deps.Wrapf("cli.common.audit_also", aerr, msg)
				}
				return errors.New(msg)
			}
			if _, err := deps.Audit.Record(ctx, audit.Event{
				Actor: "cli", Action: "project.remove", Target: p.Name, Result: "ok",
				Evidence: map[string]any{
					"mode": mode, "path": p.Path, "classification": string(p.Classification), "fix_level": p.FixLevel,
				},
			}); err != nil {
				return deps.Wrapf("cli.project.remove.audit_failed", err, p.Name, mode)
			}
			switch {
			case purge:
				fmt.Fprintln(deps.Stdout, deps.T("cli.project.remove.purged", p.Name, p.Path))
			case !p.Active:
				fmt.Fprintln(deps.Stdout, deps.T("cli.project.remove.already_inactive", p.Name, p.Name))
			default:
				fmt.Fprintln(deps.Stdout, deps.T("cli.project.remove.done", p.Name, p.Name))
			}
			return nil
		},
	}
	c.Flags().BoolVar(&purge, "purge", false, "also delete the project's scans and findings (history is lost)")
	return c
}

// cleanList trims, drops empty entries and removes duplicates, keeping order.
func cleanList(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// changedFlags names the settings flags of project set that were passed.
func changedFlags(fl *pflag.FlagSet) []string {
	var fields []string
	for _, f := range []string{"core-package", "exclude", "tech", "risk", "fix-level", "auto-fix-minor", "auto-scan", "classification", "test-cmd", "install-cmd"} {
		if fl.Changed(f) {
			fields = append(fields, f)
		}
	}
	return fields
}

// setError turns a failure of project.Update into a message in the user's
// language.
func setError(deps *Deps, name string, err error) error {
	var auditErr *project.AuditError
	if errors.As(err, &auditErr) {
		if auditErr.After == nil {
			return deps.Wrapf("cli.project.set.audit_failed", auditErr.Err, name)
		}
		return deps.Wrapf("cli.common.audit_also", auditErr.Err, setError(deps, name, auditErr.After).Error())
	}
	var refusal *project.RefusalError
	var thr *project.ThresholdError
	switch {
	case errors.As(err, &thr):
		return deps.Errorf("cli.project.set.bad_thresholds", name, thr.AutoFixBelow, thr.HandoffUpTo)
	case errors.As(err, &refusal) && refusal.Key == "api.project.patch.nothing":
		return deps.Errorf("cli.project.set.nothing")
	case errors.As(err, &refusal):
		return deps.Errorf("cli.project.set.failed", name, err)
	case errors.Is(err, project.ErrNotFound):
		return deps.Errorf("cli.project.set.not_found", name)
	}
	return deps.Errorf("cli.project.set.save_failed", name, err)
}

func newProjectSetCmd(deps *Deps) *cobra.Command {
	var corePkgs, risk, exclude, tech []string
	var class, testCmd, installCmd string
	var fixLevel int
	var autoFixMinor, autoScan bool
	c := &cobra.Command{
		Use:   "set <name>",
		Short: "Change the settings of a registered project",
		Long: "Set changes only the settings you pass. --core-package replaces the whole list of core packages " +
			"(repeat it for several; pass --core-package '' to clear). --exclude replaces the list of folder names skipped by scans and " +
			"analyses the same way (--exclude '' clears it), and --tech the list of technologies the project runs on (--tech '' clears it). --risk key=value replaces one risk-score value " +
			"for this project (see docs/remediation-risk.md); other keys keep their previous override. --auto-scan=false takes the project " +
			"out of the daily watch of michel serve (it can still be checked by hand).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, name := cmd.Context(), args[0]
			fl := cmd.Flags()
			var pt project.Patch
			if fl.Changed("core-package") {
				v := cleanList(corePkgs)
				pt.CorePackages = &v
			}
			if fl.Changed("exclude") {
				v := cleanList(exclude)
				pt.Exclude = &v
			}
			if fl.Changed("tech") {
				v := cleanList(tech)
				pt.Tech = &v
			}
			for _, kv := range risk {
				k, v, ok := strings.Cut(kv, "=")
				n, convErr := strconv.Atoi(strings.TrimSpace(v))
				if !ok || convErr != nil {
					// Not a setting yet: the audit keeps the refusal.
					msg := deps.T("cli.project.set.bad_risk", name, kv)
					ev := map[string]any{"reason": "cli.project.set.bad_risk"}
					if _, aerr := deps.Audit.Record(ctx, audit.Event{Actor: "cli", Action: "project.update",
						Target: name, Result: "denied", Evidence: ev}); aerr != nil {
						return deps.Wrapf("cli.common.audit_also", aerr, msg)
					}
					return errors.New(msg)
				}
				if pt.RiskOverrides == nil {
					pt.RiskOverrides = map[string]int{}
				}
				pt.RiskOverrides[strings.TrimSpace(k)] = n
			}
			if fl.Changed("fix-level") {
				pt.FixLevel = &fixLevel
			}
			if fl.Changed("auto-fix-minor") {
				pt.AutoFixMinor = &autoFixMinor
			}
			if fl.Changed("auto-scan") {
				pt.AutoScan = &autoScan
			}
			if fl.Changed("classification") {
				c := policy.Classification(class)
				pt.Classification = &c
			}
			if fl.Changed("test-cmd") {
				pt.TestCmd = &testCmd
			}
			if fl.Changed("install-cmd") {
				pt.InstallCmd = &installCmd
			}
			baseRisk := deps.Policy().Risk
			p, err := project.Update(ctx, projectRepo(deps), deps.Audit, project.UpdateRequest{
				Actor: "cli", Name: name, Patch: pt, Risk: &baseRisk, AllowInactive: true,
			})
			if err != nil {
				return setError(deps, name, err)
			}
			fields := changedFlags(fl)
			fmt.Fprintln(deps.Stdout, deps.T("cli.project.set.done", p.Name, strings.Join(fields, ", ")))
			if fl.Changed("core-package") || fl.Changed("risk") || fl.Changed("exclude") {
				// The stored analyses no longer match these settings (their
				// inputs hash differs): say when they are refreshed.
				fmt.Fprintln(deps.Stdout, deps.T("cli.project.set.recompute", p.Name))
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringArrayVar(&corePkgs, "core-package", nil, "package whose upgrade is riskier for this project (repeatable; replaces the list)")
	f.StringArrayVar(&exclude, "exclude", nil, "folder name that scans and analyses skip, at any depth (repeatable; replaces the list)")
	f.StringArrayVar(&tech, "tech", nil, "technology the project runs on, for example nginx (repeatable; replaces the list)")
	f.StringArrayVar(&risk, "risk", nil, "risk-score override key=value (repeatable), see docs/remediation-risk.md")
	f.IntVar(&fixLevel, "fix-level", 1, "how far Michel may go to fix a finding, 0 to 3")
	f.BoolVar(&autoFixMinor, "auto-fix-minor", false, "let Michel start fixes alone for minor and patch updates (needs fix level 2)")
	f.BoolVar(&autoScan, "auto-scan", true, "let the daily watch of michel serve check the project")
	f.StringVar(&class, "classification", "", "data classification: public, internal, confidential, sensitive, health")
	f.StringVar(&testCmd, "test-cmd", "", "command that runs the project's tests")
	f.StringVar(&installCmd, "install-cmd", "", "command that installs the project's dependencies")
	return c
}
