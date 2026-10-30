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
	"github.com/spf13/cobra"
)

func newProjectCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{Use: "project", Short: "Register the projects Michel watches"}
	c.AddCommand(newProjectAddCmd(deps), newProjectListCmd(deps), newProjectRemoveCmd(deps), newProjectSetCmd(deps))
	return c
}

func projectRepo(deps *Deps) *project.Repo {
	r := project.NewRepo(deps.Store)
	r.DefaultClassification = deps.Policy.Sovereignty.DataClassification
	return r
}

// addDenialMessage turns a validation error into a plain-language message in
// lang. The audit log stores it in English; the user reads it in deps.Lang.
func addDenialMessage(lang i18n.Lang, path, name string, err error) string {
	switch {
	case errors.Is(err, project.ErrNotADirectory):
		return i18n.T(lang, "cli.project.add.not_dir", path)
	case errors.Is(err, project.ErrDuplicateName):
		return i18n.T(lang, "cli.project.add.duplicate", name, name)
	case errors.Is(err, project.ErrEmptyName):
		return i18n.T(lang, "cli.project.add.empty_name")
	case errors.Is(err, project.ErrInvalidFixLevel):
		return i18n.T(lang, "cli.project.add.bad_fix_level")
	case errors.Is(err, project.ErrInvalidClassification):
		return i18n.T(lang, "cli.project.add.bad_classification")
	case errors.Is(err, project.ErrInvalidExclude):
		return i18n.T(lang, "cli.project.add.bad_exclude", err)
	case errors.Is(err, project.ErrInvalidTech):
		return i18n.T(lang, "cli.project.add.bad_tech", err)
	default:
		return i18n.T(lang, "cli.project.add.invalid", err)
	}
}

func newProjectAddCmd(deps *Deps) *cobra.Command {
	var name, class, testCmd, installCmd string
	var corePkgs, exclude, tech []string
	var fixLevel, serverFixLevel int
	var autoFixMinor bool
	c := &cobra.Command{
		Use:   "add <path>",
		Short: "Register a local project folder",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			path, err := filepath.Abs(args[0])
			if err != nil {
				path = args[0]
			}
			path = filepath.Clean(path)
			p := project.Project{
				Name: name, Path: path, Classification: policy.Classification(class),
				FixLevel: fixLevel, FixLevelSet: cmd.Flags().Changed("fix-level"),
				ServerFixLevel: serverFixLevel, ServerFixLevelSet: cmd.Flags().Changed("server-fix-level"),
				AutoFixMinor: autoFixMinor,
				TestCmd:      testCmd, InstallCmd: installCmd,
				CorePackages: cleanList(corePkgs), Exclude: cleanList(exclude), Tech: cleanList(tech),
			}
			added, err := projectRepo(deps).Add(ctx, p)
			if err != nil {
				// The audit log keeps the English reason; the user reads it in their language.
				result := "denied"
				reason, msg := addDenialMessage(i18n.EN, path, name, err), addDenialMessage(deps.Lang, path, name, err)
				if !isValidationErr(err) {
					result = "error"
					reason, msg = i18n.T(i18n.EN, "cli.project.add.save_failed", err), deps.T("cli.project.add.save_failed", err)
				}
				ev := map[string]any{"path": path, "reason": reason}
				if class != "" {
					ev["classification"] = class
				}
				if cmd.Flags().Changed("fix-level") {
					ev["fix_level"] = fixLevel
				}
				if _, aerr := deps.Audit.Record(ctx, audit.Event{
					Actor: "cli", Action: "project.add", Target: name, Result: result, Evidence: ev,
				}); aerr != nil {
					return deps.Wrapf("cli.common.audit_also", aerr, msg)
				}
				return errors.New(msg)
			}
			if _, err := deps.Audit.Record(ctx, audit.Event{
				Actor: "cli", Action: "project.add", Target: added.Name, Result: "ok",
				Evidence: map[string]any{
					"path": added.Path, "classification": string(added.Classification), "fix_level": added.FixLevel,
				},
			}); err != nil {
				return deps.Wrapf("cli.project.add.audit_failed", err, added.Name)
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
	f.IntVar(&serverFixLevel, "server-fix-level", 1, "how far Michel may go on the server steps of a fix, 0 to 3")
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
				dataDir, _ := cmd.Flags().GetString("data-dir")
				if err := fix.RemoveProjectFiles(dataDir, p.ID); err != nil {
					fmt.Fprintln(deps.Stderr, deps.T("cli.project.remove.fix_files_failed", p.Name, err))
				}
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

// isValidationErr reports whether err is a refusal of the input, as opposed to
// a storage or system failure.
func isValidationErr(err error) bool {
	for _, s := range []error{project.ErrNotADirectory, project.ErrDuplicateName, project.ErrEmptyName,
		project.ErrInvalidFixLevel, project.ErrInvalidClassification, project.ErrInvalidSourceType,
		project.ErrInvalidRiskOverride, project.ErrInvalidExclude, project.ErrInvalidTech} {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
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

func newProjectSetCmd(deps *Deps) *cobra.Command {
	var corePkgs, risk, exclude, tech []string
	var class, testCmd, installCmd string
	var fixLevel, serverFixLevel int
	var autoFixMinor bool
	c := &cobra.Command{
		Use:   "set <name>",
		Short: "Change the settings of a registered project",
		Long: "Set changes only the settings you pass. --core-package replaces the whole list of core packages " +
			"(repeat it for several; pass --core-package '' to clear). --exclude replaces the list of folder names skipped by scans and " +
			"analyses the same way (--exclude '' clears it), and --tech the list of technologies the project runs on (--tech '' clears it). --risk key=value replaces one risk-score value " +
			"for this project (see docs/remediation-risk.md); other keys keep their previous override.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, name := cmd.Context(), args[0]
			// fail records the refusal with its English reason and returns it
			// in the user's language.
			fail := func(result, key string, ev map[string]any, vals ...any) error {
				ev["reason"] = i18n.T(i18n.EN, key, vals...)
				msg := deps.T(key, vals...)
				if _, aerr := deps.Audit.Record(ctx, audit.Event{
					Actor: "cli", Action: "project.set", Target: name, Result: result, Evidence: ev,
				}); aerr != nil {
					return deps.Wrapf("cli.common.audit_also", aerr, msg)
				}
				return errors.New(msg)
			}
			fl := cmd.Flags()
			var fields []string
			for _, f := range []string{"core-package", "exclude", "tech", "risk", "fix-level", "server-fix-level", "auto-fix-minor", "classification", "test-cmd", "install-cmd"} {
				if fl.Changed(f) {
					fields = append(fields, f)
				}
			}
			ev := map[string]any{"fields": fields}
			if len(fields) == 0 {
				return fail("denied", "cli.project.set.nothing", ev)
			}
			repo := projectRepo(deps)
			p, err := repo.Get(ctx, name)
			if err != nil {
				if errors.Is(err, project.ErrNotFound) {
					return fail("not_found", "cli.project.set.not_found", ev, name)
				}
				return fail("error", "cli.project.set.failed", ev, name, err)
			}
			if fl.Changed("core-package") {
				p.CorePackages = cleanList(corePkgs)
			}
			if fl.Changed("exclude") {
				p.Exclude = cleanList(exclude)
				ev["exclude"] = p.Exclude
			}
			if fl.Changed("tech") {
				p.Tech = cleanList(tech)
				ev["tech"] = p.Tech
			}
			for _, kv := range risk {
				k, v, ok := strings.Cut(kv, "=")
				n, convErr := strconv.Atoi(strings.TrimSpace(v))
				if !ok || convErr != nil {
					return fail("denied", "cli.project.set.bad_risk", ev, name, kv)
				}
				p.RiskOverrides[strings.TrimSpace(k)] = n
			}
			if fl.Changed("fix-level") {
				p.FixLevel = fixLevel
			}
			if fl.Changed("server-fix-level") {
				p.ServerFixLevel, ev["server_fix_level"] = serverFixLevel, serverFixLevel
			}
			if fl.Changed("auto-fix-minor") {
				p.AutoFixMinor, ev["auto_fix_minor"] = autoFixMinor, autoFixMinor
			}
			if fl.Changed("classification") {
				p.Classification = policy.Classification(class)
			}
			if fl.Changed("test-cmd") {
				p.TestCmd = testCmd
			}
			if fl.Changed("install-cmd") {
				p.InstallCmd = installCmd
			}
			if merged := deps.Policy.Risk.WithOverrides(p.RiskOverrides); policy.ValidateRisk(merged) != nil {
				return fail("denied", "cli.project.set.bad_thresholds", ev, name, merged.AutoFixBelow, merged.HandoffUpTo)
			}
			if err := repo.Update(ctx, p); err != nil {
				if isValidationErr(err) {
					return fail("denied", "cli.project.set.failed", ev, name, err)
				}
				return fail("error", "cli.project.set.save_failed", ev, name, err)
			}
			if _, err := deps.Audit.Record(ctx, audit.Event{
				Actor: "cli", Action: "project.set", Target: p.Name, Result: "ok", Evidence: ev,
			}); err != nil {
				return deps.Wrapf("cli.project.set.audit_failed", err, p.Name)
			}
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
	f.IntVar(&serverFixLevel, "server-fix-level", 1, "how far Michel may go on the server steps of a fix, 0 to 3")
	f.BoolVar(&autoFixMinor, "auto-fix-minor", false, "let Michel start fixes alone for minor and patch updates (needs fix level 2)")
	f.StringVar(&class, "classification", "", "data classification: public, internal, confidential, sensitive, health")
	f.StringVar(&testCmd, "test-cmd", "", "command that runs the project's tests")
	f.StringVar(&installCmd, "install-cmd", "", "command that installs the project's dependencies")
	return c
}
