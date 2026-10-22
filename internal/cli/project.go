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

// addDenialMessage turns a validation error into a plain-language message.
func addDenialMessage(path, name string, err error) string {
	switch {
	case errors.Is(err, project.ErrNotADirectory):
		return fmt.Sprintf("Cannot add project: %s is not a directory. Michel scans a project folder on this machine. "+
			"Give the folder that contains the code (for example the one with composer.lock or package-lock.json).", path)
	case errors.Is(err, project.ErrDuplicateName):
		return fmt.Sprintf("Cannot add project: a project named %q already exists. Names must be unique. "+
			"Choose another --name, or run 'michel project remove %s --purge' first (a removed project keeps its name until it is purged).", name, name)
	case errors.Is(err, project.ErrEmptyName):
		return "Cannot add project: the name is empty. Give it a short name with --name, for example --name my-shop."
	case errors.Is(err, project.ErrInvalidFixLevel):
		return "Cannot add project: the fix level must be 0, 1, 2 or 3. Pass --fix-level with one of these values (default 1)."
	case errors.Is(err, project.ErrInvalidClassification):
		return "Cannot add project: unknown classification. Use one of public, internal, confidential, sensitive, health."
	default:
		return fmt.Sprintf("Cannot add project: %v. Check the arguments and try again.", err)
	}
}

func newProjectAddCmd(deps *Deps) *cobra.Command {
	var name, class, testCmd, installCmd string
	var corePkgs []string
	var fixLevel int
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
				TestCmd: testCmd, InstallCmd: installCmd,
				CorePackages: cleanList(corePkgs),
			}
			added, err := projectRepo(deps).Add(ctx, p)
			if err != nil {
				msg, result := addDenialMessage(path, name, err), "denied"
				if !isValidationErr(err) {
					result, msg = "error", fmt.Sprintf("Cannot add project: %v. Michel could not save it; check that the data folder is writable and try again.", err)
				}
				ev := map[string]any{"path": path, "reason": msg}
				if class != "" {
					ev["classification"] = class
				}
				if cmd.Flags().Changed("fix-level") {
					ev["fix_level"] = fixLevel
				}
				if _, aerr := deps.Audit.Record(ctx, audit.Event{
					Actor: "cli", Action: "project.add", Target: name, Result: result, Evidence: ev,
				}); aerr != nil {
					return fmt.Errorf("%s Also, Michel could not write the audit log: %w", msg, aerr)
				}
				return errors.New(msg)
			}
			if _, err := deps.Audit.Record(ctx, audit.Event{
				Actor: "cli", Action: "project.add", Target: added.Name, Result: "ok",
				Evidence: map[string]any{
					"path": added.Path, "classification": string(added.Classification), "fix_level": added.FixLevel,
				},
			}); err != nil {
				return fmt.Errorf("Project %s was added but Michel could not write the audit log: %w. Check that the data folder is writable", added.Name, err)
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(added)
			}
			fmt.Fprintf(deps.Stdout, "Added project %s (%s), classification %s, fix level %d.\n",
				added.Name, added.Path, added.Classification, added.FixLevel)
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&name, "name", "", "unique name of the project (required)")
	f.StringVar(&class, "classification", "", "data classification: public, internal, confidential, sensitive, health (default: from the policy)")
	f.IntVar(&fixLevel, "fix-level", 1, "how far Michel may go to fix a finding, 0 to 3")
	f.StringVar(&testCmd, "test-cmd", "", "command that runs the project's tests")
	f.StringVar(&installCmd, "install-cmd", "", "command that installs the project's dependencies")
	f.StringArrayVar(&corePkgs, "core-package", nil, "package whose upgrade is riskier for this project (repeatable)")
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
				result, msg := "error", fmt.Sprintf("Cannot remove project %s: %v. Nothing was changed; check that the data folder is writable and try again.", arg, err)
				if errors.Is(err, project.ErrNotFound) {
					result, msg = "not_found", fmt.Sprintf("Cannot remove project %s: no project has this name. Run 'michel project list' to see the registered names.", arg)
				}
				if _, aerr := deps.Audit.Record(ctx, audit.Event{
					Actor: "cli", Action: "project.remove", Target: arg, Result: result,
					Evidence: map[string]any{"mode": mode, "reason": msg},
				}); aerr != nil {
					return fmt.Errorf("%s Also, Michel could not write the audit log: %w", msg, aerr)
				}
				return errors.New(msg)
			}
			if _, err := deps.Audit.Record(ctx, audit.Event{
				Actor: "cli", Action: "project.remove", Target: p.Name, Result: "ok",
				Evidence: map[string]any{
					"mode": mode, "path": p.Path, "classification": string(p.Classification), "fix_level": p.FixLevel,
				},
			}); err != nil {
				return fmt.Errorf("Project %s was removed (%s) but Michel could not write the audit log: %w. Check that the data folder is writable", p.Name, mode, err)
			}
			switch {
			case purge:
				fmt.Fprintf(deps.Stdout, "Purged project %s: its scans and findings were deleted and cannot be recovered. "+
					"The audit log keeps the record of what happened. The folder %s was not touched.\n", p.Name, p.Path)
			case !p.Active:
				fmt.Fprintf(deps.Stdout, "Project %s was already inactive; its history is kept. "+
					"Run 'michel project remove %s --purge' to delete it for good.\n", p.Name, p.Name)
			default:
				fmt.Fprintf(deps.Stdout, "Removed project %s: Michel no longer scans it, and its scans and findings are kept as history. "+
					"Run 'michel project remove %s --purge' to delete that history too.\n", p.Name, p.Name)
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
		project.ErrInvalidRiskOverride} {
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
	var corePkgs, risk []string
	var class, testCmd, installCmd string
	var fixLevel int
	c := &cobra.Command{
		Use:   "set <name>",
		Short: "Change the settings of a registered project",
		Long: "Set changes only the settings you pass. --core-package replaces the whole list of core packages " +
			"(repeat it for several; pass --core-package '' to clear). --risk key=value replaces one risk-score value " +
			"for this project (see docs/remediation-risk.md); other keys keep their previous override.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, name := cmd.Context(), args[0]
			fail := func(result, msg string, ev map[string]any) error {
				ev["reason"] = msg
				if _, aerr := deps.Audit.Record(ctx, audit.Event{
					Actor: "cli", Action: "project.set", Target: name, Result: result, Evidence: ev,
				}); aerr != nil {
					return fmt.Errorf("%s Also, Michel could not write the audit log: %w", msg, aerr)
				}
				return errors.New(msg)
			}
			fl := cmd.Flags()
			var fields []string
			for _, f := range []string{"core-package", "risk", "fix-level", "classification", "test-cmd", "install-cmd"} {
				if fl.Changed(f) {
					fields = append(fields, f)
				}
			}
			ev := map[string]any{"fields": fields}
			if len(fields) == 0 {
				return fail("denied", "Cannot update project: nothing to change. Pass at least one of --core-package, --risk, "+
					"--fix-level, --classification, --test-cmd, --install-cmd.", ev)
			}
			repo := projectRepo(deps)
			p, err := repo.Get(ctx, name)
			if err != nil {
				if errors.Is(err, project.ErrNotFound) {
					return fail("not_found", fmt.Sprintf("Cannot update project %s: no project has this name. "+
						"Run 'michel project list' to see the registered names.", name), ev)
				}
				return fail("error", fmt.Sprintf("Cannot update project %s: %v. Nothing was changed.", name, err), ev)
			}
			if fl.Changed("core-package") {
				p.CorePackages = cleanList(corePkgs)
			}
			for _, kv := range risk {
				k, v, ok := strings.Cut(kv, "=")
				n, convErr := strconv.Atoi(strings.TrimSpace(v))
				if !ok || convErr != nil {
					return fail("denied", fmt.Sprintf("Cannot update project %s: --risk %q must look like key=number, for example major_jump=10.", name, kv), ev)
				}
				p.RiskOverrides[strings.TrimSpace(k)] = n
			}
			if fl.Changed("fix-level") {
				p.FixLevel = fixLevel
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
				return fail("denied", fmt.Sprintf("Cannot update project %s: these overrides give auto_fix_below=%d and handoff_up_to=%d. "+
					"auto_fix_below must stay below handoff_up_to, which must be at most 100; terms must be 0 to 100. Nothing was changed.",
					name, merged.AutoFixBelow, merged.HandoffUpTo), ev)
			}
			if err := repo.Update(ctx, p); err != nil {
				if isValidationErr(err) {
					return fail("denied", fmt.Sprintf("Cannot update project %s: %v. Nothing was changed.", name, err), ev)
				}
				return fail("error", fmt.Sprintf("Cannot update project %s: %v. Nothing was changed; check that the data folder is writable and try again.", name, err), ev)
			}
			if _, err := deps.Audit.Record(ctx, audit.Event{
				Actor: "cli", Action: "project.set", Target: p.Name, Result: "ok", Evidence: ev,
			}); err != nil {
				return fmt.Errorf("Project %s was updated but Michel could not write the audit log: %w. Check that the data folder is writable", p.Name, err)
			}
			fmt.Fprintf(deps.Stdout, "Updated project %s: %s.\n", p.Name, strings.Join(fields, ", "))
			return nil
		},
	}
	f := c.Flags()
	f.StringArrayVar(&corePkgs, "core-package", nil, "package whose upgrade is riskier for this project (repeatable; replaces the list)")
	f.StringArrayVar(&risk, "risk", nil, "risk-score override key=value (repeatable), see docs/remediation-risk.md")
	f.IntVar(&fixLevel, "fix-level", 1, "how far Michel may go to fix a finding, 0 to 3")
	f.StringVar(&class, "classification", "", "data classification: public, internal, confidential, sensitive, health")
	f.StringVar(&testCmd, "test-cmd", "", "command that runs the project's tests")
	f.StringVar(&installCmd, "install-cmd", "", "command that installs the project's dependencies")
	return c
}
