package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"text/tabwriter"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/spf13/cobra"
)

func newProjectCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{Use: "project", Short: "Register the projects Michel watches"}
	c.AddCommand(newProjectAddCmd(deps), newProjectListCmd(deps), newProjectRemoveCmd(deps))
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
			"Choose another --name, or run 'michel project remove %s' first.", name, name)
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
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Forget a registered project (its folder is not touched)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, arg := cmd.Context(), args[0]
			repo := projectRepo(deps)
			p, err := repo.Get(ctx, arg)
			if err != nil {
				if !errors.Is(err, project.ErrNotFound) {
					return err
				}
				if _, aerr := deps.Audit.Record(ctx, audit.Event{
					Actor: "cli", Action: "project.remove", Target: arg, Result: "not_found",
				}); aerr != nil {
					return fmt.Errorf("cannot write the audit log: %w", aerr)
				}
				return fmt.Errorf("Cannot remove project %s: no project has this name. Run 'michel project list' to see the registered names.", arg)
			}
			if err := repo.Remove(ctx, p.ID); err != nil {
				return err
			}
			if _, err := deps.Audit.Record(ctx, audit.Event{
				Actor: "cli", Action: "project.remove", Target: p.Name, Result: "ok",
				Evidence: map[string]any{
					"path": p.Path, "classification": string(p.Classification), "fix_level": p.FixLevel,
				},
			}); err != nil {
				return fmt.Errorf("Project %s was removed but Michel could not write the audit log: %w", p.Name, err)
			}
			fmt.Fprintf(deps.Stdout, "Removed project %s.\n", p.Name)
			return nil
		},
	}
}

// isValidationErr reports whether err is a refusal of the input, as opposed to
// a storage or system failure.
func isValidationErr(err error) bool {
	for _, s := range []error{project.ErrNotADirectory, project.ErrDuplicateName, project.ErrEmptyName,
		project.ErrInvalidFixLevel, project.ErrInvalidClassification, project.ErrInvalidSourceType} {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}
