// Package cli wires the michel command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/buildinfo"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/store"
	"github.com/spf13/cobra"
)

// ExitCodePolicy is the exit code used when the policy cannot be used.
const ExitCodePolicy = 3

// ExitCodeAuditBroken is the exit code used when the audit chain is broken.
const ExitCodeAuditBroken = 2

// ExitError is an error that carries the process exit code.
type ExitError struct {
	Code int
	Err  error
	// Quiet means the command already printed its message; main must not repeat it.
	Quiet bool
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

// Deps holds the dependencies shared by all commands.
type Deps struct {
	Stdout io.Writer
	Stderr io.Writer
	Now    func() time.Time

	// Policy and PolicySource are set by the root command before any
	// subcommand runs.
	Policy       policy.Policy
	PolicySource policy.Source

	// Store, Audit and Gateway are set by the root command for every command
	// except help, completion and version.
	Store   *store.Store
	Audit   *audit.Logger
	Gateway *egress.Gateway
}

// Close releases the store. It is safe to call more than once.
func (d *Deps) Close() error {
	if d.Store == nil {
		return nil
	}
	err := d.Store.Close()
	d.Store = nil
	return err
}

// userConfigDir is replaced in tests.
var userConfigDir = os.UserConfigDir

// hasAncestor reports whether cmd or one of its parents is named one of names.
func hasAncestor(cmd *cobra.Command, names ...string) bool {
	for c := cmd; c != nil; c = c.Parent() {
		for _, n := range names {
			if c.Name() == n {
				return true
			}
		}
	}
	return false
}

// NewRootCmd builds the root command and registers its subcommands.
func NewRootCmd(deps *Deps) *cobra.Command {
	var dataDir string
	base, baseErr := userConfigDir()
	if baseErr == nil {
		dataDir = filepath.Join(base, "michel")
	}
	root := &cobra.Command{
		Use:           "michel",
		Short:         "Local-first vulnerability watch for Composer and npm projects",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if hasAncestor(cmd, "help", "completion", cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd) {
				return nil
			}
			flags := cmd.Flags()
			if baseErr != nil && !(flags.Changed("config") && flags.Changed("data-dir")) {
				return fmt.Errorf("Michel cannot find your user configuration folder (%v). "+
					"Pass --config and --data-dir to say where to read and store its files", baseErr)
			}
			cfgPath, _ := flags.GetString("config")
			dir, _ := flags.GetString("data-dir")
			p, src, err := policy.Load(cfgPath, dir)
			if err != nil {
				// Load's error already names the file.
				return &ExitError{Code: ExitCodePolicy, Err: fmt.Errorf(
					"%w. Michel refuses to start without a readable policy. "+
						"Fix the file or delete it to use the built-in strict_local defaults.", err)}
			}
			if err := policy.Validate(p); err != nil {
				return &ExitError{Code: ExitCodePolicy, Err: fmt.Errorf(
					"Policy file %s is invalid: %w. Michel refuses to start with an inconsistent policy. "+
						"Fix the file or delete it to use the built-in strict_local defaults.", cfgPath, err)}
			}
			deps.Policy, deps.PolicySource = p, src
			if src == policy.SourceFile {
				fmt.Fprintf(deps.Stderr, "policy: file %s\n", cfgPath)
			} else {
				fmt.Fprintf(deps.Stderr, "policy: defaults (no file at %s)\n", cfgPath)
			}
			if cmd.Name() == "version" {
				return nil // must work on an absent or read-only data folder
			}

			st, err := store.Open(filepath.Join(dir, "michel.db"))
			if err != nil {
				return err
			}
			deps.Store = st
			deps.Audit = audit.NewLogger(st, deps.Now)
			if hasAncestor(cmd, "audit") {
				// Inspection commands must work on a locked or read-only copy,
				// so they write nothing, not even app.start.
				return nil
			}
			if _, err := deps.Audit.Record(context.Background(), audit.Event{
				Actor: "cli", Action: "app.start", Target: buildinfo.Version, Result: "ok",
				Evidence: map[string]any{
					"version":       buildinfo.Version,
					"policy_source": string(src),
					"mode":          string(p.Sovereignty.Mode),
				},
			}); err != nil {
				deps.Close()
				return fmt.Errorf("Michel cannot write its audit log: %w. Check that %s is writable", err, dir)
			}
			deps.Gateway = egress.New(p, deps.Audit.EgressSink())
			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			return deps.Close()
		},
	}
	root.SetOut(deps.Stdout)
	root.SetErr(deps.Stderr)

	flags := root.PersistentFlags()
	flags.String("config", filepath.Join(dataDir, "config.yaml"), "path to the policy file")
	flags.String("data-dir", dataDir, "directory where michel stores its data")
	flags.Bool("json", false, "print results as JSON")

	root.AddCommand(newVersionCmd(deps))
	root.AddCommand(newAuditCmd(deps))
	return root
}

// ExitCode returns the process exit code for an error returned by Execute.
func ExitCode(err error) int {
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return 1
}
