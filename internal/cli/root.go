// Package cli wires the michel command line.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/kvarot/michel/internal/policy"
	"github.com/spf13/cobra"
)

// ExitCodePolicy is the exit code used when the policy cannot be used.
const ExitCodePolicy = 3

// ExitError is an error that carries the process exit code.
type ExitError struct {
	Code int
	Err  error
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
}

// userConfigDir is replaced in tests.
var userConfigDir = os.UserConfigDir

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
			flags := cmd.Flags()
			if baseErr != nil && !(flags.Changed("config") && flags.Changed("data-dir")) {
				return fmt.Errorf("Michel cannot find your user configuration folder (%v). "+
					"Pass --config and --data-dir to say where to read and store its files", baseErr)
			}
			cfgPath, _ := flags.GetString("config")
			dir, _ := flags.GetString("data-dir")
			p, src, err := policy.Load(cfgPath, dir)
			if err == nil {
				err = policy.Validate(p)
			}
			if err != nil {
				return &ExitError{Code: ExitCodePolicy, Err: fmt.Errorf(
					"Policy file %s is invalid: %v. Michel refuses to start with an inconsistent policy. "+
						"Fix the file or delete it to use the built-in strict_local defaults.", cfgPath, err)}
			}
			deps.Policy, deps.PolicySource = p, src
			if src == policy.SourceFile {
				fmt.Fprintf(deps.Stderr, "policy: file %s\n", cfgPath)
			} else {
				fmt.Fprintf(deps.Stderr, "policy: defaults (no file at %s)\n", cfgPath)
			}
			return nil
		},
	}
	root.SetOut(deps.Stdout)
	root.SetErr(deps.Stderr)

	flags := root.PersistentFlags()
	flags.String("config", filepath.Join(dataDir, "config.yaml"), "path to the policy file")
	flags.String("data-dir", dataDir, "directory where michel stores its data")
	flags.Bool("json", false, "print results as JSON")

	root.AddCommand(newVersionCmd(deps))
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
