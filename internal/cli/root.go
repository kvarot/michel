// Package cli wires the michel command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/buildinfo"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/source"
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
	// Stdin feeds commands that read a value (michel secret set). Nil means
	// os.Stdin; a reader that is not an *os.File is never a terminal.
	Stdin io.Reader
	// TypedLine replaces the terminal in tests of the answers Michel takes only
	// from a person: what was typed, and whether a terminal is there. Nil reads
	// the line from Stdin when it is a terminal.
	TypedLine func() (string, bool)
	Stdout    io.Writer
	Stderr    io.Writer
	Now       func() time.Time

	// policy holds the policy in force and its source, set by the root
	// command before any subcommand runs and swapped whole by a reload: read
	// it with Policy and PolicySource, from any goroutine.
	policy atomic.Pointer[loadedPolicy]
	// Lang is the resolved language of generated text: the --lang flag,
	// else the policy's assistant.lang ("auto" defers), else the system's
	// language, else English.
	Lang i18n.Lang

	// Store, Audit and Gateway are set by the root command for every command
	// except help, completion and version.
	Store   *store.Store
	Audit   *audit.Logger
	Gateway *egress.Gateway

	// LogsReady, when set by michel serve, is closed when the first round of the
	// log scheduler is over; the digest loop waits for it (see digestLogWait).
	LogsReady <-chan struct{}
}

// loadedPolicy is a policy with where it was read from.
type loadedPolicy struct {
	p   policy.Policy
	src policy.Source
}

// Policy returns the policy in force. A reload replaces it whole: a reader
// never sees half of the old one and half of the new.
func (d *Deps) Policy() policy.Policy {
	if lp := d.policy.Load(); lp != nil {
		return lp.p
	}
	return policy.Policy{}
}

// PolicySource returns where the policy in force comes from.
func (d *Deps) PolicySource() policy.Source {
	if lp := d.policy.Load(); lp != nil {
		return lp.src
	}
	return ""
}

// SetPolicy puts p in force.
func (d *Deps) SetPolicy(p policy.Policy, src policy.Source) {
	d.policy.Store(&loadedPolicy{p: p, src: src})
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
			// Until the policy is read, messages follow the --lang flag when
			// it is valid, else the system language.
			flag, _ := flags.GetString("lang")
			deps.Lang = i18n.Resolve(flag, "", i18n.SystemLocale())
			if baseErr != nil && !(flags.Changed("config") && flags.Changed("data-dir")) {
				return deps.Errorf("cli.root.no_config_dir", baseErr)
			}
			cfgPath, _ := flags.GetString("config")
			dir, _ := flags.GetString("data-dir")
			p, src, err := policy.Load(cfgPath, dir)
			if err != nil {
				// Load's error already names the file.
				return &ExitError{Code: ExitCodePolicy, Err: deps.Wrapf("cli.root.policy_unreadable", err)}
			}
			if err := policy.Validate(p); err != nil {
				return &ExitError{Code: ExitCodePolicy, Err: deps.Wrapf("cli.root.policy_invalid", err, cfgPath)}
			}
			deps.SetPolicy(p, src)
			if f := strings.ToLower(strings.TrimSpace(flag)); f != "" && !i18n.Lang(f).Valid() {
				return &ExitError{Code: ExitCodePolicy, Err: deps.Errorf("cli.root.unknown_lang", f)}
			}
			deps.Lang = i18n.Resolve(flag, p.Assistant.Lang, i18n.SystemLocale())
			if src == policy.SourceFile {
				fmt.Fprintln(deps.Stderr, deps.T("cli.root.policy_file", cfgPath))
			} else {
				fmt.Fprintln(deps.Stderr, deps.T("cli.root.policy_defaults", cfgPath))
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
			// The registry follows the embedded catalog: new entries appear,
			// the user's choices stay.
			if _, _, err := source.Sync(cmd.Context(), source.NewRepo(st)); err != nil {
				deps.Close()
				return deps.Wrapf("cli.root.sources_sync", err)
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
				return deps.Wrapf("cli.root.audit_write", err, dir)
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
	flags.String("lang", "", "language of the explanations: en or fr (default: assistant.lang of the policy, else the system language)")

	root.AddCommand(newVersionCmd(deps))
	root.AddCommand(newAuditCmd(deps))
	root.AddCommand(newProjectCmd(deps))
	root.AddCommand(newDBCmd(deps))
	root.AddCommand(newScanCmd(deps))
	root.AddCommand(newAnalyzeCmd(deps))
	root.AddCommand(newFindingsCmd(deps))
	root.AddCommand(newFindingCmd(deps))
	root.AddCommand(newDecideCmd(deps))
	root.AddCommand(newDecisionsCmd(deps))
	root.AddCommand(newDigestCmd(deps))
	root.AddCommand(newSecretCmd(deps))
	root.AddCommand(newNotifyCmd(deps))
	root.AddCommand(newServeCmd(deps))
	root.AddCommand(newSourceCmd(deps))
	root.AddCommand(newTechCmd(deps))
	root.AddCommand(newBriefCmd(deps))
	root.AddCommand(newMCPCmd(deps))
	root.AddCommand(newFixCmd(deps))
	root.AddCommand(newTargetCmd(deps))
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
