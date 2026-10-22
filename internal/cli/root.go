// Package cli wires the michel command line.
package cli

import (
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

// Deps holds the dependencies shared by all commands.
type Deps struct {
	Stdout io.Writer
	Stderr io.Writer
	Now    func() time.Time
}

// defaultDataDir returns the per-user michel directory. If the user
// configuration directory is unknown, it falls back to a relative "michel".
func defaultDataDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = ""
	}
	return filepath.Join(base, "michel")
}

// NewRootCmd builds the root command and registers its subcommands.
func NewRootCmd(deps *Deps) *cobra.Command {
	dataDir := defaultDataDir()
	root := &cobra.Command{
		Use:           "michel",
		Short:         "Local-first vulnerability watch for Composer and npm projects",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(deps.Stdout)
	root.SetErr(deps.Stderr)

	flags := root.PersistentFlags()
	flags.String("config", filepath.Join(dataDir, "config.yaml"), "path to the configuration file")
	flags.String("data-dir", dataDir, "directory where michel stores its data")
	flags.Bool("json", false, "print results as JSON")

	root.AddCommand(newVersionCmd(deps))
	return root
}
