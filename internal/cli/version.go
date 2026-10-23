package cli

import (
	"fmt"

	"github.com/kvarot/michel/internal/buildinfo"
	"github.com/spf13/cobra"
)

func newVersionCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the michel version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintln(deps.Stdout, deps.T("cli.version.line", buildinfo.Version))
			return err
		},
	}
}
