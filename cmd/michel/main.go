// Command michel is a local-first vulnerability watch for Composer and npm projects.
package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/kvarot/michel/internal/cli"
)

func main() {
	deps := &cli.Deps{Stdout: os.Stdout, Stderr: os.Stderr, Now: time.Now}
	err := cli.NewRootCmd(deps).Execute()
	deps.Close() // PersistentPostRunE does not run when a command fails
	if err != nil {
		var ee *cli.ExitError
		if !(errors.As(err, &ee) && ee.Quiet) {
			fmt.Fprintln(os.Stderr, "michel:", err)
		}
		os.Exit(cli.ExitCode(err))
	}
}
