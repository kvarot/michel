// Command michel is a local-first vulnerability watch for Composer and npm projects.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/kvarot/michel/internal/cli"
)

func main() {
	deps := &cli.Deps{Stdout: os.Stdout, Stderr: os.Stderr, Now: time.Now}
	if err := cli.NewRootCmd(deps).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "michel:", err)
		os.Exit(1)
	}
}
