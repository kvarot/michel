package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/kvarot/michel/internal/buildinfo"
	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/mcp"
	"github.com/spf13/cobra"
)

func newMCPCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Serve Michel's read tools to Claude Code over stdio (MCP)",
		Long: "Mcp speaks the Model Context Protocol on stdin and stdout, for Claude Code. It never listens on the network. " +
			"Its tools read the findings, their brief, call sites and changelog; secrets are masked and paths are relative. " +
			"There is no tool to approve, apply or change a setting. propose_fix works only when Michel itself starts the " +
			"session for a fix attempt (" + fix.EnvAttempt + " and " + fix.EnvToken + "); otherwise the session is read-only.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			secrets, err := openSecrets(cmd, deps)
			if err != nil {
				return err
			}
			dataDir, _ := cmd.Flags().GetString("data-dir")
			attempt, token := os.Getenv(fix.EnvAttempt), os.Getenv(fix.EnvToken)
			if attempt != "" && token != "" && fix.CheckAttemptToken(secrets, attempt, token) {
				fmt.Fprintln(deps.Stderr, deps.T("cli.mcp.bound", attempt))
			} else {
				fmt.Fprintln(deps.Stderr, deps.T("cli.mcp.read_only"))
			}
			in := deps.Stdin
			if in == nil {
				in = os.Stdin
			}
			// The proposal is validated here, in this process, on the shared
			// store (controller ruling 2): the token check stays at the MCP
			// boundary, the attempt state check in fix.Propose.
			fd := fixDeps(cmd, deps, secrets, "mcp")
			return mcp.Serve(cmd.Context(), in, deps.Stdout, mcp.Deps{
				Store: deps.Store, DataDir: dataDir, Policy: deps.Policy, Lang: deps.Lang, Secrets: secrets,
				Attempt: attempt, Token: token, Version: buildinfo.Version, Log: deps.Stderr,
				Propose: func(ctx context.Context, attemptID string, in fix.ProposeInput) (fix.Proposal, error) {
					return fix.Propose(ctx, fd, attemptID, in)
				},
			})
		},
	}
}
