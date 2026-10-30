package cli

import (
	"context"
	"os"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/notify"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/workcopy"
	"github.com/spf13/cobra"
)

// fixDeps wires the fix service: the store, the audit log, the secret
// store, the gateway, the policy file of --config (the consent writes its
// rules there and a reload hands them to the gateway), the data folder,
// and michel mcp as the agent's only MCP server (this executable with the
// same --data-dir and --config). Proposals waiting for the user are
// announced on the policy's channels.
func fixDeps(cmd *cobra.Command, deps *Deps, secrets secret.Store, actor string) fix.Deps {
	cfg, _ := cmd.Flags().GetString("config")
	dataDir, _ := cmd.Flags().GetString("data-dir")
	exe, err := os.Executable()
	if err != nil {
		exe = "michel"
	}
	mcp := []string{exe, "mcp", "--data-dir", dataDir, "--config", cfg}
	if lang, _ := cmd.Flags().GetString("lang"); lang != "" {
		mcp = append(mcp, "--lang", lang)
	}
	d := fix.Deps{
		Store: deps.Store, Audit: deps.Audit, Secrets: secrets, Gateway: deps.Gateway,
		Policy: deps.Policy, PolicyPath: cfg,
		Reload: func() (policy.Policy, error) {
			p, src, err := policy.Load(cfg, dataDir)
			if err == nil {
				err = policy.Validate(p)
			}
			if err == nil {
				deps.Policy, deps.PolicySource = p, src
			}
			return p, err
		},
		DataDir: dataDir, OSVRoot: dbRoot(cmd, deps), Lang: deps.Lang,
		MCPCommand: mcp, Work: workcopy.Deps{DataDir: dataDir},
		Now: deps.Now, Actor: actor,
	}
	d.Notify = func(ctx context.Context, waiting int) {
		nd, err := notifyDeps(cmd, deps, false)
		if err != nil {
			return
		}
		nd.Secrets = secrets
		ns, err := notify.Build(deps.Policy.Notify, nd)
		if err != nil {
			return
		}
		notify.SendFixWaiting(ctx, ns, waiting, deps.Policy.Notify.PageURL)
	}
	return d
}
