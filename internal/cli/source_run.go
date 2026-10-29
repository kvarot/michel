package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/kvarot/michel/internal/plugin"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/source"
	"github.com/spf13/cobra"
)

func newSourceRunCmd(deps *Deps) *cobra.Command {
	var name, input string
	c := &cobra.Command{
		Use:   "run <key> --project <name> [--input <report>]",
		Short: "Run a plugin (Trivy, Semgrep) on a project, or read a report it produced",
		Long: "Run starts the plugin's tool on the project folder, offline: its network goes to a proxy of Michel's that refuses " +
			"everything and records each attempt in the audit log, and it only gets the few environment variables a program needs " +
			"to start, never a secret. Trivy checks the configuration files (misconfigurations only); Semgrep runs the rules found " +
			"in the plugins/semgrep/rules folder of Michel's data folder. The tool writes in Michel's data folder, never in the " +
			"project. --input reads a report instead (SARIF, or Trivy JSON), for any plugin: that is the only way for CodeQL, " +
			"ZAP and the generic SARIF plugin, which Michel never runs. The findings join the others (michel findings, " +
			"michel decide). The plugin must be enabled first (michel source enable).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, key := cmd.Context(), args[0]
			e, err := source.NewRepo(deps.Store).Get(ctx, key)
			if err != nil {
				return sourceErr(deps, key, err)
			}
			if e.Kind != source.KindPlugin {
				return deps.Errorf("cli.source.run.not_plugin", key)
			}
			if name == "" {
				return deps.Errorf("cli.source.run.need_project", key)
			}
			if e.State(deps.allowed) != source.StateOn {
				return deps.Errorf("cli.source.run.off", key, key)
			}
			p, err := projectRepo(deps).Get(ctx, name)
			if err != nil {
				if errors.Is(err, project.ErrNotFound) {
					return deps.Errorf("cli.scan.not_found", name)
				}
				return err
			}
			if !p.Active {
				return deps.Errorf("cli.scan.removed", p.Name, p.Name)
			}
			res, err := plugin.RunPlugin(ctx, pluginDeps(cmd, deps), e, p, input)
			if err != nil {
				return pluginErr(deps, e, p.Name, err)
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(pluginRunView{Project: p.Name, Key: key, RunResult: res})
			}
			fmt.Fprintln(deps.Stdout, pluginSummary(deps, e, p.Name, res))
			return nil
		},
	}
	c.Flags().StringVar(&name, "project", "", "name of the project to check")
	c.Flags().StringVar(&input, "input", "", "read this report (SARIF or Trivy JSON) instead of running the tool")
	return c
}

// pluginRunView is one plugin run for --json; the report path is left out.
type pluginRunView struct {
	Project string `json:"project"`
	Key     string `json:"key"`
	plugin.RunResult
}

func pluginDeps(cmd *cobra.Command, deps *Deps) plugin.RunDeps {
	dir, _ := cmd.Flags().GetString("data-dir")
	return plugin.RunDeps{Store: deps.Store, Audit: deps.Audit, Repo: source.NewRepo(deps.Store), DataDir: dir, Now: deps.Now}
}

// pluginTool is the name of the plugin's tool, as the messages show it.
func pluginTool(e source.Entry) string {
	if t := e.Config.Str("tool"); t != "" {
		return t
	}
	return strings.TrimPrefix(e.Key, "plugin.")
}

// pluginErr explains why a plugin run failed, without any path.
func pluginErr(deps *Deps, e source.Entry, projectName string, err error) error {
	tool := pluginTool(e)
	switch {
	case errors.Is(err, plugin.ErrNotRunnable):
		return deps.Errorf("cli.source.run.not_runnable", tool, e.Key, projectName)
	case errors.Is(err, plugin.ErrNotInstalled):
		return deps.Errorf("cli.source.run.not_installed", tool, tool, e.Key, projectName)
	case errors.Is(err, plugin.ErrNoRules):
		return deps.Errorf("cli.source.run.no_rules")
	case errors.Is(err, plugin.ErrDisabled):
		return deps.Errorf("cli.source.run.off", e.Key, e.Key)
	}
	return deps.Wrapf("cli.source.run.failed", err, tool, projectName)
}

// pluginSummary is the plain-language end of a plugin run.
func pluginSummary(deps *Deps, e source.Entry, projectName string, r plugin.RunResult) string {
	tool := pluginTool(e)
	var s strings.Builder
	if r.New == 0 {
		s.WriteString(deps.T("cli.source.run.no_new", tool, projectName))
	} else {
		s.WriteString(deps.N("cli.source.run.new", r.New, tool, projectName))
	}
	if r.Gone > 0 {
		s.WriteString(deps.N("cli.scan.summary.gone", r.Gone))
	}
	if r.SkippedKnown > 0 {
		s.WriteString(deps.N("cli.source.run.skipped_known", r.SkippedKnown))
	}
	s.WriteString(deps.T("cli.common.next_findings", projectName))
	return s.String()
}

// scanPlugins are the plugins 'michel scan' runs: on, with run set, and
// meant for every project or listed for this one.
func scanPlugins(entries []source.Entry, allowed func(host, purpose string) bool, projectName string) []source.Entry {
	var out []source.Entry
	for _, e := range entries {
		if e.State(allowed) != source.StateOn || !e.Config.Bool("run") {
			continue
		}
		if only := e.Config.List("projects"); len(only) > 0 && !slices.Contains(only, projectName) {
			continue
		}
		out = append(out, e)
	}
	return out
}
