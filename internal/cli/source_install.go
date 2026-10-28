package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/gitrepo"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/source"
	"github.com/spf13/cobra"
)

// previewFiles is how many files the preview lists by name.
const previewFiles = 30

// repoDeps wires the installation of skills and MCP servers: the archive
// client (purpose source.repo), the data folder, the skills folder
// (~/.claude/skills, or MICHEL_SKILLS_DIR for the tests) and the folders of
// the scanned projects, where Michel never writes.
func repoDeps(cmd *cobra.Command, deps *Deps) (gitrepo.Deps, error) {
	dir, _ := cmd.Flags().GetString("data-dir")
	skills, err := gitrepo.DefaultSkillsDir()
	if err != nil {
		return gitrepo.Deps{}, deps.Wrapf("cli.source.install.no_skills_dir", err)
	}
	projects, err := project.NewRepo(deps.Store).List(cmd.Context())
	if err != nil {
		return gitrepo.Deps{}, err
	}
	var forbidden []string
	for _, p := range projects {
		if p.Path != "" {
			forbidden = append(forbidden, p.Path)
		}
	}
	return gitrepo.Deps{Repo: source.NewRepo(deps.Store), Audit: deps.Audit, Client: deps.Gateway.Client(policy.PurposeRepo),
		DataDir: dir, SkillsDir: skills, Forbidden: forbidden, Now: deps.Now, Actor: "cli"}, nil
}

// repoEntry reads key and checks it is a skill or an MCP server whose hosts
// are allowed.
func repoEntry(cmd *cobra.Command, deps *Deps, key string) (source.Entry, error) {
	e, err := source.NewRepo(deps.Store).Get(cmd.Context(), key)
	if err != nil {
		return source.Entry{}, sourceErr(deps, key, err)
	}
	if e.Kind != source.KindSkill && e.Kind != source.KindMCP {
		return source.Entry{}, deps.Errorf("cli.source.install.wrong_kind", key)
	}
	if e.State(deps.allowed) != source.StateOn {
		return source.Entry{}, deps.Errorf("cli.source.install.not_enabled", key, key)
	}
	return e, nil
}

// installErr turns an installation error into a message in the user's
// language.
func installErr(deps *Deps, key string, err error) error {
	switch {
	case errors.Is(err, gitrepo.ErrForeignDir):
		return deps.Errorf("cli.source.install.foreign", key)
	case errors.Is(err, gitrepo.ErrInsideProject):
		return deps.Errorf("cli.source.install.inside_project")
	case errors.Is(err, gitrepo.ErrBadName):
		return deps.Wrapf("cli.source.install.bad_name", err, key)
	}
	return deps.Wrapf("cli.source.install.failed", err, key)
}

// oldFolderKept prints the warning of a moved skill whose previous folder
// stayed (the new installation is done) and returns the other errors.
func oldFolderKept(deps *Deps, err error) error {
	if !errors.Is(err, gitrepo.ErrOldFolderKept) {
		return err
	}
	fmt.Fprintln(deps.Stderr, deps.T("cli.source.install.old_folder_kept", err))
	return nil
}

// humanSize writes a byte count for people.
func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// printPreview prints what an installation brings and does, on stderr
// (the text to read before answering).
func printPreview(deps *Deps, p gitrepo.Preview, kind source.Kind) {
	out := deps.Stderr
	fmt.Fprintln(out, deps.T("cli.source.install.preview_title", p.Key, safe(p.Repo), p.SHA))
	var total int64
	for _, f := range p.Files {
		total += f.Size
	}
	fmt.Fprintln(out, deps.N("cli.source.install.files", len(p.Files), humanSize(total)))
	for i, f := range p.Files {
		if i == previewFiles {
			fmt.Fprintln(out, deps.N("cli.source.install.more_files", len(p.Files)-previewFiles))
			break
		}
		fmt.Fprintln(out, deps.T("cli.source.install.file", safe(f.Path), humanSize(f.Size)))
	}
	switch {
	case p.License.SPDX == "unknown":
		fmt.Fprintln(out, deps.T("cli.source.install.license_unknown"))
	default:
		fmt.Fprintln(out, deps.T("cli.source.install.license", p.License.SPDX, safe(p.License.File)))
		if p.Declared != "" && p.Declared != "unknown" && p.Declared != p.License.SPDX {
			fmt.Fprintln(out, deps.T("cli.source.install.license_differs", p.License.SPDX, p.Declared))
		}
	}
	printTrust(deps, p.Trust)
	if len(p.Head) > 0 {
		fmt.Fprintln(out, deps.T("cli.source.install.head_title"))
		for _, l := range p.Head {
			fmt.Fprintln(out, "  | "+l)
		}
	}
	fmt.Fprintln(out, deps.T("cli.source.install.never_run"))
	if kind == source.KindSkill {
		fmt.Fprintln(out, deps.T("cli.source.install.will_write", p.WillWrite))
		return
	}
	fmt.Fprintln(out, deps.T("cli.source.install.mcp_nothing"))
	if p.Launch == "" {
		fmt.Fprintln(out, deps.T("cli.source.install.mcp_no_launch"))
		return
	}
	fmt.Fprintln(out, deps.T("cli.source.install.mcp_launch", p.Launch))
	if p.Downloads {
		fmt.Fprintln(out, deps.T("cli.source.install.mcp_downloads"))
	}
}

// printTrust prints the trust note of a repository.
func printTrust(deps *Deps, t gitrepo.Trust) {
	out := deps.Stderr
	if t.InCatalog {
		fmt.Fprintln(out, deps.T("source.trust.in_catalog"))
	} else {
		fmt.Fprintln(out, deps.T("source.trust.user"))
	}
	if t.Archived == "" {
		fmt.Fprintln(out, deps.T("source.trust.unchecked"))
		return
	}
	fmt.Fprintln(out, deps.T("source.trust.stars", t.Stars, shortDate(t.PushedAt)))
	if t.Archived == "yes" {
		fmt.Fprintln(out, deps.T("source.trust.archived"))
	}
}

// shortDate is the day of an RFC 3339 time, as given when it is not one.
func shortDate(s string) string {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Local().Format(time.DateOnly)
	}
	return safe(s)
}

// askConsent asks y/N on a terminal after the text printed by the caller.
// Without a terminal it refuses with exit code 3 and needsYes; a "no" is
// refused with refused. Both refusals are audited under action.
func askConsent(cmd *cobra.Command, deps *Deps, action, key string, needsYes, refused error) error {
	in, tty := stdinTerminal(deps)
	if !tty {
		if err := recordSource(cmd, deps, action, key, "denied", map[string]any{"key": key, "reason": "consent needed, no terminal and no --yes"}); err != nil {
			return err
		}
		return &ExitError{Code: ExitCodePolicy, Err: needsYes}
	}
	fmt.Fprint(deps.Stderr, deps.T("cli.source.enable.prompt"))
	answer, rerr := in.ReadString('\n')
	if rerr != nil && answer == "" {
		return deps.Wrapf("cli.source.enable.read_failed", rerr)
	}
	if !yes(answer) {
		if err := recordSource(cmd, deps, action, key, "denied", map[string]any{"key": key, "reason": "consent refused"}); err != nil {
			return err
		}
		return &ExitError{Code: ExitCodePolicy, Err: refused}
	}
	return nil
}

func newSourceInstallCmd(deps *Deps) *cobra.Command {
	var assumeYes bool
	c := &cobra.Command{
		Use:   "install <key>",
		Short: "Install a skill or pin an MCP server, after a preview and your consent",
		Long: "Install downloads the pinned commit of the repository into Michel's data folder, then shows its files, licence, " +
			"the start of its instructions, what is known of the repository and what the installation will write, and asks y/N. " +
			"A skill is copied to ~/.claude/skills/<name>/ with a marker file; a folder of that name that Michel did not install " +
			"is never touched. An MCP server is only kept for reading: Michel prints the claude mcp add line for you to run and " +
			"writes nothing in the Claude Code settings. Michel never runs anything from the repository. --yes gives the consent " +
			"without asking, for scripts. The source must be enabled first (michel source enable).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, key := cmd.Context(), args[0]
			e, err := repoEntry(cmd, deps, key)
			if err != nil {
				return err
			}
			sha := e.Config.Str("pinned")
			if !gitrepo.ValidSHA(sha) {
				return deps.Errorf("cli.source.install.no_pin", key)
			}
			gd, err := repoDeps(cmd, deps)
			if err != nil {
				return err
			}
			p, err := gitrepo.PreviewInstall(ctx, gd, e, sha)
			if err != nil {
				return installErr(deps, key, err)
			}
			printPreview(deps, p, e.Kind)
			if !assumeYes {
				if err := askConsent(cmd, deps, "source.install", key, deps.Errorf("cli.source.install.needs_yes", key, key), deps.Errorf("cli.source.install.refused", key)); err != nil {
					return err
				}
			}
			// The sha installed is the one shown.
			to, err := gitrepo.Install(ctx, gd, e, p.SHA)
			if err = oldFolderKept(deps, err); err != nil {
				return installErr(deps, key, err)
			}
			if e.Kind == source.KindSkill {
				fmt.Fprintln(deps.Stdout, deps.T("cli.source.install.done_skill", key, to))
			} else {
				fmt.Fprintln(deps.Stdout, deps.T("cli.source.install.done_mcp", key, p.SHA))
				if p.Launch != "" {
					fmt.Fprintln(deps.Stdout, "  "+p.Launch)
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&assumeYes, "yes", false, "give the consent without asking (for scripts)")
	return c
}

func newSourceUpgradeCmd(deps *Deps) *cobra.Command {
	var assumeYes bool
	c := &cobra.Command{
		Use:   "upgrade <key>",
		Short: "Move an installed skill or MCP server to the new version found by the daily update",
		Long: "Upgrade downloads the version that michel source update found on the repository's default branch, shows the files " +
			"added, changed and removed and the changed lines of SKILL.md, asks y/N, then installs it and pins it. Michel never " +
			"upgrades on its own. --yes gives the consent without asking, for scripts.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, key := cmd.Context(), args[0]
			e, err := repoEntry(cmd, deps, key)
			if err != nil {
				return err
			}
			if e.Config.Str("installed_sha") == "" {
				return deps.Errorf("cli.source.upgrade.not_installed", key, key)
			}
			_, to, ok := e.NewVersion()
			if !ok || !gitrepo.ValidSHA(to) || to == e.Config.Str("installed_sha") {
				return deps.Errorf("cli.source.upgrade.nothing", key)
			}
			gd, err := repoDeps(cmd, deps)
			if err != nil {
				return err
			}
			diff, err := gitrepo.Upgrade(ctx, gd, e, to)
			if err != nil {
				return installErr(deps, key, err)
			}
			out := deps.Stderr
			fmt.Fprintln(out, deps.T("cli.source.upgrade.title", key, diff.From, diff.To))
			if diff.NewDir != "" && diff.OldDir != diff.NewDir {
				fmt.Fprintln(out, deps.T("cli.source.upgrade.folder_changes", diff.OldDir, diff.NewDir))
			}
			list := func(files []string) string {
				names := make([]string, 0, len(files))
				for _, f := range files {
					names = append(names, safe(f))
				}
				sort.Strings(names)
				return strings.Join(names, ", ")
			}
			if len(diff.Added) > 0 {
				fmt.Fprintln(out, deps.N("cli.source.upgrade.added", len(diff.Added), list(diff.Added)))
			}
			if len(diff.Changed) > 0 {
				fmt.Fprintln(out, deps.N("cli.source.upgrade.changed", len(diff.Changed), list(diff.Changed)))
			}
			if len(diff.Removed) > 0 {
				fmt.Fprintln(out, deps.N("cli.source.upgrade.removed", len(diff.Removed), list(diff.Removed)))
			}
			if diff.SkillMDDiff != "" {
				fmt.Fprintln(out, deps.T("cli.source.upgrade.skill_md"))
				fmt.Fprint(out, diff.SkillMDDiff)
			}
			if len(diff.Added)+len(diff.Changed)+len(diff.Removed) == 0 {
				fmt.Fprintln(out, deps.T("cli.source.upgrade.same_files"))
			}
			fmt.Fprintln(out, deps.T("cli.source.install.never_run"))
			if !assumeYes {
				if err := askConsent(cmd, deps, "source.install", key, deps.Errorf("cli.source.upgrade.needs_yes", key, key), deps.Errorf("cli.source.install.refused", key)); err != nil {
					return err
				}
			}
			dir, err := gitrepo.Install(ctx, gd, e, diff.To)
			if err = oldFolderKept(deps, err); err != nil {
				return installErr(deps, key, err)
			}
			if err := gd.Repo.SetStatus(ctx, key, dropNewVersion(e.Status)); err != nil {
				return sourceErr(deps, key, err)
			}
			if e.Kind == source.KindSkill {
				fmt.Fprintln(deps.Stdout, deps.T("cli.source.upgrade.done_skill", key, diff.To, dir))
			} else {
				fmt.Fprintln(deps.Stdout, deps.T("cli.source.upgrade.done_mcp", key, diff.To))
			}
			return nil
		},
	}
	c.Flags().BoolVar(&assumeYes, "yes", false, "give the consent without asking (for scripts)")
	return c
}

// dropNewVersion is the status without its new version mark, once the new
// version is installed.
func dropNewVersion(st map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range st {
		if k != "new_version" {
			out[k] = v
		}
	}
	out["new_version_available"] = false
	return out
}

// uninstallSkill removes what an installation wrote, after y/N (or --yes).
func uninstallSkill(cmd *cobra.Command, deps *Deps, e source.Entry, assumeYes bool) error {
	gd, err := repoDeps(cmd, deps)
	if err != nil {
		return err
	}
	if dir := e.Config.Str("install_dir"); dir != "" {
		fmt.Fprintln(deps.Stderr, deps.T("cli.source.remove.will_uninstall", e.Key, dir))
	} else {
		fmt.Fprintln(deps.Stderr, deps.T("cli.source.remove.will_unpin", e.Key))
	}
	if !assumeYes {
		if err := askConsent(cmd, deps, "source.remove", e.Key, deps.Errorf("cli.source.remove.needs_yes", e.Key, e.Key), deps.Errorf("cli.source.remove.refused", e.Key)); err != nil {
			return err
		}
	}
	if err := gitrepo.Uninstall(cmd.Context(), gd, e); err != nil {
		if errors.Is(err, gitrepo.ErrForeignDir) {
			return deps.Errorf("cli.source.remove.foreign", e.Key)
		}
		return sourceErr(deps, e.Key, err)
	}
	fmt.Fprintln(deps.Stdout, deps.T("cli.source.remove.uninstalled", e.Key))
	return nil
}

// printRepoStatus prints the last GitHub status of a skill, MCP server or
// plugin.
func printRepoStatus(deps *Deps, e source.Entry) {
	out := deps.Stdout
	checked, _ := e.Status["checked_at"].(string)
	if _, ok := e.Status["head_sha"]; !ok || checked == "" {
		if e.Config.Str("repo") != "" {
			fmt.Fprintln(out, deps.T("cli.source.show.status_none"))
		}
		return
	}
	stars := 0
	if v, ok := e.Status["stars"].(float64); ok {
		stars = int(v)
	}
	pushed, _ := e.Status["pushed_at"].(string)
	head, _ := e.Status["head_sha"].(string)
	fmt.Fprintln(out, deps.T("cli.source.show.status", shortDate(checked), stars, shortDate(pushed), safe(head)))
	if rel, _ := e.Status["latest_release"].(string); rel != "" {
		fmt.Fprintln(out, deps.T("cli.source.show.status_release", safe(rel)))
	}
	if a, _ := e.Status["archived"].(bool); a {
		fmt.Fprintln(out, deps.T("source.trust.archived"))
	}
	if from, to, ok := e.NewVersion(); ok {
		fmt.Fprintln(out, deps.T("cli.source.show.status_new_version", safe(to), safe(from), e.Key))
	}
}
