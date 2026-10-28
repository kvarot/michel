package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/kvarot/michel/internal/gitrepo"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/source"
	"github.com/spf13/cobra"
)

func newSourceDiscoverCmd(deps *Deps) *cobra.Command {
	var add, ignore, kind, pin, path, name string
	c := &cobra.Command{
		Use:   "discover [--add owner/name --kind skill|mcp --pin <sha> | --ignore owner/name]",
		Short: "List the repositories found by topic, to add or to ignore",
		Long: "Discover lists the repositories that michel source update found on GitHub by topic (source discover.github, off " +
			"by default) and that are not sources yet. --add makes one a source of yours (skill or MCP server, pinned to the " +
			"commit you give, off until you enable it), --ignore hides it from the list. Michel reads nothing here: the list " +
			"comes from the last update.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			dr := gitrepo.NewDiscoveryRepo(deps.Store)
			switch {
			case add != "" && ignore != "":
				return deps.Errorf("cli.source.discover.usage")
			case ignore != "":
				if err := dr.SetState(ctx, ignore, gitrepo.StateIgnored); err != nil {
					return discoverErr(deps, ignore, err)
				}
				if err := recordSource(cmd, deps, "source.discover", ignore, "ok", map[string]any{"repo": ignore, "state": gitrepo.StateIgnored}); err != nil {
					return err
				}
				fmt.Fprintln(deps.Stdout, deps.T("cli.source.discover.ignored", ignore))
				return nil
			case add != "":
				return discoverAdd(cmd, deps, dr, add, kind, pin, path, name)
			}
			list, err := dr.List(ctx, gitrepo.StateNew)
			if err != nil {
				return err
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(list)
			}
			if len(list) == 0 {
				fmt.Fprintln(deps.Stdout, deps.T("cli.source.discover.empty"))
				return nil
			}
			tw := tabwriter.NewWriter(deps.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, deps.T("cli.source.discover.header"))
			for _, d := range list {
				fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", safe(d.Repo), d.Stars, safe(d.Topic), safe(d.Description))
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.source.discover.hint"))
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&add, "add", "", "make this repository (owner/name) a source of yours")
	f.StringVar(&ignore, "ignore", "", "hide this repository (owner/name) from the list")
	f.StringVar(&kind, "kind", "", "with --add: skill or mcp")
	f.StringVar(&pin, "pin", "", "with --add: full 40-character commit to install")
	f.StringVar(&path, "path", "", "with --add: folder of the skill or server inside the repository")
	f.StringVar(&name, "name", "", "with --add: name shown in the lists; the key is made from it")
	return c
}

func discoverErr(deps *Deps, repo string, err error) error {
	if errors.Is(err, gitrepo.ErrUnknownDiscovery) {
		return deps.Errorf("cli.source.discover.unknown", repo)
	}
	return err
}

// discoverAdd creates a user skill or mcp entry from a discovery, like
// michel source add, and marks the discovery added.
func discoverAdd(cmd *cobra.Command, deps *Deps, dr *gitrepo.DiscoveryRepo, repo, kind, pin, path, name string) error {
	ctx := cmd.Context()
	k := source.Kind(kind)
	if k != source.KindSkill && k != source.KindMCP {
		return deps.Errorf("cli.source.discover.add_kind")
	}
	found, err := dr.List(ctx, "")
	if err != nil {
		return err
	}
	known := false
	for _, d := range found {
		if strings.EqualFold(d.Repo, repo) {
			known, repo = true, d.Repo
		}
	}
	if !known {
		return deps.Errorf("cli.source.discover.unknown", repo)
	}
	if !repoName.MatchString(repo) {
		return deps.Errorf("cli.source.add.bad_repo", repo)
	}
	if !commitSHA.MatchString(pin) {
		return deps.Errorf("cli.source.add.bad_pin", pin)
	}
	user := map[string]any{"repo": repo, "pinned": pin}
	if path != "" {
		clean, ok := cleanRepoPath(path)
		if !ok {
			return deps.Errorf("cli.source.add.bad_path", path)
		}
		user["path"] = clean
	}
	if name = strings.TrimSpace(name); name == "" {
		name = repo[strings.Index(repo, "/")+1:]
	}
	e := source.Entry{Kind: k, Origin: source.OriginUser, Name: name, URL: "https://github.com/" + repo, Hosts: repoHosts,
		Purpose: policy.PurposeRepo, Config: source.Config{Catalog: map[string]any{}, User: user}}
	e.Key = source.KeyFor(k, name)
	if !source.ValidKey(e.Key) {
		return deps.Errorf("cli.source.add.no_name")
	}
	r := source.NewRepo(deps.Store)
	if _, err := r.Get(ctx, e.Key); err == nil {
		return deps.Errorf("cli.source.add.exists", e.Key)
	} else if !errors.Is(err, source.ErrNotFound) {
		return sourceErr(deps, e.Key, err)
	}
	added, err := r.Upsert(ctx, e)
	if err != nil {
		return deps.Wrapf("cli.source.add.invalid", err)
	}
	if err := dr.SetState(ctx, repo, gitrepo.StateAdded); err != nil {
		return discoverErr(deps, repo, err)
	}
	if err := recordSource(cmd, deps, "source.add", added.Key, "ok", map[string]any{"key": added.Key, "kind": string(added.Kind), "from": "discover"}); err != nil {
		return err
	}
	fmt.Fprintln(deps.Stdout, deps.T("cli.source.add.done", added.Key, added.Key))
	return nil
}
