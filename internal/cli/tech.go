package cli

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/source"
	"github.com/spf13/cobra"
)

func newTechCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{
		Use:   "tech",
		Short: "Declare the technologies you run outside your projects (nginx, postgresql...)",
		Long: "The technologies declared here, with those of each project (michel project set --tech) and those " +
			"Michel detects in the manifests, choose which feed items are worth reading.",
	}
	c.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List the technologies declared outside your projects",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			tags, err := source.ListTech(cmd.Context(), deps.Store)
			if err != nil {
				return deps.Wrapf("cli.tech.failed", err)
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(tags)
			}
			if len(tags) == 0 {
				fmt.Fprintln(deps.Stdout, deps.T("cli.tech.none"))
			}
			for _, t := range tags {
				fmt.Fprintln(deps.Stdout, t)
			}
			return nil
		},
	}, newTechChangeCmd(deps, "add"), newTechChangeCmd(deps, "remove"))
	return c
}

// newTechChangeCmd builds "tech add" and "tech remove".
func newTechChangeCmd(deps *Deps, action string) *cobra.Command {
	short := "Declare a technology, for example nginx"
	if action == "remove" {
		short = "Stop declaring a technology"
	}
	return &cobra.Command{
		Use:   action + " <tag>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tag := args[0]
			var err error
			if action == "add" {
				err = source.AddTech(cmd.Context(), deps.Store, tag)
			} else {
				err = source.RemoveTech(cmd.Context(), deps.Store, tag)
			}
			if errors.Is(err, project.ErrInvalidTech) {
				return deps.Errorf("cli.tech.bad_tag", tag)
			}
			if err != nil {
				return deps.Wrapf("cli.tech.failed", err)
			}
			if err := recordSource(cmd, deps, "tech.set", tag, "ok", map[string]any{"tag": tag, "action": action}); err != nil {
				return err
			}
			if action == "add" {
				fmt.Fprintln(deps.Stdout, deps.T("cli.tech.added", tag))
			} else {
				fmt.Fprintln(deps.Stdout, deps.T("cli.tech.removed", tag))
			}
			return nil
		},
	}
}
