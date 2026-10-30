package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kvarot/michel/internal/brief"
	"github.com/kvarot/michel/internal/gitrepo"
	"github.com/kvarot/michel/internal/mask"
	"github.com/spf13/cobra"
)

func newBriefCmd(deps *Deps) *cobra.Command {
	var write, writeSkill, removeSkill bool
	c := &cobra.Command{
		Use:   "brief <id-or-prefix>",
		Short: "Print the fix brief of a finding (find, understand, fix), for you or for Claude Code",
		Long: "Brief gathers what Michel knows about one finding into a short Markdown file in three parts: where the " +
			"vulnerable package is used, what the flaw means, and how to fix it. Secrets are masked and paths are relative. " +
			"By default it only prints. --write also keeps the file in Michel's data folder; --write-skill writes a skill " +
			"for Claude Code in ~/.claude/skills (a folder Michel did not write is never touched); --remove-skill removes it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if writeSkill && removeSkill {
				return deps.Errorf("cli.brief.exclusive")
			}
			fi, p, err := resolveFinding(ctx, deps, args[0])
			if err != nil {
				return err
			}
			skills := func() (string, error) { return gitrepo.DefaultSkillsDir() }
			if removeSkill {
				dir, err := skills()
				if err != nil {
					return err
				}
				name, err := brief.SkillName(fi.ID)
				if err != nil {
					return err
				}
				_, before := os.Lstat(filepath.Join(dir, name))
				if err := brief.RemoveSkill(dir, fi.ID); err != nil {
					return err
				}
				if _, after := os.Lstat(filepath.Join(dir, name)); before == nil && after != nil {
					fmt.Fprintln(deps.Stdout, deps.T("cli.brief.skill_removed", filepath.Join(dir, name)))
				} else {
					fmt.Fprintln(deps.Stdout, deps.T("cli.brief.skill_absent", dir))
				}
				return nil
			}
			dataDir, _ := cmd.Flags().GetString("data-dir")
			b, err := brief.Build(ctx, brief.Deps{Store: deps.Store, DataDir: dataDir, Policy: deps.Policy, Lang: deps.Lang}, fi.ID, mask.New())
			if err != nil {
				return err
			}
			if write {
				path := brief.Path(dataDir, p.ID, fi.ID)
				if err := writeFileAtomic(path, brief.Markdown(b, deps.Lang)); err != nil {
					return err
				}
				fmt.Fprintln(deps.Stdout, deps.T("cli.brief.written", path))
			}
			if writeSkill {
				dir, err := skills()
				if err != nil {
					return err
				}
				out, err := brief.WriteSkill(dir, b, deps.Lang)
				if err != nil {
					return err
				}
				fmt.Fprintln(deps.Stdout, deps.T("cli.brief.skill_written", out, filepath.Base(out)))
			}
			if write || writeSkill {
				return nil
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(b)
			}
			_, err = deps.Stdout.Write(brief.Markdown(b, deps.Lang))
			return err
		},
	}
	f := c.Flags()
	f.BoolVar(&write, "write", false, "also write the brief in Michel's data folder")
	f.BoolVar(&writeSkill, "write-skill", false, "write the Claude Code skill of this finding in the skills folder")
	f.BoolVar(&removeSkill, "remove-skill", false, "remove the skill of this finding (only when Michel wrote it)")
	return c
}

// writeFileAtomic writes data to path (folders 0700, file 0600) through a
// temporary file renamed into place.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".brief-")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}
