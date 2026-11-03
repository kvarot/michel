package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/digest"
	"github.com/spf13/cobra"
)

func newDigestCmd(deps *Deps) *cobra.Command {
	var since string
	var asHTML, send bool
	c := &cobra.Command{
		Use:   "digest",
		Short: "Show what changed since the last digest",
		Long: "Digest lists, for every active project, the new findings, the findings gone at the last scan, the decisions " +
			"to review and the deferrals coming due, since the last digest sent (24 hours the first time). It only reads " +
			"the data folder. With --send, Michel first takes the deferrals whose date is reached out of force, sends " +
			"the digest on every enabled channel of the policy's notify section (see 'michel notify list'), then " +
			"records it so the next one starts where this one ends. A channel that fails does not stop the others; " +
			"the command then exits with code 1.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			asJSON, _ := cmd.Flags().GetBool("json")
			if asJSON && asHTML {
				return deps.Errorf("cli.digest.json_and_html")
			}
			opt, err := digestOptions(cmd, deps, since)
			if err != nil {
				return err
			}
			if !send {
				d, err := digest.Compute(cmd.Context(), deps.Store, deps.Now(), deps.Lang, opt)
				if err != nil {
					return err
				}
				return printDigest(deps, d, asJSON, asHTML)
			}
			res, err := sendDigest(cmd.Context(), cmd, deps, opt, false)
			if err != nil {
				return err
			}
			if err := printDigest(deps, res.Digest, asJSON, asHTML); err != nil {
				return err
			}
			if failed := reportChannels(deps, res.Deliveries); failed > 0 {
				return &ExitError{Code: 1, Quiet: true, Err: errors.New(deps.N("cli.digest.channels_failed", failed))}
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&since, "since", "", "start of the window, as YYYY-MM-DD (default: the end of the last digest sent, else 24 hours ago)")
	f.BoolVar(&asHTML, "html", false, "print the digest as an HTML page")
	f.BoolVar(&send, "send", false, "take due deferrals out of force, send the digest on the notify channels, then record it")
	f.String("osv-db", "", "directory of the offline databases (default: from the policy)")
	return c
}

// digestOptions reads the digest settings from the flags and the policy.
func digestOptions(cmd *cobra.Command, deps *Deps, since string) (digest.Options, error) {
	opt := digest.Options{Assistant: deps.Policy.Assistant.Name, OSVRoot: dbRoot(cmd, deps), PageURL: deps.Policy.Notify.PageURL,
		Allowed: deps.allowed}
	if s := strings.TrimSpace(since); s != "" {
		t, err := time.Parse("2006-01-02", s)
		if err != nil {
			return digest.Options{}, deps.Errorf("cli.digest.bad_since", s)
		}
		opt.Since = t.UTC()
	}
	return opt, nil
}

// printDigest prints d as text, JSON or HTML.
func printDigest(deps *Deps, d digest.Digest, asJSON, asHTML bool) error {
	switch {
	case asJSON:
		b, err := digest.RenderJSON(d)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(deps.Stdout, string(b))
		return err
	case asHTML:
		s, err := digest.RenderHTML(d)
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(deps.Stdout, s)
		return err
	}
	s, err := digest.RenderText(d)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(deps.Stdout, s)
	return err
}
