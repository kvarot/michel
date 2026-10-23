package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/scan"
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
			"the data folder. With --send, Michel first takes the deferrals whose date is reached out of force, then " +
			"records the digest so the next one starts where this one ends.",
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
			var d digest.Digest
			if send {
				d, err = sendDigest(cmd.Context(), deps, opt)
			} else {
				d, err = digest.Compute(cmd.Context(), deps.Store, deps.Now(), deps.Lang, opt)
			}
			if err != nil {
				return err
			}
			return printDigest(deps, d, asJSON, asHTML)
		},
	}
	f := c.Flags()
	f.StringVar(&since, "since", "", "start of the window, as YYYY-MM-DD (default: the end of the last digest sent, else 24 hours ago)")
	f.BoolVar(&asHTML, "html", false, "print the digest as an HTML page")
	f.BoolVar(&send, "send", false, "take due deferrals out of force, then record the digest as sent")
	f.String("osv-db", "", "directory of the offline databases (default: from the policy)")
	return c
}

// digestOptions reads the digest settings from the flags and the policy.
func digestOptions(cmd *cobra.Command, deps *Deps, since string) (digest.Options, error) {
	opt := digest.Options{Assistant: deps.Policy.Assistant.Name, OSVRoot: dbRoot(cmd, deps)}
	// TODO(task 7): PageURL comes from the policy's notify.page_url.
	if s := strings.TrimSpace(since); s != "" {
		t, err := time.Parse("2006-01-02", s)
		if err != nil {
			return digest.Options{}, deps.Errorf("cli.digest.bad_since", s)
		}
		opt.Since = t.UTC()
	}
	return opt, nil
}

// sendDigest marks stale scans as interrupted, takes the due deferrals out of
// force, computes the digest and records it as a run (audit digest.run).
// Channels are not wired yet: the run has none.
func sendDigest(ctx context.Context, deps *Deps, opt digest.Options) (digest.Digest, error) {
	now := deps.Now().UTC()
	swept, err := scan.SweepStale(ctx, deps.Store.DB(), now, scan.StaleScanAfter)
	if err != nil {
		return digest.Digest{}, err
	}
	if swept > 0 {
		if _, err := deps.Audit.Record(ctx, audit.Event{Actor: "digest", Action: "scan.sweep", Target: "digest", Result: "ok",
			Evidence: map[string]any{"swept": swept, "max_age": scan.StaleScanAfter.String()}}); err != nil {
			return digest.Digest{}, err
		}
	}
	if _, err := decide.NewRepo(deps.Store).ExpireDue(ctx, now, deps.Audit); err != nil {
		return digest.Digest{}, err
	}
	d, err := digest.Compute(ctx, deps.Store, now, deps.Lang, opt)
	if err != nil {
		return digest.Digest{}, err
	}
	run := digest.RunOf(d, now)
	if err := digest.NewRepo(deps.Store).Save(ctx, run); err != nil {
		return digest.Digest{}, err
	}
	if _, err := deps.Audit.Record(ctx, audit.Event{Actor: "digest", Action: "digest.run", Target: run.ID, Result: "ok",
		Evidence: map[string]any{
			"run_id": run.ID, "since": run.Since.UTC().Format(time.RFC3339), "until": run.Until.UTC().Format(time.RFC3339),
			"projects": len(d.Projects), "new_total": d.NewTotal, "attention_total": d.AttentionTotal, "channels": run.Channels,
		}}); err != nil {
		return digest.Digest{}, err
	}
	return d, nil
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
