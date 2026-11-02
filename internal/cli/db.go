package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/source"
	"github.com/spf13/cobra"
)

// osvPurpose is the egress purpose of the offline database download.
const osvPurpose = "osv.db"

// staleAfter is the age after which a database is reported as STALE.
const staleAfter = 7 * 24 * time.Hour

func newDBCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{Use: "db", Short: "Manage the offline vulnerability databases"}
	c.AddCommand(newDBUpdateCmd(deps), newDBStatusCmd(deps))
	return c
}

func dbRoot(cmd *cobra.Command, deps *Deps) string {
	if v, _ := cmd.Flags().GetString("osv-db"); v != "" {
		return v
	}
	return deps.Policy.DB.OSVPath
}

func newDBUpdateCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{
		Use:   "update",
		Short: "Download the offline OSV databases of the enabled ecosystems",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, root := cmd.Context(), dbRoot(cmd, deps)
			ecos, err := osvdb.Enabled(ctx, source.NewRepo(deps.Store), deps.allowed)
			if err != nil {
				return err
			}
			record := func(result string, ev map[string]any) error {
				_, err := deps.Audit.Record(ctx, audit.Event{
					Actor: "cli", Action: "osv.db.update", Target: root, Result: result, Evidence: ev,
				})
				return err
			}
			if ok, _ := deps.Gateway.Allowed(osvdb.Host, osvPurpose); !ok {
				if err := record("denied", map[string]any{"ecosystems": ecos, "reason": "no network.allow entry for " + osvdb.Host}); err != nil {
					return deps.Wrapf("cli.common.audit_also", err, deps.T("cli.db.rule_missing", osvdb.Host, osvPurpose))
				}
				return &ExitError{Code: ExitCodePolicy, Err: deps.Errorf("cli.db.rule_missing", osvdb.Host, osvPurpose)}
			}
			st, err := osvdb.Update(ctx, root, deps.Gateway.Client(osvPurpose), ecos, deps.Now)
			sizes := map[string]int64{}
			done := []string{}
			fetched := ""
			for _, s := range st {
				sizes[s.Ecosystem] = s.SizeBytes
				done = append(done, s.Ecosystem)
				fetched = s.FetchedAt.UTC().Format(time.RFC3339)
			}
			ev := map[string]any{"ecosystems": done, "sizes": sizes, "fetched_at": fetched}
			if err != nil {
				result := "error"
				denied := errors.Is(err, egress.ErrEgressDenied)
				if denied {
					result = "denied"
				}
				failed := ecos[len(st)]
				ev["attempted"] = ecos
				ev["completed"] = done
				ev["failed"] = failed
				ev["reason"] = err.Error()
				msg := deps.T("cli.db.update.failed", failed, err)
				if len(done) > 0 {
					msg = deps.T("cli.db.update.failed_kept", failed, err, strings.Join(done, ", "))
				}
				if aerr := record(result, ev); aerr != nil {
					return deps.Wrapf("cli.common.audit_also", aerr, msg)
				}
				if denied {
					return &ExitError{Code: ExitCodePolicy, Err: errors.New(msg)}
				}
				return errors.New(msg)
			}
			if err := record("ok", ev); err != nil {
				return deps.Wrapf("cli.db.update.audit_failed", err)
			}
			// The stored server inventories are judged again against the new
			// databases, offline; a failure there does not undo the update.
			rematched, rerr := serverRematch(cmd, deps)(ctx)
			if rerr != nil {
				fmt.Fprintln(deps.Stderr, deps.T("cli.db.update.rematch_failed", rerr))
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(st)
			}
			for _, s := range st {
				fmt.Fprintln(deps.Stdout, deps.T("cli.db.update.done", s.Ecosystem, s.SizeBytes))
			}
			if rematched > 0 {
				fmt.Fprintln(deps.Stdout, deps.N("cli.db.update.rematched", rematched))
			}
			return nil
		},
	}
	c.Flags().String("osv-db", "", "directory of the offline databases (default: from the policy)")
	return c
}

func newDBStatusCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{
		Use:   "status",
		Short: "Show which offline databases are present and how old they are",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ecos, err := osvdb.Enabled(cmd.Context(), source.NewRepo(deps.Store), deps.allowed)
			if err != nil {
				return err
			}
			st, err := osvdb.Statuses(dbRoot(cmd, deps), ecos)
			if err != nil {
				return err
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(st)
			}
			now := deps.Now()
			tw := tabwriter.NewWriter(deps.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ecosystem\tpresent\tfetched_at\tsize\tstate")
			for _, s := range st {
				state, at := "OK", "-"
				if !s.FetchedAt.IsZero() {
					at = s.FetchedAt.UTC().Format(time.RFC3339)
				}
				switch {
				case !s.Present:
					state = "MISSING"
				case s.FetchedAt.IsZero() || now.Sub(s.FetchedAt) > staleAfter:
					state = "STALE"
				}
				fmt.Fprintf(tw, "%s\t%t\t%s\t%d\t%s\n", s.Ecosystem, s.Present, at, s.SizeBytes, state)
			}
			return tw.Flush()
		},
	}
	c.Flags().String("osv-db", "", "directory of the offline databases (default: from the policy)")
	return c
}
