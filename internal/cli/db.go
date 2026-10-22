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

const dbRuleMissing = "db update requires network.allow entry {host: " + osvdb.Host + ", purpose: " + osvPurpose + "}. " +
	"Michel never downloads anything that is not listed in your policy. " +
	"Add this entry under sovereignty.network.allow in config.yaml, then run 'michel db update' again."

func newDBUpdateCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{
		Use:   "update",
		Short: "Download the offline OSV databases (Packagist and npm)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, root := cmd.Context(), dbRoot(cmd, deps)
			ecos := osvdb.Ecosystems
			record := func(result string, ev map[string]any) error {
				_, err := deps.Audit.Record(ctx, audit.Event{
					Actor: "cli", Action: "osv.db.update", Target: root, Result: result, Evidence: ev,
				})
				return err
			}
			if ok, _ := deps.Gateway.Allowed(osvdb.Host, osvPurpose); !ok {
				if err := record("denied", map[string]any{"ecosystems": ecos, "reason": "no network.allow entry for " + osvdb.Host}); err != nil {
					return fmt.Errorf("%s Also, Michel could not write the audit log: %w", dbRuleMissing, err)
				}
				return &ExitError{Code: ExitCodePolicy, Err: errors.New(dbRuleMissing)}
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
				msg := fmt.Sprintf("Database update failed for %s: %v. ", failed, err)
				if len(done) > 0 {
					msg += fmt.Sprintf("Already installed and kept: %s. ", strings.Join(done, ", "))
				}
				msg += "The previous database for the failed ecosystem, if any, was kept. " +
					"Check your network and the policy, then run 'michel db update' again."
				if aerr := record(result, ev); aerr != nil {
					return fmt.Errorf("%s Also, Michel could not write the audit log: %w", msg, aerr)
				}
				if denied {
					return &ExitError{Code: ExitCodePolicy, Err: errors.New(msg)}
				}
				return errors.New(msg)
			}
			if err := record("ok", ev); err != nil {
				return fmt.Errorf("The databases were updated but Michel could not write the audit log: %w. Check that the data folder is writable", err)
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(st)
			}
			for _, s := range st {
				fmt.Fprintf(deps.Stdout, "Updated %s: %d bytes\n", s.Ecosystem, s.SizeBytes)
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
			st, err := osvdb.Statuses(dbRoot(cmd, deps))
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
