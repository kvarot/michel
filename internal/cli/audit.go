package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/kvarot/michel/internal/audit"
	"github.com/spf13/cobra"
)

func newAuditCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{Use: "audit", Short: "Inspect the tamper-evident audit log"}
	c.AddCommand(newAuditVerifyCmd(deps), newAuditListCmd(deps))
	return c
}

func newAuditVerifyCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Check that no audit event was changed or removed",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := audit.Verify(cmd.Context(), deps.Store)
			if err != nil {
				return err
			}
			asJSON, _ := cmd.Flags().GetBool("json")
			if asJSON {
				out := map[string]any{"checked": res.Checked, "broken": nil, "reason": res.Reason}
				if res.Broken != nil {
					out["broken"] = res.Broken
				}
				if err := json.NewEncoder(deps.Stdout).Encode(out); err != nil {
					return err
				}
			}
			if res.Broken != nil {
				msg := fmt.Sprintf("audit: BROKEN at event %s: %s", res.Broken.ID, res.Reason)
				if !asJSON {
					fmt.Fprintln(deps.Stdout, msg)
				}
				return &ExitError{Code: ExitCodeAuditBroken, Err: fmt.Errorf("%s", msg), Quiet: true}
			}
			if !asJSON {
				fmt.Fprintf(deps.Stdout, "audit: %d events verified\n", res.Checked)
			}
			return nil
		},
	}
}

func newAuditListCmd(deps *Deps) *cobra.Command {
	var last int
	c := &cobra.Command{
		Use:   "list",
		Short: "List the most recent audit events",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if last < 1 {
				return fmt.Errorf("--last must be at least 1. Pass a positive number of events to show")
			}
			rows, err := deps.Store.DB().QueryContext(cmd.Context(), `SELECT id, ts, actor, action, target, result
				FROM (SELECT rowid AS rid, * FROM audit_event ORDER BY rowid DESC LIMIT ?) ORDER BY rid`, last)
			if err != nil {
				return fmt.Errorf("cannot read the audit log: %w", err)
			}
			defer rows.Close()
			events := []audit.Event{}
			for rows.Next() {
				var e audit.Event
				if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.Target, &e.Result); err != nil {
					return err
				}
				events = append(events, e)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(events)
			}
			tw := tabwriter.NewWriter(deps.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ts\taction\ttarget\tresult")
			for _, e := range events {
				ts := e.TS
				if i := strings.IndexByte(ts, '.'); i >= 0 {
					ts = ts[:i] + "Z"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", ts, e.Action, e.Target, e.Result)
			}
			return tw.Flush()
		},
	}
	c.Flags().IntVar(&last, "last", 20, "number of most recent events to show")
	return c
}
