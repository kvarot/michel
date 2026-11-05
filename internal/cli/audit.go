package cli

import (
	"encoding/json"
	"errors"
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
			required := sealRequired(deps.Policy())
			var opt audit.VerifyOptions
			if required {
				dir, _ := cmd.Flags().GetString("data-dir")
				key, err := loadSealKey(dir, false)
				if err != nil {
					// Read-only: a key that cannot be read leaves the seals unchecked,
					// which the walk reports at the first sealed event.
					key = nil
				}
				opt = audit.VerifyOptions{Key: key, Required: true}
			}
			res, err := audit.VerifyWith(cmd.Context(), deps.Store, opt)
			if err != nil {
				return err
			}
			asJSON, _ := cmd.Flags().GetBool("json")
			if asJSON {
				out := map[string]any{"checked": res.Checked, "broken": nil, "reason": res.Reason, "expected": res.Expected,
					"sealed": res.Sealed, "unsealed": res.Unsealed, "failed": res.Failed(required)}
				if res.Broken != nil {
					out["broken"] = res.Broken
				}
				if err := json.NewEncoder(deps.Stdout).Encode(out); err != nil {
					return err
				}
			}
			tail := res.Reason == audit.ReasonTailTruncated
			if tail {
				msg := deps.T("cli.audit.verify.broken_tail", res.Expected, res.Checked)
				if !asJSON {
					fmt.Fprintln(deps.Stdout, msg)
				}
				return &ExitError{Code: ExitCodeAuditBroken, Err: errors.New(msg), Quiet: true}
			}
			if res.Broken != nil && res.Reason == audit.ReasonSealKeyMissing {
				msg := deps.T("cli.audit.verify.key_missing")
				if !asJSON {
					fmt.Fprintln(deps.Stdout, msg)
				}
				return &ExitError{Code: ExitCodeAuditBroken, Err: errors.New(msg), Quiet: true}
			}
			if res.Broken != nil {
				msg := deps.T("cli.audit.verify.broken_event", res.Broken.ID, res.Reason)
				if !asJSON {
					fmt.Fprintln(deps.Stdout, msg)
				}
				return &ExitError{Code: ExitCodeAuditBroken, Err: errors.New(msg), Quiet: true}
			}
			if res.Failed(required) {
				// The protection is required and the anchor is gone: the newest
				// events may have been removed.
				msg := deps.T("cli.audit.verify.broken_head", audit.HeadFile(deps.Store.Path()), res.Checked)
				if !asJSON {
					fmt.Fprintln(deps.Stdout, msg)
				}
				return &ExitError{Code: ExitCodeAuditBroken, Err: errors.New(msg), Quiet: true}
			}
			if !asJSON {
				if res.Head != "" {
					fmt.Fprintln(deps.Stdout, deps.N("cli.audit.verify.ok_head", res.Checked, res.Head))
				} else {
					fmt.Fprintln(deps.Stdout, deps.N("cli.audit.verify.ok", res.Checked))
				}
				if required {
					fmt.Fprintln(deps.Stdout, deps.N("cli.audit.verify.sealed", res.Sealed))
					if res.Unsealed > 0 {
						fmt.Fprintln(deps.Stdout, deps.N("cli.audit.verify.unsealed", res.Unsealed))
					}
				}
				if res.Reason == audit.ReasonHeadAbsent {
					fmt.Fprintln(deps.Stdout, deps.T("cli.audit.verify.head_absent", audit.HeadFile(deps.Store.Path())))
				}
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
				return deps.Errorf("cli.audit.list.bad_last")
			}
			rows, err := deps.Store.DB().QueryContext(cmd.Context(), `SELECT id, ts, actor, action, target, result
				FROM (SELECT * FROM audit_event ORDER BY seq DESC LIMIT ?) AS last ORDER BY seq`, last)
			if err != nil {
				return deps.Wrapf("cli.audit.list.read_failed", err)
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
