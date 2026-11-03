package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/kvarot/michel/internal/api"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/servererr"
	"github.com/kvarot/michel/internal/serverlog"
)

// logReadBound bounds one read started by hand.
const logReadBound = 15 * time.Minute

func newTargetLogsCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{
		Use:   "logs",
		Short: "See the errors Michel reads in the logs of a server, or read them now",
		Long: "Michel reads the log files you declare on a server's page, over SSH, with a filter that sends back only the level, " +
			"the type and the place of each error: never a log line. michel serve does it at the interval of each server and " +
			"warns by itself; these commands show the result (list) or run one read now (read). Nothing is written on a server.",
	}
	c.AddCommand(newTargetLogsListCmd(deps), newTargetLogsReadCmd(deps))
	return c
}

func newTargetLogsListCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "list <server>",
		Short: "List the log sources of a server and the errors Michel found",
		Long: "List shows the log sources declared for the server, when each was last read, and the errors found, with their " +
			"count and status. The cleaned text of an error shows only if the server's settings keep it. It also says when a " +
			"setting is away from the recommended choice, and when nothing is set up to warn you.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			t, err := targetRef(cmd, deps, args[0])
			if err != nil {
				return err
			}
			repo := serverlog.NewRepo(deps.Store)
			srcs, err := repo.Sources(ctx, t.ID)
			if err != nil {
				return targetFailure(deps, err, false)
			}
			st, err := repo.Settings(ctx, t.ID)
			if err != nil {
				return targetFailure(deps, err, false)
			}
			sigs, err := repo.Signatures(ctx, t.ID)
			if err != nil {
				return targetFailure(deps, err, false)
			}
			v := logListing{Server: t.Name, Deviations: append([]string{}, serverlog.Deviations(st)...), Sources: []logSrcRow{}, Errors: []logErrRow{}}
			active := false
			for _, s := range srcs {
				cursors, err := repo.Cursors(ctx, s.ID)
				if err != nil {
					return targetFailure(deps, err, false)
				}
				row := logSrcRow{ID: s.ID, Path: scan.SanitizeText(s.Path), Format: string(s.Format), Active: s.Active}
				for _, c := range cursors {
					if c.ReadAt.After(row.LastRead) {
						row.LastRead = c.ReadAt
					}
				}
				active = active || s.Active
				v.Sources = append(v.Sources, row)
			}
			v.NoChannel = active && !api.LogChannelHears(deps.Policy, st)
			for _, g := range sigs {
				row := logErrRow{ID: g.ID, Level: string(g.Level), Type: scan.SanitizeText(g.Type), Location: scan.SanitizeText(g.Location),
					Channel: scan.SanitizeText(g.Channel), Status: string(g.Status), Total: g.Total, FirstAt: g.FirstAt, LastAt: g.LastAt}
				if st.StoreText {
					txt, ok, err := repo.Text(ctx, g.ID)
					if err != nil {
						return targetFailure(deps, err, false)
					}
					if ok {
						row.Text = scan.SanitizeText(txt)
					}
				}
				v.Errors = append(v.Errors, row)
			}
			if asJSON(cmd) {
				return json.NewEncoder(deps.Stdout).Encode(v)
			}
			return printLogs(deps, v, len(srcs))
		},
	}
}

// logSrcRow, logErrRow and logListing are what `logs list` shows (and prints as JSON).
type logSrcRow struct {
	ID, Path, Format string
	Active           bool
	LastRead         time.Time
}

type logErrRow struct {
	ID, Level, Type, Location, Channel, Status string
	Total                                      int64
	FirstAt, LastAt                            time.Time
	Text                                       string `json:",omitempty"`
}

type logListing struct {
	Server     string
	NoChannel  bool
	Deviations []string
	Sources    []logSrcRow
	Errors     []logErrRow
}

func stampOrDash(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func activeWord(a bool) string {
	if a {
		return "active"
	}
	return "off"
}

// printLogs writes the sources and the errors as tables, then the warnings. The
// text of an error, when there is one, follows the table.
func printLogs(deps *Deps, v logListing, declared int) error {
	out := deps.Stdout
	if declared == 0 {
		fmt.Fprintln(out, deps.T("cli.target.logs.no_sources", v.Server))
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "id\tformat\tstate\tlast_read\tpath")
	for _, s := range v.Sources {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.ID, s.Format, activeWord(s.Active), stampOrDash(s.LastRead), s.Path)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(v.Errors) == 0 {
		fmt.Fprintln(out, deps.T("cli.target.logs.no_errors"))
	} else {
		tw = tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "level\ttype\tlocation\tcount\tstatus\tlast_seen")
		var texts []string
		for _, e := range v.Errors {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n", e.Level, e.Type, e.Location, e.Total, e.Status, stampOrDash(e.LastAt))
			if e.Text != "" {
				texts = append(texts, e.Type+" "+e.Location+": "+e.Text)
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		for _, t := range texts {
			fmt.Fprintln(out, "  "+t)
		}
	}
	if len(v.Deviations) > 0 {
		fmt.Fprintln(out, deps.T("cli.target.logs.deviations", strings.Join(v.Deviations, ", ")))
	}
	if v.NoChannel {
		fmt.Fprintln(out, deps.T("api.logs.no_channel"))
	}
	return nil
}

func newTargetLogsReadCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "read <server>",
		Short: "Read the logs of a server now",
		Long: "Read runs one pass of the log reader on the server: the same read michel serve does at each interval, with the same " +
			"caps and the same filter. Errors that call for an alert at once are sent on your notification channels. A source " +
			"read for the first time only locates the end of its files: Michel does not replay the past.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := targetRef(cmd, deps, args[0])
			if err != nil {
				return err
			}
			repo := serverlog.NewRepo(deps.Store)
			srcs, err := repo.Sources(cmd.Context(), t.ID)
			if err != nil {
				return targetFailure(deps, err, false)
			}
			active := false
			for _, s := range srcs {
				active = active || s.Active
			}
			if !active {
				fmt.Fprintln(deps.Stdout, deps.T("cli.target.logs.read.nothing", t.Name))
				return nil
			}
			cd := serverCheckDeps(cmd, deps)
			ctx, cancel := context.WithTimeout(cmd.Context(), logReadBound)
			defer cancel()
			res, err := serverlog.Pass(ctx, serverlog.Deps{Repo: repo, Targets: cd.Repo, Audit: deps.Audit, SSH: cd.SSH,
				Alert: serverLogAlert(cmd, deps, repo), Now: deps.Now}, t.ID)
			if err != nil {
				switch {
				case servererr.Key(err) != "":
					return targetFailure(deps, err, true)
				case errors.Is(err, serverlog.ErrInactive):
					return deps.Errorf("cli.target.logs.read.inactive", t.Name)
				case errors.Is(err, serverlog.ErrPassRunning):
					return deps.Errorf("cli.target.logs.read.busy", t.Name)
				}
				// What the server printed is not repeated: only the cause.
				return deps.Errorf("cli.target.logs.read.failed", t.Name, deps.T("notify.log.reason."+logReasonKey(res.Reason)))
			}
			if asJSON(cmd) {
				return json.NewEncoder(deps.Stdout).Encode(res)
			}
			fmt.Fprintln(deps.Stdout, deps.N("cli.target.logs.read.done", res.Records, t.Name, res.Alerts))
			if res.Rejected > 0 {
				fmt.Fprintln(deps.Stdout, deps.N("cli.target.logs.read.rejected", res.Rejected))
			}
			return nil
		},
	}
}

// logReasonKey is the part of the catalog key for the cause of a failed read:
// a known reason, else the general one.
func logReasonKey(reason string) string {
	switch reason {
	case serverlog.ReasonNoAgent, serverlog.ReasonNoKeyAccepted, serverlog.ReasonHostKeyUnknown, serverlog.ReasonHostKeyChanged,
		serverlog.ReasonDenied, serverlog.ReasonTimeout, serverlog.ReasonOutputCut, serverlog.ReasonInactive, serverlog.ReasonBusy:
		return reason
	}
	return serverlog.ReasonError
}
