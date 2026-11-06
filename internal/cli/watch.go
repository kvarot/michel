package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/kvarot/michel/internal/api"
	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/sourceupdate"
	"github.com/kvarot/michel/internal/watch"
	"github.com/spf13/cobra"
)

// watchTick is how often michel serve looks at whether the daily watch is due.
var watchTick = time.Minute

// watchLoop is watch.Loop; replaced in tests.
var watchLoop = watch.Loop

// serveWatchDeps wires the daily watch of michel serve: the sources are read
// as michel source update does (a source waiting for consent reads nothing and
// says so), then the due projects are checked with scanOne, the same pass and
// the same one-at-a-time lock as a check from the page.
func serveWatchDeps(cmd *cobra.Command, deps *Deps, fd fix.Deps, scanOne func(ctx context.Context, p project.Project) error) watch.Deps {
	return watch.Deps{
		Now:    deps.Now,
		Policy: deps.Policy,
		Projects: func(ctx context.Context) ([]project.Project, error) {
			return projectRepo(deps).List(ctx)
		},
		Repo: watch.NewRepo(deps.Store),
		Sources: func(ctx context.Context) error {
			fmt.Fprintln(deps.Stdout, deps.T("cli.watch.sources"))
			rep, err := sourceUpdateIn(ctx, cmd, deps, nil, "")
			if err != nil && !errors.Is(err, sourceupdate.ErrSomeFailed) {
				return err
			}
			printSourceUpdate(deps, rep)
			return err
		},
		Scan: func(ctx context.Context, p project.Project) error {
			// As the page's check: no reading of a folder a click is
			// writing, and no click during the check (R35).
			unlock, free := fix.TryGitLock(fd, p.ID)
			if !free {
				return watch.ErrBusy
			}
			defer unlock()
			err := scanOne(ctx, p)
			if errors.Is(err, api.ErrNothingToScan) {
				return nil // a folder without dependencies is checked, not failed
			}
			return err
		},
	}
}

func newWatchCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{
		Use:   "watch",
		Short: "See the daily watch of michel serve",
		Long: "While michel serve runs, it watches by itself once a day, from watch.scan_at (an hour before the digest by default): " +
			"it reads the enabled sources, as michel source update, then checks every active project, as michel scan. " +
			"michel project set <name> --auto-scan=false takes a project out of it; watch.enabled: false turns it off.",
	}
	c.AddCommand(newWatchStatusCmd(deps))
	return c
}

// watchProjectView is one project in michel watch status --json.
type watchProjectView struct {
	Name           string `json:"name"`
	AutoScan       bool   `json:"auto_scan"`
	LastScanAt     string `json:"last_scan_at"`
	LastScanStatus string `json:"last_scan_status"`
	NextScanAt     string `json:"next_scan_at"`
}

func newWatchStatusCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the hour of the daily watch, and the last and next check of each project",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			now := deps.Now()
			h, m, on := deps.Policy().WatchHour()
			list, err := projectRepo(deps).List(ctx)
			if err != nil {
				return err
			}
			repo := watch.NewRepo(deps.Store)
			views := []watchProjectView{}
			for _, p := range list {
				if !p.Active {
					continue
				}
				v := watchProjectView{Name: p.Name, AutoScan: p.AutoScan, LastScanStatus: "never"}
				at, status, has, err := repo.LastScan(ctx, p.ID)
				if err != nil {
					return err
				}
				if has {
					v.LastScanAt, v.LastScanStatus = at.UTC().Format(time.RFC3339), status
				}
				if on && p.AutoScan {
					// From the last check that counts, as the watch itself.
					start, counted, err := repo.LastStart(ctx, p.ID)
					if err != nil {
						return err
					}
					v.NextScanAt = watch.Next(start, counted, now, h, m).UTC().Format(time.RFC3339)
				}
				views = append(views, v)
			}
			next := ""
			if on {
				next = watch.Next(now, true, now, h, m).UTC().Format(time.RFC3339)
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(deps.Stdout).Encode(struct {
					Enabled  bool               `json:"enabled"`
					ScanAt   string             `json:"scan_at"`
					NextPass string             `json:"next_pass"`
					Projects []watchProjectView `json:"projects"`
				}{on, hourText(on, h, m), next, views})
			}
			if !on {
				fmt.Fprintln(deps.Stdout, deps.T("cli.watch.status.off"))
			} else {
				fmt.Fprintln(deps.Stdout, deps.T("cli.watch.status.on", hourText(on, h, m), whenText(deps, watch.Next(now, true, now, h, m), now)))
				fmt.Fprintln(deps.Stdout, deps.T("cli.watch.status.serve_needed"))
			}
			if len(views) == 0 {
				fmt.Fprintln(deps.Stdout, deps.T("cli.watch.status.no_projects"))
				return nil
			}
			fmt.Fprintln(deps.Stdout)
			tw := tabwriter.NewWriter(deps.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, deps.T("cli.watch.status.header"))
			for _, v := range views {
				last := deps.T("cli.watch.status.never")
				if v.LastScanAt != "" {
					t, _ := time.Parse(time.RFC3339, v.LastScanAt)
					last = deps.T("cli.watch.status.last", t.In(now.Location()).Format("2006-01-02 15:04"), deps.T("cli.watch.scan_status."+v.LastScanStatus))
				}
				nextText := deps.T("cli.watch.status.project_off")
				if v.NextScanAt != "" {
					t, _ := time.Parse(time.RFC3339, v.NextScanAt)
					nextText = whenText(deps, t.In(now.Location()), now)
				} else if !on {
					nextText = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", v.Name, last, nextText)
			}
			return tw.Flush()
		},
	}
}

// hourText is HH:MM, "" when the watch is off.
func hourText(on bool, h, m int) string {
	if !on {
		return ""
	}
	return fmt.Sprintf("%02d:%02d", h, m)
}

// whenText says t from now: "today at 07:00", "tomorrow at 07:00", or the date.
func whenText(deps *Deps, t, now time.Time) string {
	hm := t.Format("15:04")
	ty, tm, td := t.Date()
	y, m, d := now.Date()
	switch {
	case ty == y && tm == m && td == d:
		return deps.T("cli.watch.when.today", hm)
	case time.Date(y, m, d+1, 0, 0, 0, 0, now.Location()).Equal(time.Date(ty, tm, td, 0, 0, 0, 0, now.Location())):
		return deps.T("cli.watch.when.tomorrow", hm)
	}
	return deps.T("cli.watch.when.date", t.Format("2006-01-02"), hm)
}
