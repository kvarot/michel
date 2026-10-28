package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/feed"
	"github.com/kvarot/michel/internal/scan"
	"github.com/spf13/cobra"
)

func newSourceItemsCmd(deps *Deps) *cobra.Command {
	var unread bool
	var since string
	var tech []string
	c := &cobra.Command{
		Use:   "items",
		Short: "List the feed items to read: those about the technologies you use",
		Long: "Items lists what the feeds brought that is worth reading: the items whose source or title meets a technology " +
			"of your projects (declared with michel project set --tech or detected in the manifests) or declared with " +
			"michel tech add. --tech replaces those technologies for this listing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			from, err := parseItemsSince(since, deps.Now())
			if err != nil {
				return deps.Errorf("cli.source.items.bad_since", since)
			}
			asJSON, _ := cmd.Flags().GetBool("json")
			if len(tech) == 0 {
				if tech, err = feed.DeclaredAll(cmd.Context(), deps.Store); err != nil {
					return deps.Wrapf("cli.source.items.failed", err)
				}
				if len(tech) == 0 && !asJSON {
					fmt.Fprintln(deps.Stdout, deps.T("cli.source.items.no_tech"))
					return nil
				}
			}
			items, err := feed.NewRepo(deps.Store).ListToRead(cmd.Context(), from, unread, tech)
			if err != nil {
				return deps.Wrapf("cli.source.items.failed", err)
			}
			for i := range items {
				items[i].Title = feed.Title(deps.Lang, items[i])
			}
			if asJSON {
				return json.NewEncoder(deps.Stdout).Encode(items)
			}
			if len(items) == 0 {
				fmt.Fprintln(deps.Stdout, deps.T("cli.source.items.none"))
				return nil
			}
			out := deps.Stdout
			for _, it := range items {
				head := []string{it.ID, itemDay(it), scan.SanitizeText(it.SourceName)}
				if it.ReadAt != "" {
					head = append(head, deps.T("cli.source.items.read_mark"))
				}
				fmt.Fprintln(out, strings.Join(head, "  "))
				fmt.Fprintln(out, "  "+it.Title)
				if it.URL != "" {
					fmt.Fprintln(out, "  "+it.URL)
				}
			}
			return nil
		},
	}
	f := c.Flags()
	f.BoolVar(&unread, "unread", false, "only the items not marked as read")
	f.StringVar(&since, "since", "", "only the items published since then: a number of days (7d), hours (48h) or a date (YYYY-MM-DD)")
	f.StringArrayVar(&tech, "tech", nil, "list the items about this technology instead of yours (repeatable)")
	return c
}

// itemDay is the day an item counts from, in local time.
func itemDay(it feed.Item) string {
	s := it.PublishedAt
	if s == "" {
		s = it.SeenAt
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return "-"
	}
	return t.Local().Format(time.DateOnly)
}

// parseItemsSince reads "7d", "48h" or "2026-10-01" ("" is no bound).
func parseItemsSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return time.Time{}, errors.New("bad number of days")
		}
		return now.AddDate(0, 0, -n), nil
	}
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		return now.Add(-d), nil
	}
	return time.ParseInLocation(time.DateOnly, s, time.Local)
}

func newSourceReadCmd(deps *Deps) *cobra.Command {
	var all bool
	c := &cobra.Command{
		Use:   "read <item-id> | --all",
		Short: "Mark a feed item as read, or all of them with --all",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if all == (len(args) == 1) {
				return deps.Errorf("cli.source.read.usage")
			}
			r := feed.NewRepo(deps.Store)
			now := deps.Now()
			if all {
				n, err := r.MarkAllRead(cmd.Context(), now)
				if err != nil {
					return deps.Wrapf("cli.source.items.failed", err)
				}
				if err := recordSource(cmd, deps, "source.item_read", "all", "ok", map[string]any{"count": n}); err != nil {
					return err
				}
				fmt.Fprintln(deps.Stdout, deps.N("cli.source.read.all", n))
				return nil
			}
			id := args[0]
			err := r.MarkRead(cmd.Context(), id, now)
			if errors.Is(err, feed.ErrItemNotFound) {
				return deps.Errorf("cli.source.read.not_found", id)
			}
			if err != nil {
				return deps.Wrapf("cli.source.items.failed", err)
			}
			if err := recordSource(cmd, deps, "source.item_read", id, "ok", map[string]any{"count": 1}); err != nil {
				return err
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.source.read.done", id))
			return nil
		},
	}
	c.Flags().BoolVar(&all, "all", false, "mark every item as read")
	return c
}
