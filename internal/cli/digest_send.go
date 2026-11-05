package cli

import (
	"context"
	"log/slog"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/notify"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/spf13/cobra"
)

// digestState is how a call of sendDigest ended.
type digestState int

const (
	// digestSent: the digest reached a channel (or the call was a manual one)
	// and is recorded: the next one starts where this one ends.
	digestSent digestState = iota
	// digestHeld: the digest was computed but reached nobody (no channel, or
	// every channel failed). Nothing is recorded: the next digest covers the
	// same period, so nothing is lost.
	digestHeld
	// digestSkipped: a digest already left today, or another sender (michel
	// serve, the scheduled task) is sending it. Nothing was computed.
	digestSkipped
)

// digestSend is what sendDigest did. Digest and Deliveries are empty when the
// call was skipped.
type digestSend struct {
	Digest     digest.Digest
	Deliveries []notify.Delivery
	State      digestState
}

// sendDigest marks stale scans as interrupted, takes the due deferrals out of
// force, computes the digest and sends it on every enabled channel (one
// failure never stops the others).
//
// With once false (michel digest --send) it always sends and always records
// the run, even when no channel got it: the run is the "since last time" mark.
//
// With once true (the loop of michel serve, scan --digest) it sends one digest
// a day, shared by every sender: it skips when one already left today, and it
// claims the window in the record of the last digest before it sends, so that
// two senders at once cannot both send. The run is kept only when a channel
// got the digest; else the claim is given back and the window does not move.
// skip names the channels that already received this digest on an earlier try
// (the loop keeps them for the day): they get no copy.
// Each channel's result is audited either way (notify.send, never the body).
func sendDigest(ctx context.Context, cmd *cobra.Command, deps *Deps, opt digest.Options, once bool, skip map[string]bool) (digestSend, error) {
	now := deps.Now().UTC()
	repo := digest.NewRepo(deps.Store)
	var seen string
	if once {
		// The state the claim will be compared with is read first: whatever is saved
		// after it makes the claim fail, so no other check can lag behind it.
		var err error
		if seen, err = repo.Newest(ctx, now); err != nil {
			return digestSend{}, err
		}
		// Only a digest that reached somebody counts as sent today.
		last, hasLast, err := repo.LastDelivered(ctx)
		if err != nil {
			return digestSend{}, err
		}
		busy, err := repo.InFlight(ctx, now)
		if err != nil {
			return digestSend{}, err
		}
		if busy || (hasLast && sameDay(last.CreatedAt, deps.Now())) {
			return digestSend{State: digestSkipped}, nil
		}
	}
	swept, err := scan.SweepStale(ctx, deps.Store.DB(), now, scan.StaleScanAfter)
	if err != nil {
		return digestSend{}, err
	}
	if swept > 0 {
		if _, err := deps.Audit.Record(ctx, audit.Event{Actor: "digest", Action: "scan.sweep", Target: "digest", Result: "ok",
			Evidence: map[string]any{"swept": swept, "max_age": scan.StaleScanAfter.String()}}); err != nil {
			return digestSend{}, err
		}
	}
	if _, err := decide.NewRepo(deps.Store).ExpireDue(ctx, now, deps.Audit); err != nil {
		return digestSend{}, err
	}
	d, err := digest.Compute(ctx, deps.Store, now, deps.Lang, opt)
	if err != nil {
		return digestSend{}, err
	}
	if once && opt.Since.IsZero() {
		// Without a digest sent yet, the start of this window is kept: a digest that
		// reaches nobody records no run, and the next window must not start later.
		if _, has, err := repo.Last(ctx); err == nil && !has {
			if err := repo.HoldStart(ctx, d.Since); err != nil {
				return digestSend{}, err
			}
		}
	}
	run := digest.RunOf(d, now)
	if once {
		if digestChannels(deps) == 0 {
			return digestSend{Digest: d, State: digestHeld}, nil
		}
		digestBeforeClaim()
		claimed, err := repo.Claim(ctx, run, seen)
		if err != nil {
			return digestSend{}, err
		}
		if !claimed {
			return digestSend{State: digestSkipped}, nil
		}
	}
	// A stop of serve in the middle of a send must not leave the claim behind.
	settle := context.WithoutCancel(ctx)
	deliveries, err := sendChannels(ctx, cmd, deps, d, skip)
	if err != nil {
		if once {
			if rerr := repo.Release(settle, run.ID); rerr != nil {
				slog.Error("digest: cannot give back the claim", "err", rerr)
			}
		}
		return digestSend{}, err
	}
	for _, dl := range deliveries {
		run.Channels = append(run.Channels, dl.ChannelResult)
	}
	delivered, reminded := deliveredTo(deps, deliveries)
	if !reminded {
		delete(run.Summary, "deviation_reminded")
	}
	recorded := !once || delivered
	runID := run.ID
	switch {
	case !recorded:
		if err := repo.Release(settle, run.ID); err != nil {
			slog.Error("digest: cannot give back the claim of a digest nobody received, the next digest waits for it to expire", "err", err)
		}
		runID = ""
	case once:
		if err := repo.Finish(settle, run.ID, run.Channels, reminded); err != nil {
			slog.Error("digest: the digest was sent but could not be recorded as sent: it may be sent again", "err", err)
			return digestSend{}, err
		}
	default:
		if err := repo.Save(ctx, run); err != nil {
			return digestSend{}, err
		}
	}
	for _, dl := range deliveries {
		// Never the body: the channel, where it went, how it ended, its size.
		if _, err := deps.Audit.Record(settle, audit.Event{Actor: "digest", Action: "notify.send", Target: dl.Name, Result: dl.Result,
			Evidence: map[string]any{"channel": dl.Name, "type": dl.Type, "host": dl.Host, "result": dl.Result, "bytes": dl.Bytes,
				"run_id": runID}}); err != nil {
			return digestSend{}, err
		}
	}
	if !recorded {
		return digestSend{Digest: d, Deliveries: deliveries, State: digestHeld}, nil
	}
	if _, err := deps.Audit.Record(settle, audit.Event{Actor: "digest", Action: "digest.run", Target: run.ID, Result: "ok",
		Evidence: map[string]any{
			"run_id": run.ID, "since": run.Since.UTC().Format(time.RFC3339), "until": run.Until.UTC().Format(time.RFC3339),
			"projects": len(d.Projects), "new_total": d.NewTotal, "attention_total": d.AttentionTotal, "channels": run.Channels,
		}}); err != nil {
		return digestSend{}, err
	}
	return digestSend{Digest: d, Deliveries: deliveries, State: digestSent}, nil
}

// heldMessage is the sentence that says a digest was not recorded as sent: no
// channel at all, or channels that all failed.
func heldMessage(deps *Deps, deliveries []notify.Delivery) string {
	if len(deliveries) == 0 {
		return deps.T("cli.digest.no_channel")
	}
	for _, dl := range deliveries {
		if dl.Result == notify.ResultOK {
			// Some channels got it, none of those that carry the server sections.
			return deps.T("cli.digest.partly_delivered")
		}
	}
	return deps.T("cli.digest.not_delivered")
}

// deliveredTo says whether the digest reached somebody, and whether the
// sections about servers did. A channel limited to some projects gets no
// server section, so when a channel without such a limit is enabled, only an
// ok on one of those counts as delivered (else the errors of the servers would
// be taken for told and be lost); when every channel is limited, any ok counts.
// The weekly reminder of the settings is a server section: it counts as told
// on an unlimited channel only.
func deliveredTo(deps *Deps, deliveries []notify.Delivery) (delivered, reminded bool) {
	scoped := map[string]bool{}
	unlimited := false
	for _, c := range deps.Policy().Notify.Channels {
		if !c.IsEnabled() || c.Type == policy.ChannelSMS {
			continue
		}
		scoped[c.Name] = len(c.Projects) > 0
		unlimited = unlimited || len(c.Projects) == 0
	}
	anyOK := false
	for _, dl := range deliveries {
		if dl.Result != notify.ResultOK {
			continue
		}
		anyOK = true
		if !scoped[dl.Name] {
			reminded = true
		}
	}
	if unlimited {
		return reminded, reminded
	}
	return anyOK, reminded
}
