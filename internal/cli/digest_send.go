package cli

import (
	"context"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/notify"
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
// Each channel's result is audited either way (notify.send, never the body).
func sendDigest(ctx context.Context, cmd *cobra.Command, deps *Deps, opt digest.Options, once bool) (digestSend, error) {
	now := deps.Now().UTC()
	repo := digest.NewRepo(deps.Store)
	var seen string
	if once {
		last, hasLast, err := repo.Last(ctx)
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
		if seen, err = repo.Newest(ctx); err != nil {
			return digestSend{}, err
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
	deliveries, err := sendChannels(ctx, cmd, deps, d)
	if err != nil {
		if once {
			_ = repo.Release(settle, run.ID)
		}
		return digestSend{}, err
	}
	delivered := false
	for _, dl := range deliveries {
		run.Channels = append(run.Channels, dl.ChannelResult)
		delivered = delivered || dl.Result == notify.ResultOK
	}
	recorded := !once || delivered
	runID := run.ID
	switch {
	case !recorded:
		if err := repo.Release(settle, run.ID); err != nil {
			return digestSend{}, err
		}
		runID = ""
	case once:
		if err := repo.Finish(settle, run.ID, run.Channels); err != nil {
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
func heldMessage(deps *Deps, deliveries int) string {
	if deliveries == 0 {
		return deps.T("cli.digest.no_channel")
	}
	return deps.T("cli.digest.not_delivered")
}
