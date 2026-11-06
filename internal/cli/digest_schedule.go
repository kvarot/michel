package cli

import (
	"context"
	"log/slog"
	"time"

	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/notify"
	"github.com/kvarot/michel/internal/policy"
	"github.com/spf13/cobra"
)

// digestTick is how often michel serve looks at whether the daily digest is due.
const digestTick = time.Minute

// digestRetry is how long the loop waits before it tries again a digest that
// reached nobody (every channel failed).
const digestRetry = 15 * time.Minute

// digestLoop is runDigestLoop; replaced in tests.
var digestLoop = runDigestLoop

// digestLogWait is how long the first look at the digest waits for the first round
// of the log scheduler (deps.LogsReady): what was written while the computer was
// off, and the holes in the reading, are then in the digest. A variable for tests.
var digestLogWait = 2 * time.Minute

// digestLagWait is how long the look waits once the first round has ended: the
// period of a digest stops digest.LogReadLag before now, and that round must be
// in it. A variable for tests.
var digestLagWait = digest.LogReadLag + time.Second

// Test hooks of the loop: tick is called at the start of each look, waiting
// when the loop starts to wait for the logs.
var (
	digestTickHook    = func() {}
	digestWaitingHook = func() {}
)

// digestBeforeClaim, when set (tests), is called once a digest is computed and
// before it is claimed: the point where two senders can meet.
var digestBeforeClaim = func() {}

// sameDay says whether a and b are on the same calendar day in b's zone.
func sameDay(a, b time.Time) bool {
	a = a.In(b.Location())
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

// digestDue says whether the daily digest is due at now: at is the hour of
// the day ("HH:MM", local, or "off" for never; empty is the default), the
// hour has come, and no digest was sent on this local day. A computer that was
// off at the hour gets its digest as soon as it is on: it is due all day.
func digestDue(last digest.Run, hasLast bool, now time.Time, at string) bool {
	h, m, on := policy.NotifyConfig{DigestAt: at}.DigestHour()
	if !on {
		return false
	}
	y, mo, d := now.Date()
	if now.Before(time.Date(y, mo, d, h, m, 0, 0, now.Location())) {
		return false
	}
	return !hasLast || !sameDay(last.CreatedAt, now)
}

// digestChannels counts the channels the digest can go to: enabled ones, the
// SMS excluded (the digest never goes by SMS).
func digestChannels(deps *Deps) int {
	n := 0
	for _, c := range deps.Policy().Notify.Channels {
		if c.IsEnabled() && c.Type != policy.ChannelSMS {
			n++
		}
	}
	return n
}

// runDigestLoop sends the daily digest of michel serve until ctx ends: it
// looks every `every`, starts with a look at once (a computer that was off at
// the hour gets its digest as soon as serve starts), and sends when the digest
// is due. It shares the record of the last digest with the scheduled task
// (michel scan --all --update --digest), so a digest already sent today is not
// sent again. Nothing is recorded when nobody received the digest, so the
// next one covers the same period.
func runDigestLoop(ctx context.Context, cmd *cobra.Command, deps *Deps, every time.Duration) {
	var retryAt time.Time
	warned := false
	// The channels that got a digest that stayed held, for the local day it was
	// sent: a retry the same day does not send them a second copy. In memory: a
	// restart of serve can repeat one.
	served, servedDay := map[string]bool{}, ""
	tick := func() {
		digestTickHook()
		now := deps.Now()
		if digestChannels(deps) == 0 {
			// Nobody to send to: the window must still start here, not slide with
			// the clock until a channel is added.
			holdFirstWindow(ctx, deps, now)
			return
		}
		if now.Before(retryAt) {
			return
		}
		repo := digest.NewRepo(deps.Store)
		last, hasLast, err := repo.LastDelivered(ctx)
		if err == nil {
			var busy bool
			if busy, err = repo.InFlight(ctx, now); err == nil && busy {
				return
			}
		}
		if err != nil {
			if ctx.Err() == nil {
				slog.Warn("serve: cannot read the last digest", "err", err)
			}
			return
		}
		if !digestDue(last, hasLast, now, deps.Policy().Notify.DigestAt) {
			return
		}
		opt, err := digestOptions(cmd, deps, "")
		if err != nil {
			slog.Warn("serve: cannot prepare the digest", "err", err)
			return
		}
		if day := now.Format("2006-01-02"); day != servedDay {
			served, servedDay = map[string]bool{}, day
		}
		res, err := sendDigest(ctx, cmd, deps, opt, true, served)
		switch {
		case ctx.Err() != nil:
		case err != nil:
			slog.Warn("serve: cannot send the digest", "err", err)
			retryAt = now.Add(digestRetry)
		case res.State == digestHeld:
			partly := false
			for _, dl := range res.Deliveries {
				if dl.Result == notify.ResultOK {
					served[dl.Name] = true
					partly = true
				}
			}
			// Said once per incident, not at each retry; nothing of the digest in it.
			if !warned {
				if partly {
					slog.Warn("serve: the digest reached some channels but not those that carry the server sections, it is tried again later on the others and nothing is lost")
				} else {
					slog.Warn("serve: the digest reached nobody, it is tried again later and nothing is lost")
				}
				warned = true
			}
			retryAt = now.Add(digestRetry)
		default:
			warned = false
		}
	}
	if deps.LogsReady != nil {
		digestWaitingHook()
		wait := time.NewTimer(digestLogWait)
		select {
		case <-deps.LogsReady:
			lag := time.NewTimer(digestLagWait)
			select {
			case <-lag.C:
			case <-ctx.Done():
			}
			lag.Stop()
		case <-wait.C:
		case <-ctx.Done():
		}
		wait.Stop()
	}
	tick()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// holdFirstWindow keeps the start of the first window (24 hours before now)
// when no digest was sent yet, so that it does not move while nobody can get one.
func holdFirstWindow(ctx context.Context, deps *Deps, now time.Time) {
	repo := digest.NewRepo(deps.Store)
	if _, has, err := repo.Last(ctx); err != nil || has {
		return
	}
	if err := repo.HoldStart(ctx, now.UTC().Add(-digest.DefaultWindow)); err != nil && ctx.Err() == nil {
		slog.Warn("serve: cannot keep the start of the first digest", "err", err)
	}
}
