package fix

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/workcopy"
)

// HeldExpiry is how long a held attempt waits for an answer before it ends as
// a no. While it waits, the project takes no other fix and the copy stays.
const HeldExpiry = 14 * 24 * time.Hour

// maxHoldFiles and maxHoldLines bound what a hold lists: the count stays whole.
const (
	maxHoldFiles = 20
	maxHoldLines = 20
)

// HoldFile is one file where the detectors found a possible key: its path in
// the project and the lines, never the value.
type HoldFile struct {
	File  string `json:"file"`
	Lines []int  `json:"lines"`
}

// HoldInfo is what a held attempt asks about: how many possible keys, where,
// and the hash the answer must send back.
type HoldInfo struct {
	Count int        `json:"count"`
	Files []HoldFile `json:"files"`
	// More is how many other files hold one, beyond Files.
	More int    `json:"more"`
	Hash string `json:"hash"`
}

// sortedHits is hits in one order, whichever walk found them.
func sortedHits(hits []mask.Hit) []mask.Hit {
	out := slices.Clone(hits)
	slices.SortFunc(out, func(a, b mask.Hit) int {
		return cmp.Or(cmp.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line), cmp.Compare(string(a.Kind), string(b.Kind)))
	})
	return out
}

// holdFingerprint names what the person was shown: the commit of the copy, its
// content and the hits. It holds no value.
func holdFingerprint(w Work) string {
	h := sha256.New()
	fmt.Fprintf(h, "hold\x00%s\x00%s\x00", w.Copy.Base, w.HoldSum)
	for _, hit := range sortedHits(w.Copy.SecretHits) {
		fmt.Fprintf(h, "%s\x00%d\x00%s\x00", hit.File, hit.Line, hit.Kind)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// HoldOf is what a held attempt asks about; ok is false in any other state.
func HoldOf(a Attempt) (HoldInfo, bool) {
	if a.State != StateHeld {
		return HoldInfo{}, false
	}
	hits := sortedHits(strongHits(a.Work.Copy.SecretHits))
	info := HoldInfo{Count: len(hits), Files: []HoldFile{}, Hash: holdFingerprint(a.Work)}
	last, listed := "", false
	for _, hit := range hits {
		if !listed || hit.File != last {
			last = hit.File
			listed = len(info.Files) < maxHoldFiles
			if !listed {
				info.More++
				listed = true
				continue
			}
			info.Files = append(info.Files, HoldFile{File: scan.SanitizeText(hit.File), Lines: []int{}})
		}
		if info.More > 0 {
			continue
		}
		f := &info.Files[len(info.Files)-1]
		if len(f.Lines) < maxHoldLines && !slices.Contains(f.Lines, hit.Line) {
			f.Lines = append(f.Lines, hit.Line)
		}
	}
	return info, true
}

// holdEvidence is the audit of a hold: counts only, never a file nor a value.
func holdEvidence(a Attempt) map[string]any {
	strong := strongHits(a.Work.Copy.SecretHits)
	files := map[string]bool{}
	for _, h := range strong {
		files[h.File] = true
	}
	return map[string]any{"attempt_id": a.ID, "finding_id": a.FindingID, "project_id": a.ProjectID, "origin": a.Origin,
		"secret_hits": len(strong), "weak_hits": len(a.Work.Copy.SecretHits) - len(strong), "files": len(files)}
}

// strongHits are the hits that stop an agent. The others are only told.
func strongHits(hits []mask.Hit) []mask.Hit {
	return slices.DeleteFunc(slices.Clone(hits), func(h mask.Hit) bool { return !h.Strong })
}

// weakHits are the hits that do not stop an agent: a type, a variable, a call
// or a sentence on a sensitive name.
func weakHits(hits []mask.Hit) []mask.Hit {
	return slices.DeleteFunc(slices.Clone(hits), func(h mask.Hit) bool { return h.Strong })
}

// hold stops the attempt before anything leaves the computer: no agent, no
// update (it would use the network), no token. The copy stays for the answer.
func (d Deps) hold(ctx context.Context, a Attempt, c workcopy.Copy) (Attempt, error) {
	repo := d.repo()
	sum, _, err := workcopy.Reread(d.work(), c)
	if err != nil {
		return d.failStart(ctx, a, c, "fix.cause.prepare_failed", err)
	}
	a.Work = Work{Copy: c, HoldSum: sum}
	if err := repo.SetWork(ctx, a.ID, a.Work); err != nil {
		return d.failStart(ctx, a, c, "fix.cause.prepare_failed", err)
	}
	if err := d.record(ctx, "fix.hold", a.FindingID, "ok", holdEvidence(a)); err != nil {
		return d.failStart(ctx, a, c, "fix.cause.prepare_failed", err)
	}
	if text := secretHitsMessage(d.lang(), strongHits(c.SecretHits)); text != "" {
		_, _ = repo.AddMessage(ctx, Message{AttemptID: a.ID, Role: RoleMichel, Text: text})
	}
	if err := repo.SetState(ctx, a.ID, []State{StatePreparing}, StateHeld, ""); err != nil {
		return d.failStart(ctx, a, c, "fix.cause.prepare_failed", err)
	}
	// Nobody is looking at a start Michel made alone.
	if d.NotifyHeld != nil && a.Origin == OriginAgentAuto {
		d.NotifyHeld(ctx, 1)
	}
	return repo.GetAttempt(ctx, a.ID)
}

// actorAnswers says the actor is a person's way in: the page or the command
// line, and nothing else. It names the door used, not who is behind it.
func actorAnswers(actor string) bool {
	switch actor {
	case "cli", "web":
		return true
	}
	return false
}

// holdChanged says what was searched is no longer what the agent would read,
// or that the flaw left and there is nothing to send the code for.
func (d Deps) holdChanged(ctx context.Context, a Attempt, fi scan.Finding, p project.Project) bool {
	c := a.Work.Copy
	if fi.Status == scan.StatusGone || a.Work.HoldSum == "" {
		return true
	}
	if head, err := workcopy.Head(ctx, d.work(), p); err != nil || head != c.Base {
		return true
	}
	// A folder excluded since is meant to stay out, and it is in this copy.
	if !slices.Equal(sortedStrings(p.Exclude), sortedStrings(c.Exclude)) {
		return true
	}
	sum, hits, err := workcopy.Reread(d.work(), c)
	if err != nil || sum != a.Work.HoldSum {
		return true
	}
	return !slices.Equal(sortedHits(hits), sortedHits(c.SecretHits))
}

func sortedStrings(list []string) []string {
	out := slices.Clone(list)
	slices.Sort(out)
	return out
}

// ContinueHeld is a person's yes to a held attempt, for that attempt only:
// hash must be what HoldOf gave. Every gate of Start is checked again; a
// missing one leaves the attempt waiting. When the copy, the project or the
// search changed, the attempt ends failed and nothing starts (ErrHoldStale),
// and a new start searches again. Otherwise the agent starts as in Start.
func ContinueHeld(ctx context.Context, d Deps, attemptID, hash string) (Attempt, error) {
	repo := d.repo()
	lock := d.sessions().attemptLock(attemptID)
	lock.Lock()
	a, err := repo.GetAttempt(ctx, attemptID)
	if err != nil {
		lock.Unlock()
		return Attempt{}, err
	}
	refuse := func(reason string, err error) (Attempt, error) {
		ev := holdEvidence(a)
		ev["reason"], ev["author"] = reason, d.actor()
		_ = d.record(ctx, "fix.hold.continue", a.FindingID, "refused", ev)
		lock.Unlock()
		return Attempt{}, err
	}
	if !actorAnswers(d.Actor) {
		return refuse("not_a_person", ErrHoldPerson)
	}
	if a.State != StateHeld {
		lock.Unlock()
		return Attempt{}, fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	if hash != holdFingerprint(a.Work) {
		return refuse("other_hash", ErrHoldStale)
	}
	fi, p, err := d.find(ctx, a.FindingID)
	if err != nil {
		lock.Unlock()
		return Attempt{}, err
	}
	if err := d.startGates(ctx, p); err != nil {
		lock.Unlock()
		return Attempt{}, err
	}
	if d.holdChanged(ctx, a, fi, p) {
		text := i18n.T(d.lang(), "fix.cause.hold_stale")
		if err := repo.SetState(ctx, a.ID, []State{StateHeld}, StateFailed, text); err != nil {
			lock.Unlock()
			return Attempt{}, err
		}
		d.cleanup(ctx, a, true)
		return refuse("changed", ErrHoldStale)
	}
	if err := repo.SetState(ctx, a.ID, []State{StateHeld}, StatePreparing, ""); err != nil {
		lock.Unlock()
		return Attempt{}, err
	}
	ev := holdEvidence(a)
	ev["author"] = d.actor()
	err = d.record(ctx, "fix.hold.continue", a.FindingID, "ok", ev)
	// The end of the session takes this lock.
	lock.Unlock()
	if err != nil {
		return d.failStart(ctx, a, a.Work.Copy, "fix.cause.prepare_failed", err)
	}
	_, _ = repo.AddMessage(ctx, Message{AttemptID: a.ID, Role: RoleMichel, Text: i18n.N(d.lang(), "fix.msg.hold_continued", len(strongHits(a.Work.Copy.SecretHits)))})
	return d.launch(ctx, a, fi, p, a.Work.Copy)
}

// expireHeld ends the attempts nobody answered for HeldExpiry, as a no: only a
// no, never a yes. The copy is removed and the project takes fixes again;
// alreadyTried keeps the queue from asking again before a new commit.
func (d Deps) expireHeld(ctx context.Context) error {
	repo := d.repo()
	held, err := repo.ListAttempts(ctx, "", string(StateHeld))
	if err != nil {
		return err
	}
	days := int(HeldExpiry / (24 * time.Hour))
	for _, a := range held {
		if d.now().Sub(a.UpdatedAt) < HeldExpiry {
			continue
		}
		lock := d.sessions().attemptLock(a.ID)
		lock.Lock()
		err := repo.SetState(ctx, a.ID, []State{StateHeld}, StateWithdrawn, i18n.T(d.lang(), "fix.cause.hold_expired", days))
		if err == nil {
			d.cleanup(ctx, a, true)
			ev := holdEvidence(a)
			ev["author"] = "expired"
			_ = d.record(ctx, "fix.hold.withdraw", a.FindingID, "ok", ev)
		}
		lock.Unlock()
	}
	return nil
}

// WithdrawHeld ends a held attempt on the person's word: no agent started,
// the copy is removed. The finding stays as it was.
func WithdrawHeld(ctx context.Context, d Deps, attemptID string) error {
	repo := d.repo()
	lock := d.sessions().attemptLock(attemptID)
	lock.Lock()
	defer lock.Unlock()
	a, err := repo.GetAttempt(ctx, attemptID)
	if err != nil {
		return err
	}
	if err := repo.SetState(ctx, a.ID, []State{StateHeld}, StateWithdrawn, i18n.T(d.lang(), "fix.cause.hold_withdrawn")); err != nil {
		return err
	}
	d.cleanup(ctx, a, true)
	ev := holdEvidence(a)
	ev["author"] = d.actor()
	return d.record(ctx, "fix.hold.withdraw", a.FindingID, "ok", ev)
}
