package digest

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// A digest sent by michel serve and the same digest sent by the scheduled
// task must not both go out. The sender first claims the window: a row of
// digest_run marked pending, saved only if nobody saved one since the sender
// read the state. It then sends, and either finishes the claim (somebody got
// the digest) or releases it (nobody did, so the window stays where it was).

// PendingTTL is how long a claim may stay pending: past it the process that
// made it is taken for dead and the claim no longer counts.
const PendingTTL = 10 * time.Minute

// pendingRoom is how many pending claims List steps over: one at a time is
// alive, the others are abandoned ones.
const pendingRoom = 20

// Pending says whether the run is a claim whose send is not over.
func (r Run) Pending() bool { return r.Summary["pending"] == 1 }

// Newest returns the id of the newest row, pending claims included ("" when
// there is none). It is what Claim compares with.
func (r *Repo) Newest(ctx context.Context) (string, error) {
	var id string
	err := r.s.DB().QueryRowContext(ctx, `SELECT COALESCE((SELECT id FROM digest_run ORDER BY created_at DESC, id DESC LIMIT 1), '')`).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("cannot read the digest runs: %w", err)
	}
	return id, nil
}

// Claim saves run as a pending claim, unless another run was saved since the
// caller read Newest (seen). Of two processes that send at once, one wins: the
// test and the insert are one statement, which the database runs alone.
func (r *Repo) Claim(ctx context.Context, run Run, seen string) (bool, error) {
	if run.ID == "" {
		run.ID = ulid.Make().String()
	}
	if run.CreatedAt.IsZero() {
		run.CreatedAt = time.Now()
	}
	summary := map[string]int{}
	for k, v := range run.Summary {
		summary[k] = v
	}
	summary["pending"] = 1
	projects := run.Projects
	if projects == nil {
		projects = []ProjectSummary{}
	}
	pj, _ := json.Marshal(projects)
	sm, _ := json.Marshal(summary)
	res, err := r.s.DB().ExecContext(ctx, `INSERT INTO digest_run (id, since, until, lang, projects, summary, channels, created_at)
		SELECT ?,?,?,?,?,?,?,? WHERE COALESCE((SELECT id FROM digest_run ORDER BY created_at DESC, id DESC LIMIT 1), '') = ?`,
		run.ID, timeText(run.Since), timeText(run.Until), string(run.Lang), string(pj), string(sm), "[]", timeText(run.CreatedAt), seen)
	if err != nil {
		return false, fmt.Errorf("cannot save the digest run: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// Finish turns a claim into a sent digest and records what happened on its channels.
func (r *Repo) Finish(ctx context.Context, id string, channels []ChannelResult) error {
	var sm string
	if err := r.s.DB().QueryRowContext(ctx, `SELECT summary FROM digest_run WHERE id = ?`, id).Scan(&sm); err != nil {
		return fmt.Errorf("cannot read the digest run: %w", err)
	}
	summary := map[string]int{}
	_ = json.Unmarshal([]byte(sm), &summary)
	delete(summary, "pending")
	if channels == nil {
		channels = []ChannelResult{}
	}
	sj, _ := json.Marshal(summary)
	cj, _ := json.Marshal(channels)
	if _, err := r.s.DB().ExecContext(ctx, `UPDATE digest_run SET summary = ?, channels = ? WHERE id = ?`, string(sj), string(cj), id); err != nil {
		return fmt.Errorf("cannot save the digest run: %w", err)
	}
	return nil
}

// Release removes a claim whose digest reached nobody: the window stays where it was.
func (r *Repo) Release(ctx context.Context, id string) error {
	if _, err := r.s.DB().ExecContext(ctx, `DELETE FROM digest_run WHERE id = ?`, id); err != nil {
		return fmt.Errorf("cannot release the digest run: %w", err)
	}
	return nil
}

// InFlight says whether a recent claim is still being sent.
func (r *Repo) InFlight(ctx context.Context, now time.Time) (bool, error) {
	runs, err := r.query(ctx, `ORDER BY created_at DESC, id DESC LIMIT ?`, pendingRoom)
	if err != nil {
		return false, err
	}
	for _, run := range runs {
		if run.Pending() && now.Sub(run.CreatedAt) <= PendingTTL {
			return true, nil
		}
	}
	return false, nil
}
