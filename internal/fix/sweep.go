package fix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/workcopy"
)

// idFolder is a folder named after a project or attempt id.
var idFolder = regexp.MustCompile(`^[0-9A-Za-z]{1,64}$`)

// finished are the states whose copy has no use any more.
func finished(s State) bool {
	switch s {
	case StateRefused, StateFailed, StateWithdrawn, StateApplied, StateProvenFixed, StateInconclusive, StateSuperseded, StateUnknown:
		return true
	}
	return false
}

// sweepMargin is added to the session timeout before a preparing attempt
// of another process is taken for abandoned.
const sweepMargin = 5 * time.Minute

// liveElsewhere reports whether a preparing attempt may still have its
// agent in another process (michel fix prepare while serve starts): its
// token is still in the secret store and it changed less than a session
// timeout (plus a margin) ago.
func (d Deps) liveElsewhere(a Attempt) bool {
	if d.Secrets == nil {
		return false
	}
	if _, err := d.Secrets.Get(tokenName(a.ID)); err != nil {
		return false
	}
	return d.now().Sub(a.UpdatedAt) < d.timeout()+sweepMargin
}

// Sweep is run when michel serve starts (and by michel fix clean): it
// purges the messages older than MessageRetention, fails the attempts left
// preparing by a stopped process (their agent is gone), applies the
// approved ones, and removes the generated files of the agents
// (<data>/agent/<id>), the temporary files (<data>/fix-tmp/<id>) and the
// copies and mirrors of finished or unknown attempts. A preparing attempt
// whose agent may still run in another process (liveElsewhere) is left as
// it is, files included (final review I5).
func Sweep(ctx context.Context, d Deps) error {
	repo := d.repo()
	lang := d.lang()
	if err := d.purge(ctx); err != nil {
		return err
	}
	if err := d.expireHeld(ctx); err != nil {
		return err
	}
	workcopy.SweepNetRepos(d.work(), d.now())
	preparing, err := repo.ListAttempts(ctx, "", string(StatePreparing))
	if err != nil {
		return err
	}
	live := map[string]bool{}
	for _, a := range preparing {
		if _, here := d.sessions().get(a.ID); here || d.liveElsewhere(a) {
			live[a.ID] = true
			continue
		}
		_ = repo.SetState(ctx, a.ID, []State{StatePreparing}, StateFailed, i18n.T(lang, "fix.cause.restarted"))
		d.cleanup(ctx, a, true)
	}
	for _, sub := range []string{"agent", "fix-tmp"} {
		dir := filepath.Join(d.DataDir, sub)
		entries, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("Michel cannot clean its data folder: %w", noPath(err))
		}
		for _, e := range entries {
			if live[strings.ToUpper(e.Name())] || live[e.Name()] {
				continue
			}
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				return fmt.Errorf("Michel cannot clean its data folder: %w", noPath(err))
			}
		}
		_ = os.Remove(dir) // only when empty
	}
	// A server fix left running by a stopped process.
	if _, err := SweepRunning(ctx, d); err != nil {
		return err
	}
	approved, err := repo.ListAttempts(ctx, "", string(StateApproved))
	if err != nil {
		return err
	}
	for _, a := range approved {
		_ = d.applyApproved(ctx, a.ID)
	}
	all, err := repo.ListAttempts(ctx, "", "")
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, a := range all {
		if !finished(a.State) {
			keep[a.ID] = true
		}
		// A token serves a session of a preparing attempt only.
		if a.State != StatePreparing && d.Secrets != nil {
			_ = DeleteAttemptToken(d.Secrets, a.ID)
		}
	}
	wd := d.work()
	for _, tree := range []string{"worktrees", "fix-mirrors"} {
		projects, _ := os.ReadDir(filepath.Join(d.DataDir, tree))
		for _, pe := range projects {
			if !pe.IsDir() || !idFolder.MatchString(pe.Name()) {
				continue
			}
			entries, _ := os.ReadDir(filepath.Join(d.DataDir, tree, pe.Name()))
			for _, e := range entries {
				id := strings.TrimSuffix(e.Name(), ".git")
				if !idFolder.MatchString(id) || keep[id] {
					continue
				}
				c := workcopy.Copy{Dir: filepath.Join(d.DataDir, "worktrees", pe.Name(), id), Mirror: filepath.Join(d.DataDir, "fix-mirrors", pe.Name(), id+".git")}
				if err := workcopy.Remove(wd, c); err != nil {
					// No copy folder left (a mirror alone): remove it directly,
					// inside the mirrors tree only.
					_ = os.RemoveAll(c.Mirror)
					_ = os.RemoveAll(c.Dir)
				}
			}
			_ = os.Remove(filepath.Join(d.DataDir, tree, pe.Name()))
		}
	}
	return nil
}

// RemoveProjectFiles deletes the copies, mirrors and briefs of a project
// from the data folder (project purge).
func RemoveProjectFiles(dataDir, projectID string) error {
	if !idFolder.MatchString(projectID) || dataDir == "" || !filepath.IsAbs(dataDir) {
		return errors.New("invalid project id or data folder")
	}
	for _, sub := range []string{"worktrees", "fix-mirrors", "briefs"} {
		if err := os.RemoveAll(filepath.Join(dataDir, sub, projectID)); err != nil {
			return fmt.Errorf("Michel cannot delete the project's fix files: %w", noPath(err))
		}
	}
	return nil
}

// purge deletes the messages older than MessageRetention, and the mask
// tables of the finished attempts of that age (their messages are gone).
func (d Deps) purge(ctx context.Context) error {
	repo := d.repo()
	before := d.now().Add(-MessageRetention)
	if _, err := repo.PurgeMessages(ctx, before); err != nil {
		return err
	}
	if _, err := repo.PurgeBackups(ctx, d.now().Add(-BackupRetention)); err != nil {
		return err
	}
	if d.Secrets == nil {
		return nil
	}
	all, err := repo.ListAttempts(ctx, "", "")
	if err != nil {
		return err
	}
	for _, a := range all {
		if finished(a.State) && a.UpdatedAt.Before(before) {
			_ = mask.Delete(d.Secrets, a.ID)
		}
	}
	return nil
}

// PurgeProject forgets what the fix service keeps for a project outside its
// tables: the mask tables and tokens of its attempts in the secret store,
// its copies, mirrors and briefs, and the network rule Michel wrote for its Git
// service if no other attached project uses it. The rows go with
// project.Repo.Purge.
func PurgeProject(ctx context.Context, d Deps, projectID string) error {
	// A rule that cannot be removed does not keep the files: said at the end.
	ruleErr := ReleaseProjectRule(ctx, d, projectID)
	attempts, err := d.repo().ListAttempts(ctx, projectID, "")
	if err != nil {
		return err
	}
	for _, a := range attempts {
		// Close waits for the session's loop to end: Claude Code has left
		// the copy before it is removed.
		d.sessions().Close(a.ID)
		if d.Secrets != nil {
			_ = mask.Delete(d.Secrets, a.ID)
			_ = DeleteAttemptToken(d.Secrets, a.ID)
		}
	}
	// A process that just left a folder can still hold it for an instant
	// (Windows): a few tries.
	for try := 0; try < 5; try++ {
		if err = RemoveProjectFiles(d.DataDir, projectID); err == nil {
			return ruleErr
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.Join(err, ruleErr)
}
