package fix

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/agent"
	"github.com/kvarot/michel/internal/brief"
	"github.com/kvarot/michel/internal/egress/allowproxy"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/workcopy"
)

// find returns the finding with this exact id, or the one matching a
// unique prefix, and its project.
func (d Deps) find(ctx context.Context, id string) (scan.Finding, project.Project, error) {
	id = strings.TrimSpace(id)
	list, err := scan.NewRepo(d.Store).FindByIDPrefix(ctx, id)
	if err != nil {
		return scan.Finding{}, project.Project{}, err
	}
	var fi scan.Finding
	found := false
	for _, f := range list {
		if f.ID == id {
			fi, found = f, true
		}
	}
	if !found {
		switch len(list) {
		case 1:
			fi, found = list[0], true
		case 0:
			return scan.Finding{}, project.Project{}, fmt.Errorf("%w: no finding has the id %q", ErrNotFound, scan.SanitizeText(id))
		default:
			return scan.Finding{}, project.Project{}, fmt.Errorf("%w: the id prefix %q matches %d findings", ErrNotFound, scan.SanitizeText(id), len(list))
		}
	}
	p, err := project.NewRepo(d.Store).Get(ctx, fi.ProjectID)
	if err != nil {
		return scan.Finding{}, project.Project{}, fmt.Errorf("cannot read the project of finding %s: %w", fi.ID, err)
	}
	return fi, p, nil
}

// busy reports whether the project has an attempt being worked on or
// waiting for the user.
func (d Deps) busy(ctx context.Context, projectID string) (bool, error) {
	return d.busyIn(ctx, projectID, StatePreparing, StateHeld, StateProposed, StateApproved, StateRunning)
}

// serverBusy is busy for a server: an applied attempt (its site check, undo
// and recollection still run) or one whose outcome is unknown counts too,
// so a server never has two fixes at once.
func (d Deps) serverBusy(ctx context.Context, targetID string) (bool, error) {
	return d.busyIn(ctx, targetID, StatePreparing, StateProposed, StateApproved, StateRunning, StateApplied, StateUnknown)
}

func (d Deps) busyIn(ctx context.Context, projectID string, states ...State) (bool, error) {
	for _, st := range states {
		list, err := d.repo().ListAttempts(ctx, projectID, string(st))
		if err != nil {
			return false, err
		}
		if len(list) > 0 {
			return true, nil
		}
	}
	return false, nil
}

func (d Deps) agentStatus(ctx context.Context) agent.Status {
	if d.AgentStatus != nil {
		return d.AgentStatus(ctx)
	}
	ad := d.AgentDeps
	ad.DataDir, ad.Now = d.DataDir, d.Now
	return agent.Detect(ctx, ad)
}

func (d Deps) startAgent(ctx context.Context, ad agent.Deps, s agent.Spec) (Session, error) {
	if d.Agent != nil {
		return d.Agent(ctx, ad, s)
	}
	return agent.Start(ctx, ad, s)
}

// Branch is the branch Apply creates in the user's repository for the
// attempt.
func Branch(attemptID string) string { return "michel/fix-" + strings.ToLower(attemptID) }

// Start begins an attempt on the finding: it refuses a project that is not
// in git (ErrNotGit), a health project (ErrHealthForbidden), a strict_local
// policy (ErrStrictLocal), a project without AI consent
// (ErrConsentRequired), a project with an attempt in progress (ErrBusy) and
// an unusable Claude Code (ErrAgentUnavailable). It then prepares the work
// copy. When the search of the copy finds a possible key, the attempt comes
// back in state held: no agent, no update, nothing leaves the computer until a
// person answers (ContinueHeld, WithdrawHeld). Otherwise it builds the masked
// brief and the skill, binds a token for michel mcp, opens the agent's allow
// proxy, starts the agent with the initial prompt and returns the attempt in
// state preparing. The session goes on in the background: its events become
// messages, and the attempt ends failed when the agent stops without a
// proposal.
func Start(ctx context.Context, d Deps, findingID string, origin string) (Attempt, error) {
	fi, p, err := d.find(ctx, findingID)
	if err != nil {
		return Attempt{}, err
	}
	if origin == "" {
		origin = OriginAgent
	}
	if !filepath.IsAbs(p.Path) || !workcopy.IsGitRepo(p.Path) {
		return Attempt{}, ErrNotGit
	}
	if err := d.policyGates(ctx, p); err != nil {
		return Attempt{}, err
	}
	if busy, err := d.busy(ctx, p.ID); err != nil {
		return Attempt{}, err
	} else if busy {
		return Attempt{}, ErrBusy
	}
	if err := d.agentGates(ctx); err != nil {
		return Attempt{}, err
	}
	repo := d.repo()
	a, err := repo.CreateAttempt(ctx, Attempt{FindingID: fi.ID, ProjectID: p.ID, Origin: origin})
	if err != nil {
		return Attempt{}, err
	}
	c, err := workcopy.Prepare(ctx, d.work(), p, a.ID)
	if err != nil {
		if errors.Is(err, workcopy.ErrNotGitRepo) {
			err = fmt.Errorf("%w: %v", ErrNotGit, err)
		}
		return d.failStart(ctx, a, c, "fix.cause.prepare_failed", err)
	}
	if len(strongHits(c.SecretHits)) > 0 {
		return d.hold(ctx, a, c)
	}
	return d.launch(ctx, a, fi, p, c)
}

// policyGates are the refusals of a project an external agent never works on,
// or not yet: health, strict_local, no consent.
func (d Deps) policyGates(ctx context.Context, p project.Project) error {
	if p.Classification == policy.ClassHealth {
		return ErrHealthForbidden
	}
	if d.Policy.Sovereignty.Mode == policy.ModeStrictLocal {
		return ErrStrictLocal
	}
	ok, err := d.consentOK(ctx, p)
	if err != nil {
		return err
	}
	if !ok {
		return ErrConsentRequired
	}
	return nil
}

// agentGates says the agent can run now.
func (d Deps) agentGates(ctx context.Context) error {
	if st := d.agentStatus(ctx); st.Hint != "" {
		return &AgentUnavailableError{Status: st}
	}
	if d.Gateway == nil {
		return errors.New("the fix service needs the egress gateway")
	}
	return nil
}

// startGates are the gates a held attempt passes again at the person's yes.
func (d Deps) startGates(ctx context.Context, p project.Project) error {
	if err := d.policyGates(ctx, p); err != nil {
		return err
	}
	return d.agentGates(ctx)
}

// failStart ends an attempt that has not reached its agent. c is the copy once
// prepared: until SetWork records it in the attempt, cleanup cannot find it, so
// it is removed here (final review I6).
func (d Deps) failStart(ctx context.Context, a Attempt, c workcopy.Copy, key string, cause error) (Attempt, error) {
	repo := d.repo()
	text := i18n.T(d.lang(), plainCause(key, cause))
	if repo.SetState(ctx, a.ID, []State{StatePreparing}, StateFailed, text) == nil {
		_ = repo.SetCauseDetail(ctx, a.ID, auditDetail(d, cause))
	}
	got, _ := repo.GetAttempt(ctx, a.ID)
	d.cleanup(ctx, got, true)
	if got.Work.Copy.Dir == "" && c.Dir != "" {
		_ = workcopy.Remove(d.work(), c)
	}
	return got, cause
}

// launch takes a prepared attempt to its agent: the brief, Michel's update,
// the token, the allow proxy, the session. Here the code starts to leave the
// computer: no search hit reaches it unanswered (Start, ContinueHeld).
func (d Deps) launch(ctx context.Context, a Attempt, fi scan.Finding, p project.Project, c workcopy.Copy) (Attempt, error) {
	repo := d.repo()
	lang := d.lang()
	wd := d.work()
	origin := a.Origin
	var err error
	fail := func(key string, cause error) (Attempt, error) {
		return d.failStart(ctx, a, c, key, cause)
	}
	if text := weakHitsMessage(lang, weakHits(c.SecretHits)); text != "" {
		_, _ = repo.AddMessage(ctx, Message{AttemptID: a.ID, Role: RoleMichel, Text: text})
	}
	m := mask.New()
	b, err := brief.Build(ctx, brief.Deps{Store: d.Store, DataDir: d.DataDir, Policy: d.Policy, Lang: lang}, fi.ID, m)
	if err != nil {
		return fail("fix.cause.prepare_failed", err)
	}
	// The copy's hard-coded secrets are known to the masker too, so a value
	// the agent quotes is shown as a token.
	if d.Secrets != nil {
		if err := m.Save(d.Secrets, a.ID); err != nil {
			return fail("fix.cause.prepare_failed", err)
		}
	}
	w := Work{Copy: c, Plan: buildPlan(fi, b)}
	// Michel's own update, on the pristine copy, before the agent sees it
	// (controller ruling 36); its result is the first message of Michel.
	dirs := []string{c.Dir, c.Mirror, d.DataDir}
	updateFailed := false
	if len(w.Plan.Update) > 0 {
		proxyURL, closeInstall, err := allowproxy.Listen(d.Gateway, policy.PurposeFixInstall)
		if err != nil {
			return fail("fix.cause.prepare_failed", err)
		}
		wdi := wd
		wdi.ProxyAddr = proxyURL
		err = workcopy.Update(ctx, wdi, c, w.Plan.Ecosystem, w.Plan.ManifestRel, w.Plan.Update)
		closeInstall()
		var cmdErr *workcopy.CmdError
		var text string
		switch {
		case err == nil:
			w.UpdateRan = true
			text = i18n.T(lang, "fix.msg.update_ran", strings.Join(w.Plan.Update, " "))
		case errors.As(err, &cmdErr):
			// No Tree0: nothing of this attempt is applied without a click.
			updateFailed, w.UpdateRan = true, true
			text = i18n.T(lang, "fix.msg.update_failed", shown(m, dirs, cmdErr.Output))
		case changeRefused(err):
			return fail("fix.cause.change_refused", err)
		default:
			text = i18n.T(lang, "fix.msg.update_refused", shown(m, dirs, noPath(err).Error()))
		}
		_, _ = repo.AddMessage(ctx, Message{AttemptID: a.ID, Role: RoleMichel, Text: text})
	}
	// The update's output may have given the masker new tokens.
	if d.Secrets != nil {
		if err := m.Save(d.Secrets, a.ID); err != nil {
			return fail("fix.cause.prepare_failed", err)
		}
	}
	if !updateFailed {
		if w.Tree0, err = workcopy.TreeHash(ctx, wd, c); err != nil {
			return fail("fix.cause.prepare_failed", err)
		}
	}
	if err := repo.SetWork(ctx, a.ID, w); err != nil {
		return fail("fix.cause.prepare_failed", err)
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fail("fix.cause.prepare_failed", err)
	}
	token := hex.EncodeToString(raw[:])
	if d.Secrets == nil {
		return fail("fix.cause.prepare_failed", errors.New("no secret store for the attempt token"))
	}
	if err := SetAttemptToken(d.Secrets, a.ID, token); err != nil {
		return fail("fix.cause.prepare_failed", err)
	}
	proxyURL, closeProxy, err := allowproxy.Listen(d.Gateway, policy.PurposeAgentClaude)
	if err != nil {
		return fail("fix.cause.prepare_failed", err)
	}
	ad := d.AgentDeps
	ad.DataDir, ad.ProxyAddr, ad.Now = d.DataDir, proxyURL, d.Now
	spec := agent.Spec{
		Dir: c.Dir, Prompt: Prompt(b, lang), MCPCommand: d.MCPCommand,
		MCPEnv:  map[string]string{EnvAttempt: a.ID, EnvToken: token},
		Timeout: d.Timeout, MaxTurns: d.maxTurns(),
	}
	// The session outlives the request that started it.
	sess, err := d.startAgent(context.WithoutCancel(ctx), ad, spec)
	if err != nil {
		closeProxy()
		return fail("fix.cause.agent_start_failed", err)
	}
	if id := sess.ID(); id != "" {
		_ = repo.SetRun(ctx, a.ID, c.Dir, id)
	}
	if err := d.record(ctx, "fix.start", fi.ID, "ok", map[string]any{
		"attempt_id": a.ID, "finding_id": fi.ID, "project_id": p.ID, "origin": origin, "classification": string(p.Classification),
		"excluded_files": len(c.Excluded), "secret_hits": len(c.SecretHits), "update_planned": len(w.Plan.Update) > 0,
	}); err != nil {
		_ = sess.Close()
		closeProxy()
		return fail("fix.cause.prepare_failed", err)
	}
	r := &running{sess: sess, masker: m, saved: m.Len(), closeProxy: closeProxy, done: make(chan struct{})}
	d.sessions().add(a.ID, r)
	go d.run(a.ID, r)
	got, err := repo.GetAttempt(ctx, a.ID)
	if err != nil {
		return a, err
	}
	return got, nil
}

// secretHitsMessage tells the user, in plain words, that the agent did not
// start because keys seem written in the copy's files (at most five files
// named) and what to do: move the key out of the code, or exclude the folder
// that holds it (project.Exclude takes folder names, not paths: the folders
// are named). "" when there is none.
func secretHitsMessage(lang i18n.Lang, hits []mask.Hit) string {
	n := len(hits)
	if n == 0 {
		return ""
	}
	files, folders := hitPlaces(hits)
	if len(folders) == 0 {
		return i18n.N(lang, "fix.msg.secret_hits", n, strings.Join(files, ", "))
	}
	return i18n.N(lang, "fix.msg.secret_hits_folder", n, strings.Join(files, ", "), strings.Join(folders, ", "))
}

// weakHitsMessage is the warning about lines that talk about a key without one
// that looks real: they do not stop the agent, and it can read them.
func weakHitsMessage(lang i18n.Lang, hits []mask.Hit) string {
	if len(hits) == 0 {
		return ""
	}
	files, _ := hitPlaces(hits)
	return i18n.N(lang, "fix.msg.weak_hits", len(hits), strings.Join(files, ", "))
}

// hitPlaces names the first files of hits and their folders, masked: a file
// can be named like a key.
func hitPlaces(hits []mask.Hit) (files, folders []string) {
	m := mask.New()
	files, folders = []string{}, []string{}
	for _, h := range hits {
		f := m.Mask(scan.SanitizeText(h.File))
		if !slices.Contains(files, f) && len(files) < 5 {
			files = append(files, f)
			if dir := path.Dir(f); dir != "." {
				if name := path.Base(dir); !slices.Contains(folders, name) {
					folders = append(folders, name)
				}
			}
		}
	}
	return files, folders
}

// causeKey maps an error event of the agent to a catalog key.
func causeKey(text string) string {
	switch text {
	case agent.CauseTimeout:
		return "fix.cause.timeout"
	case agent.CauseCancelled:
		return "fix.cause.cancelled"
	case agent.CauseExit:
		return "fix.cause.exit"
	}
	return ""
}

// run reads the session until it ends, stores its events as messages,
// applies an automatic approval, and settles the attempt when the agent is
// gone: failed without a proposal, else the token is dropped and the
// proposal waits for the user.
func (d Deps) run(id string, r *running) {
	ctx := context.Background()
	repo := d.repo()
	lang := d.lang()
	defer close(r.done)
	defer d.sessions().remove(id)
	defer r.closeProxy()
	ticker := time.NewTicker(d.pollInterval())
	defer ticker.Stop()
	events := r.sess.Events()
	cause := ""
	for events != nil {
		select {
		case ev, ok := <-events:
			if !ok {
				events = nil
				break
			}
			switch ev.Kind {
			case agent.KindText:
				if strings.TrimSpace(ev.Text) != "" {
					// Masked per event: Claude Code -p sends whole content
					// blocks, so a secret is not cut across two events in
					// practice; a secret that is cut is not recognised.
					_, _ = repo.AddMessage(ctx, Message{AttemptID: id, Role: RoleAgent, Text: r.mask(d.Secrets, id, ev.Text)})
				}
			case agent.KindTool:
				_, _ = repo.AddMessage(ctx, Message{AttemptID: id, Role: RoleTool, Text: strings.TrimSpace(ev.Tool + " " + r.mask(d.Secrets, id, ev.Text))})
			case agent.KindError:
				if k := causeKey(ev.Text); k != "" {
					cause = i18n.T(lang, k)
				} else {
					cause = r.mask(d.Secrets, id, ev.Text)
				}
				_, _ = repo.AddMessage(ctx, Message{AttemptID: id, Role: RoleMichel, Text: i18n.T(lang, "fix.msg.agent_error", cause)})
			}
			if sid := r.sess.ID(); sid != "" {
				if a, err := repo.GetAttempt(ctx, id); err == nil && a.SessionID != sid {
					_ = repo.SetRun(ctx, id, a.CloneDir, sid)
				}
			}
		case <-ticker.C:
			// The state may change in another process (michel mcp fails the
			// attempt, a level 3 rule approves it): an ended attempt stops
			// its agent, an automatic approval is applied here.
			a, err := repo.GetAttempt(ctx, id)
			switch {
			case err != nil:
			case finished(a.State):
				_ = r.sess.Close()
			case a.State == StateApproved && a.ApprovedBy == ActorAuto:
				// The agent is stopped first; the end of this loop applies
				// (the copy is removed only once Claude Code has left it).
				_ = r.sess.Close()
			}
		}
	}
	_ = r.sess.Close()
	if counts := r.masker.Counts(); len(counts) > 0 {
		ev := map[string]any{"attempt_id": id}
		for k, v := range counts {
			ev[k] = v
		}
		_ = d.record(ctx, "fix.mask", id, "ok", ev)
	}
	lock := d.sessions().attemptLock(id)
	lock.Lock()
	defer lock.Unlock()
	a, err := repo.GetAttempt(ctx, id)
	if err != nil {
		return
	}
	switch a.State {
	case StatePreparing:
		if cause == "" {
			cause = i18n.T(lang, "fix.cause.agent_ended")
		}
		_ = repo.SetState(ctx, id, []State{StatePreparing}, StateFailed, cause)
		a.State = StateFailed
		d.cleanup(ctx, a, true)
	case StateProposed:
		// The agent is gone: no more proposal can come. The copy stays
		// until the user decides; a server agent's empty folder goes.
		_ = DeleteAttemptToken(d.Secrets, id)
		if a.Work.Server != nil {
			d.cleanup(ctx, a, true)
		}
	case StateApproved:
		// A server fix is never applied from here: an agent's proposal is
		// never approved by a rule.
		if a.ApprovedBy == ActorAuto && a.Work.Server == nil {
			d.applyAuto(ctx, a)
		}
	}
}

// applyAuto applies an automatically approved attempt under its lock
// (held by the caller); a failure ends the attempt as failed with its cause
// instead of being retried.
func (d Deps) applyAuto(ctx context.Context, a Attempt) {
	err := d.applyLocked(ctx, a)
	if err == nil || errors.Is(err, ErrMaskToken) || errors.Is(err, ErrStaleProposal) {
		return
	}
	cause := i18n.T(d.lang(), plainCause("fix.cause.apply_failed", err))
	if d.repo().SetState(ctx, a.ID, []State{StateApproved}, StateFailed, cause) == nil {
		_ = d.repo().SetCauseDetail(ctx, a.ID, auditDetail(d, err))
	}
	d.cleanup(ctx, a, true)
}

// applyApproved applies an attempt approved by a level 3 rule, under the
// attempt's lock.
func (d Deps) applyApproved(ctx context.Context, id string) error {
	lock := d.sessions().attemptLock(id)
	// Never wait: a caller of Apply may hold the lock while it waits for
	// this very session to end.
	if !lock.TryLock() {
		return nil
	}
	defer lock.Unlock()
	a, err := d.repo().GetAttempt(ctx, id)
	if err != nil {
		return err
	}
	// A server fix never runs at a restart: it runs when the user (or a
	// level 3 rule, at the time) asked for it, never later on its own.
	if a.State != StateApproved || a.Work.Server != nil {
		return nil
	}
	d.applyAuto(ctx, a)
	return nil
}

// cleanup removes what an ended attempt leaves: the token, the mask
// table, and the copy and its mirror when removeCopy. The fix flow writes
// no Claude Code skill (controller ruling 42: the agent reads the brief
// through Michel's MCP server; only michel brief --write-skill writes one).
func (d Deps) cleanup(ctx context.Context, a Attempt, removeCopy bool) {
	if d.Secrets != nil {
		_ = DeleteAttemptToken(d.Secrets, a.ID)
	}
	if removeCopy && a.Work.Copy.Dir != "" {
		_ = workcopy.Remove(d.work(), a.Work.Copy)
	}
	// A server agent's empty working folder.
	if removeCopy && a.Work.Server != nil && d.DataDir != "" && filepath.IsAbs(d.DataDir) && idFolder.MatchString(a.ID) && idFolder.MatchString(a.ProjectID) {
		_ = os.RemoveAll(serverAgentDir(d.DataDir, a.ProjectID, a.ID))
		_ = os.Remove(filepath.Join(d.DataDir, "worktrees", a.ProjectID))
	}
}
