package fix

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/agent"
	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/brief"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/egress/allowproxy"
	"github.com/kvarot/michel/internal/gitrepo"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/workcopy"
)

// Session is a running agent, as the service drives it: *agent.Session, or
// a fake in the tests.
type Session interface {
	Events() <-chan agent.Event
	ID() string
	Send(text string) error
	Close() error
}

// ActorAuto is the actor of an approval made by a level 3 rule.
const ActorAuto = "auto"

// MessageRetention is how long the conversations are kept.
const MessageRetention = 30 * 24 * time.Hour

// MaxAutoPerDay is the number of attempts Michel starts alone per project
// and per day (fix level 2).
const MaxAutoPerDay = 3

// Deps are the collaborators of the fix service. Store, Secrets, Gateway,
// Policy and DataDir are always needed; Agent, AgentDeps, AgentStatus and
// MCPCommand only where attempts are started (michel serve); Notify where
// proposals are recorded (michel serve and michel mcp).
type Deps struct {
	// Repo is the fix tables; nil means NewRepo(Store) with Now.
	Repo    *Repo
	Store   *store.Store
	Audit   *audit.Logger
	Secrets secret.Store
	// Gateway is the egress gateway the allow proxies of the attempt use
	// (purposes agent.claude and fix.install).
	Gateway *egress.Gateway
	// Policy is the policy in force; PolicyPath the file GiveConsent edits;
	// Reload rereads it (the gateway learns the rules). After GiveConsent
	// the caller refreshes its own copy of the policy through Reload.
	Policy     policy.Policy
	PolicyPath string
	Reload     func() (policy.Policy, error)
	// LivePolicy, when set, is the policy in force as the process sees it
	// now (michel serve: the one a consent given on the page reloads). The
	// worker reads it at each pass instead of keeping Policy.
	LivePolicy func() policy.Policy
	// DataDir is Michel's data folder; OSVRoot the offline databases of the
	// re-scan (empty: the policy's db.osv_path); SkillsDir the Claude Code
	// skills folder (empty: ~/.claude/skills).
	DataDir   string
	OSVRoot   string
	SkillsDir string
	Lang      i18n.Lang
	// Agent starts Claude Code for a spec with the agent deps of the
	// attempt (proxy and data folder filled in). Nil means agent.Start.
	Agent func(ctx context.Context, ad agent.Deps, s agent.Spec) (Session, error)
	// AgentDeps are the fixed parts of the agent driver (Binary, Home,
	// Exec for Detect); DataDir, ProxyAddr and Now are set per attempt.
	AgentDeps agent.Deps
	// AgentStatus tells whether Claude Code can be used. Nil means
	// agent.Detect with AgentDeps.
	AgentStatus func(ctx context.Context) agent.Status
	// MCPCommand starts michel mcp (the executable and its arguments); it is
	// the only MCP server of the agent.
	MCPCommand []string
	// Work are the collaborators of the work copy; its ProxyAddr is replaced
	// by the install proxy of each proposal.
	Work workcopy.Deps
	// Rescan reports whether the finding is absent from the copy at root.
	// Nil means scan.ScanDir offline with the project's exclusions.
	Rescan func(ctx context.Context, root string, f scan.Finding, p project.Project) (absent bool, err error)
	// Notify is called when a proposal waits for the user, with the number
	// of proposals waiting over every project. Nil sends nothing.
	Notify func(ctx context.Context, waiting int)
	Now    func() time.Time
	// Actor is the audit actor of the calls (cli, web, serve).
	Actor string
	// Sessions holds the running agents of this process; nil means a
	// package-wide registry.
	Sessions *Sessions
	// Timeout and MaxTurns bound a session (0: agent.DefaultTimeout, no
	// turn cap). WorkerInterval is the pause between two looks at the
	// queue (0: 30 s). PollInterval is how often a running session's state
	// is read (0: 1 s).
	Timeout        time.Duration
	MaxTurns       int
	WorkerInterval time.Duration
	PollInterval   time.Duration
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

func (d Deps) repo() *Repo {
	if d.Repo != nil {
		return d.Repo
	}
	r := NewRepo(d.Store)
	if d.Now != nil {
		r.Now = d.Now
	}
	return r
}

func (d Deps) lang() i18n.Lang {
	if d.Lang.Valid() {
		return d.Lang
	}
	return i18n.EN
}

func (d Deps) actor() string {
	if d.Actor != "" {
		return d.Actor
	}
	return "michel"
}

func (d Deps) work() workcopy.Deps {
	w := d.Work
	if w.DataDir == "" {
		w.DataDir = d.DataDir
	}
	if w.Now == nil {
		w.Now = d.Now
	}
	return w
}

func (d Deps) skillsDir() (string, error) {
	if d.SkillsDir != "" {
		return d.SkillsDir, nil
	}
	return gitrepo.DefaultSkillsDir()
}

var defaultSessions = NewSessions()

func (d Deps) sessions() *Sessions {
	if d.Sessions != nil {
		return d.Sessions
	}
	return defaultSessions
}

func (d Deps) pollInterval() time.Duration {
	if d.PollInterval > 0 {
		return d.PollInterval
	}
	return time.Second
}

func (d Deps) osvRoot() string {
	if d.OSVRoot != "" {
		return d.OSVRoot
	}
	return d.Policy.DB.OSVPath
}

// record writes an audit event; a nil logger records nothing.
func (d Deps) record(ctx context.Context, action, target, result string, ev map[string]any) error {
	if d.Audit == nil {
		return nil
	}
	_, err := d.Audit.Record(ctx, audit.Event{Actor: d.actor(), Action: action, Target: target, Result: result, Evidence: ev})
	return err
}

// Sessions is the registry of the agents running in this process.
type Sessions struct {
	mu        sync.Mutex
	m         map[string]*running
	lock      map[string]*sync.Mutex
	proposing map[string]*sync.Mutex
}

// running is one attempt's session: the agent, its proxy, its display
// masker and the signal of its end.
type running struct {
	sess       Session
	masker     *mask.Masker
	closeProxy func()
	done       chan struct{}
}

// NewSessions returns an empty registry.
func NewSessions() *Sessions {
	return &Sessions{m: map[string]*running{}, lock: map[string]*sync.Mutex{}, proposing: map[string]*sync.Mutex{}}
}

// proposeLock is the mutex held for a whole Propose of one attempt: two
// proposals of the same attempt never run at the same time (one scratch
// worktree, one commit at a time); the second waits for the first.
func (s *Sessions) proposeLock(id string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.proposing[id]
	if !ok {
		m = &sync.Mutex{}
		s.proposing[id] = m
	}
	return m
}

func (s *Sessions) add(id string, r *running) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = r
}

func (s *Sessions) get(id string) (*running, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[id]
	return r, ok
}

func (s *Sessions) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

// attemptLock is the mutex of one attempt: Apply and the end of its session
// never run at the same time.
func (s *Sessions) attemptLock(id string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.lock[id]
	if !ok {
		m = &sync.Mutex{}
		s.lock[id] = m
	}
	return m
}

// Wait waits until the session of the attempt has ended (at once when there
// is none) and reports whether it did within timeout.
func (s *Sessions) Wait(id string, timeout time.Duration) bool {
	r, ok := s.get(id)
	if !ok {
		return true
	}
	select {
	case <-r.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// Close ends the session of the attempt, if this process runs it, and
// waits for its loop to finish.
func (s *Sessions) Close(id string) {
	r, ok := s.get(id)
	if !ok {
		return
	}
	_ = r.sess.Close()
	<-r.done
}

// CloseAll ends every session of the registry (serve stops).
func (s *Sessions) CloseAll() {
	s.mu.Lock()
	ids := make([]string, 0, len(s.m))
	for id := range s.m {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.Close(id)
	}
}

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
	for _, st := range []State{StatePreparing, StateProposed, StateApproved} {
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

// shortID is the lowercase start of an attempt id, as in the branch and the
// skill names.
func shortID(attemptID string) string {
	id := strings.ToLower(attemptID)
	if len(id) > 8 {
		id = id[:8]
	}
	return id
}

// Branch is the branch Apply creates in the user's repository for the
// attempt.
func Branch(attemptID string) string { return "michel/fix-" + shortID(attemptID) }

// Start begins an attempt on the finding: it refuses a project that is not
// in git (ErrNotGit), a health project (ErrHealthForbidden), a strict_local
// policy (ErrStrictLocal), a project without AI consent
// (ErrConsentRequired), a project with an attempt in progress (ErrBusy) and
// an unusable Claude Code (ErrAgentUnavailable). It then prepares the work
// copy, builds the masked brief and the skill, binds a token for michel mcp,
// opens the agent's allow proxy, starts the agent with the initial prompt
// and returns the attempt in state preparing. The session goes on in the
// background: its events become messages, and the attempt ends failed when
// the agent stops without a proposal.
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
	if p.Classification == policy.ClassHealth {
		return Attempt{}, ErrHealthForbidden
	}
	if d.Policy.Sovereignty.Mode == policy.ModeStrictLocal {
		return Attempt{}, ErrStrictLocal
	}
	ok, err := d.consentOK(ctx, p)
	if err != nil {
		return Attempt{}, err
	}
	if !ok {
		return Attempt{}, ErrConsentRequired
	}
	if busy, err := d.busy(ctx, p.ID); err != nil {
		return Attempt{}, err
	} else if busy {
		return Attempt{}, ErrBusy
	}
	if st := d.agentStatus(ctx); st.Hint != "" {
		return Attempt{}, &AgentUnavailableError{Status: st}
	}
	if d.Gateway == nil {
		return Attempt{}, errors.New("the fix service needs the egress gateway")
	}
	repo := d.repo()
	a, err := repo.CreateAttempt(ctx, Attempt{FindingID: fi.ID, ProjectID: p.ID, Origin: origin})
	if err != nil {
		return Attempt{}, err
	}
	lang := d.lang()
	fail := func(key string, cause error) (Attempt, error) {
		text := i18n.T(lang, key, scan.SanitizeText(noPath(cause).Error()))
		_ = repo.SetState(ctx, a.ID, []State{StatePreparing}, StateFailed, text)
		got, _ := repo.GetAttempt(ctx, a.ID)
		d.cleanup(ctx, got, true)
		return got, cause
	}
	wd := d.work()
	c, err := workcopy.Prepare(ctx, wd, p, a.ID)
	if err != nil {
		if errors.Is(err, workcopy.ErrNotGitRepo) {
			err = fmt.Errorf("%w: %v", ErrNotGit, err)
		}
		return fail("fix.cause.prepare_failed", err)
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
			text = i18n.T(lang, "fix.msg.update_ran", strings.Join(w.Plan.Update, " "))
		case errors.As(err, &cmdErr):
			// No Tree0: nothing of this attempt is applied without a click.
			updateFailed = true
			text = i18n.T(lang, "fix.msg.update_failed", shown(m, dirs, cmdErr.Output))
		case changeRefused(err):
			return fail("fix.cause.change_refused", err)
		default:
			text = i18n.T(lang, "fix.msg.update_refused", shown(m, dirs, noPath(err).Error()))
		}
		_, _ = repo.AddMessage(ctx, Message{AttemptID: a.ID, Role: RoleMichel, Text: text})
	}
	if !updateFailed {
		if w.Tree0, err = workcopy.TreeHash(ctx, wd, c); err != nil {
			return fail("fix.cause.prepare_failed", err)
		}
	}
	if err := repo.SetWork(ctx, a.ID, w); err != nil {
		return fail("fix.cause.prepare_failed", err)
	}
	skills, err := d.skillsDir()
	if err != nil {
		return fail("fix.cause.prepare_failed", err)
	}
	if _, err := brief.WriteSkill(skills, b, lang); err != nil {
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
		Timeout: d.Timeout, MaxTurns: d.MaxTurns,
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
	if n := len(c.SecretHits); n > 0 {
		files := []string{}
		for _, h := range c.SecretHits {
			if f := scan.SanitizeText(h.File); !slices.Contains(files, f) && len(files) < 5 {
				files = append(files, f)
			}
		}
		_, _ = repo.AddMessage(ctx, Message{AttemptID: a.ID, Role: RoleMichel, Text: i18n.N(lang, "fix.msg.secret_hits", n, strings.Join(files, ", "))})
	}
	r := &running{sess: sess, masker: m, closeProxy: closeProxy, done: make(chan struct{})}
	d.sessions().add(a.ID, r)
	go d.run(a.ID, r)
	got, err := repo.GetAttempt(ctx, a.ID)
	if err != nil {
		return a, err
	}
	return got, nil
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
					_, _ = repo.AddMessage(ctx, Message{AttemptID: id, Role: RoleAgent, Text: r.masker.Mask(ev.Text)})
				}
			case agent.KindTool:
				_, _ = repo.AddMessage(ctx, Message{AttemptID: id, Role: RoleTool, Text: strings.TrimSpace(ev.Tool + " " + r.masker.Mask(ev.Text))})
			case agent.KindError:
				if k := causeKey(ev.Text); k != "" {
					cause = i18n.T(lang, k)
				} else {
					cause = r.masker.Mask(ev.Text)
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
		// until the user decides.
		_ = DeleteAttemptToken(d.Secrets, id)
	case StateApproved:
		if a.ApprovedBy == ActorAuto {
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
	cause := i18n.T(d.lang(), "fix.cause.apply_failed", auditDetail(d, err))
	_ = d.repo().SetState(ctx, a.ID, []State{StateApproved}, StateFailed, cause)
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
	if a.State != StateApproved {
		return nil
	}
	d.applyAuto(ctx, a)
	return nil
}

// cleanup removes what an ended attempt leaves: the skill, the token, the
// mask table, and the copy and its mirror when removeCopy.
func (d Deps) cleanup(ctx context.Context, a Attempt, removeCopy bool) {
	if skills, err := d.skillsDir(); err == nil {
		_ = brief.RemoveSkill(skills, a.FindingID)
	}
	if d.Secrets != nil {
		_ = DeleteAttemptToken(d.Secrets, a.ID)
	}
	if removeCopy && a.Work.Copy.Dir != "" {
		_ = workcopy.Remove(d.work(), a.Work.Copy)
	}
}

// SendMessage sends text to the agent of the attempt, masked, and keeps it in
// the conversation. ErrAgentGone when no session runs for it.
func SendMessage(ctx context.Context, d Deps, attemptID, text string) error {
	repo := d.repo()
	a, err := repo.GetAttempt(ctx, attemptID)
	if err != nil {
		return err
	}
	r, ok := d.sessions().get(attemptID)
	if !ok {
		return ErrAgentGone
	}
	if a.State != StatePreparing && a.State != StateProposed {
		return fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	text = strings.TrimSpace(scan.SanitizeText(text))
	if text == "" {
		return errors.New("the message is empty")
	}
	masked := r.masker.Mask(text)
	if _, err := repo.AddMessage(ctx, Message{AttemptID: attemptID, Role: RoleUser, Text: masked}); err != nil {
		return err
	}
	if err := r.sess.Send(masked); err != nil {
		return fmt.Errorf("%w: %v", ErrAgentGone, err)
	}
	return nil
}

// refusals of the work copy that end the attempt with a cause.
func changeRefused(err error) bool {
	for _, target := range []error{workcopy.ErrOutsideCopy, workcopy.ErrExcludedPath, workcopy.ErrBinaryChange, workcopy.ErrDiffTooLarge,
		workcopy.ErrCopyTampered, workcopy.ErrNotACopy, workcopy.ErrInvalidCommit} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// noPath drops the file path of a file system error.
func noPath(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// maxShown bounds a command output quoted in a message.
const maxShown = 8000

// shown makes a text safe for a message of Michel: the copy, mirror and
// data folders replaced by <path>, control characters removed, bounded,
// then masked with the attempt's masker (secrets and other absolute paths).
func shown(m *mask.Masker, dirs []string, text string) string {
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		text = strings.ReplaceAll(text, dir, "<path>")
		text = strings.ReplaceAll(text, filepath.ToSlash(dir), "<path>")
	}
	text = strings.TrimSpace(scan.SanitizeText(strings.ToValidUTF8(text, "�")))
	if r := []rune(text); len(r) > maxShown {
		text = string(r[:maxShown]) + "…"
	}
	return m.Mask(text)
}

// maxDetail bounds the detail of an error in the audit log.
const maxDetail = 200

// auditDetail is what the audit keeps of an error: no path, no secret,
// sanitized and bounded.
func auditDetail(d Deps, err error) string {
	if err == nil {
		return ""
	}
	text := noPath(err).Error()
	if d.DataDir != "" {
		text = strings.ReplaceAll(text, d.DataDir, "<data>")
		text = strings.ReplaceAll(text, filepath.ToSlash(d.DataDir), "<data>")
	}
	text = mask.New().Mask(scan.SanitizeText(strings.ToValidUTF8(text, "")))
	if r := []rune(text); len(r) > maxDetail {
		text = string(r[:maxDetail]) + "…"
	}
	return text
}

// Propose records the agent's proposal for the attempt (state preparing or
// proposed; a new proposal supersedes the previous one). Michel freezes one
// snapshot of the copy (a change outside the copy, of an excluded file or
// unreadable ends the attempt: ErrChangeRefused), materialises it in a
// scratch worktree where it installs (with every check of the settings),
// runs the project's tests and re-scans, then commits that very snapshot
// in the mirror; the diff, the files and the hash are the snapshot's. The proposal's
// Hash is the SHA-256 of the raw patch, the commit, the tests status and
// the summary. A change holding a mask token is ErrMaskToken (the attempt
// goes on); an empty change is ErrNoChange. The results come back as a
// message of Michel. The proposal is approved at once when the project's
// level 3 rules allow it and the committed tree is the one Michel's own
// update left (Work.Tree0): the agent changed nothing.
func Propose(ctx context.Context, d Deps, attemptID string, in ProposeInput) (Proposal, error) {
	pl := d.sessions().proposeLock(attemptID)
	pl.Lock()
	defer pl.Unlock()
	repo := d.repo()
	lang := d.lang()
	a, err := repo.GetAttempt(ctx, attemptID)
	if err != nil {
		return Proposal{}, err
	}
	if a.State != StatePreparing && a.State != StateProposed {
		return Proposal{}, fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	fi, p, err := d.find(ctx, a.FindingID)
	if err != nil {
		return Proposal{}, err
	}
	c := a.Work.Copy
	if c.Dir == "" {
		return Proposal{}, errors.New("the attempt has no work copy")
	}
	m := mask.New()
	if d.Secrets != nil {
		if loaded, err := mask.Load(d.Secrets, attemptID); err == nil {
			m = loaded
		}
	}
	dirs := []string{c.Dir, c.Mirror, d.DataDir}
	tell := func(text string) string { return shown(m, dirs, text) }
	summary := tell(in.Summary)
	notes := tell(in.Notes)
	say := func(text string) {
		_, _ = repo.AddMessage(ctx, Message{AttemptID: attemptID, Role: RoleMichel, Text: tell(text)})
	}
	fail := func(key string, cause error) (Proposal, error) {
		text := i18n.T(lang, key, tell(noPath(cause).Error()))
		say(text)
		_ = repo.SetState(ctx, attemptID, []State{StatePreparing, StateProposed}, StateFailed, text)
		got, _ := repo.GetAttempt(ctx, attemptID)
		d.sessions().Close(attemptID)
		d.cleanup(ctx, got, true)
		_ = d.record(ctx, "fix.propose", attemptID, "refused", map[string]any{"attempt_id": attemptID, "finding_id": fi.ID, "reason": key, "detail": auditDetail(d, cause)})
		return Proposal{}, fmt.Errorf("%w: %v", ErrChangeRefused, cause)
	}
	if d.Gateway == nil {
		return Proposal{}, errors.New("the fix service needs the egress gateway")
	}
	if notes != "" {
		_, _ = repo.AddMessage(ctx, Message{AttemptID: attemptID, Role: RoleAgent, Text: i18n.T(lang, "fix.msg.notes", notes)})
	}

	// One frozen snapshot of the agent's copy (controller ruling 37): the
	// install, the tests, the re-scan, the diff, the hash and the commit are
	// all about it; a write to the copy after this instant belongs to the
	// next proposal.
	wd := d.work()
	snap, err := workcopy.Freeze(ctx, wd, c)
	if err != nil {
		if changeRefused(err) {
			return fail("fix.cause.change_refused", err)
		}
		return Proposal{}, err
	}
	ch := snap.Change
	if len(ch.Files) == 0 {
		say(i18n.T(lang, "fix.msg.no_change"))
		return Proposal{}, ErrNoChange
	}
	if mask.HasToken(string(ch.Raw)) {
		say(i18n.T(lang, "fix.msg.mask_token"))
		return Proposal{}, ErrMaskToken
	}
	// Decided now, before anything runs: the agent left Michel's tree as it
	// was.
	unchanged := a.Work.Tree0 != "" && snap.Tree == a.Work.Tree0

	// Michel's own run on the snapshot, in a scratch worktree: never in the
	// agent's copy.
	run, cleanup, err := workcopy.Materialize(ctx, wd, c, snap.Tree)
	if err != nil {
		if changeRefused(err) {
			return fail("fix.cause.change_refused", err)
		}
		return Proposal{}, err
	}
	defer cleanup()
	proxyURL, closeProxy, err := allowproxy.Listen(d.Gateway, policy.PurposeFixInstall)
	if err != nil {
		return Proposal{}, err
	}
	defer closeProxy()
	wd.ProxyAddr = proxyURL
	dirs = append(dirs, run.Dir)
	var lines []string
	plan := a.Work.Plan
	testsStatus, testsOut := workcopy.TestsNotRun, ""
	installed := false
	var cmdErr *workcopy.CmdError
	switch err := workcopy.Install(ctx, wd, run, plan.Ecosystem, plan.ManifestRel); {
	case err == nil:
		installed = true
	case errors.Is(err, workcopy.ErrInstallUnsupported):
		lines = append(lines, i18n.T(lang, "fix.msg.install_unsupported"))
	case errors.As(err, &cmdErr):
		testsStatus, testsOut = workcopy.TestsFailed, cmdErr.Output
		lines = append(lines, i18n.T(lang, "fix.msg.install_failed", tell(cmdErr.Output)))
	case changeRefused(err):
		return fail("fix.cause.change_refused", err)
	default:
		lines = append(lines, i18n.T(lang, "fix.msg.install_refused", tell(noPath(err).Error())))
	}
	if installed {
		argv, err := workcopy.SplitCommand(p.TestCmd)
		switch {
		case err != nil:
			lines = append(lines, i18n.T(lang, "fix.msg.tests_not_run", tell(err.Error())))
		case len(argv) == 0:
			lines = append(lines, i18n.T(lang, "fix.msg.tests_none"))
		default:
			var terr error
			testsStatus, testsOut, terr = workcopy.RunTests(ctx, wd, run, argv)
			switch {
			case terr != nil && changeRefused(terr):
				return fail("fix.cause.change_refused", terr)
			case testsStatus == workcopy.TestsPassed:
				lines = append(lines, i18n.T(lang, "fix.msg.tests_passed"))
			case testsStatus == workcopy.TestsFailed:
				lines = append(lines, i18n.T(lang, "fix.msg.tests_failed", tell(testsOut)))
			default:
				reason := ""
				if terr != nil {
					reason = tell(noPath(terr).Error())
				}
				lines = append(lines, i18n.T(lang, "fix.msg.tests_not_run", reason))
			}
		}
	}
	clean := false
	if absent, err := d.rescan(ctx, run.Dir, fi, p); err != nil {
		lines = append(lines, i18n.T(lang, "fix.msg.rescan_failed", tell(noPath(err).Error())))
	} else if clean = absent; clean {
		lines = append(lines, i18n.T(lang, "fix.msg.rescan_clean", scan.SanitizeText(fi.OSVID)))
	} else {
		lines = append(lines, i18n.T(lang, "fix.msg.rescan_dirty", scan.SanitizeText(fi.OSVID)))
	}
	// The scratch worktree has served; the commit comes from the snapshot.
	cleanup()
	message := "fix(deps): update " + plan.Package
	if plan.Target != "" {
		message += " to " + plan.Target
	}
	if plan.Package == "" {
		message = "fix: Michel"
	}
	sha, _, err := workcopy.CommitSnapshot(ctx, wd, c, snap, message)
	if err != nil {
		if changeRefused(err) || errors.Is(err, workcopy.ErrNothingToCommit) {
			return fail("fix.cause.change_refused", err)
		}
		return Proposal{}, err
	}
	risk := 0
	an, hasAn, err := analyze.NewRepo(d.Store).Get(ctx, fi.ID)
	if err != nil {
		return Proposal{}, err
	}
	if hasAn {
		risk = an.Risk.Score
	}
	prop := Proposal{
		AttemptID: attemptID, Summary: summary, Diff: m.Mask(ch.Display), Files: ch.Files,
		TestsStatus: testsStatus, TestsOutput: tell(testsOut), RescanClean: clean, Risk: risk,
		CommitSHA: sha, DiffRaw: ch.Raw, StepsServer: []string{},
	}
	prop.Hash = proposalHash(ch.Raw, sha, testsStatus, summary)
	prop, err = repo.AddProposal(ctx, prop)
	if err != nil {
		return Proposal{}, err
	}
	if a.State == StatePreparing {
		if err := repo.SetState(ctx, attemptID, []State{StatePreparing}, StateProposed, ""); err != nil {
			return Proposal{}, err
		}
	}
	say(strings.Join(append(lines, i18n.T(lang, "fix.msg.proposed")), "\n"))
	if err := d.record(ctx, "fix.propose", attemptID, "ok", map[string]any{
		"attempt_id": attemptID, "finding_id": fi.ID, "project_id": p.ID, "proposal_id": prop.ID, "hash": prop.Hash,
		"commit": sha, "files": len(ch.Files), "tests": testsStatus, "rescan_clean": clean, "risk": risk,
		"superseded": a.State == StateProposed, "tree_unchanged": unchanged,
	}); err != nil {
		return prop, err
	}
	if d.Notify != nil {
		if waiting, err := repo.ListAttempts(ctx, "", string(StateProposed)); err == nil {
			d.Notify(ctx, len(waiting))
		}
	}
	if p.FixLevel >= 3 && p.AutoFixMinor {
		reason := ""
		switch {
		case !hasAn:
			reason = "no analysis"
		case !unchanged:
			reason = "the snapshot is not the tree Michel's update left"
		case !AutoApplicable(p, prop, an, effectiveRisk(d.Policy, p)):
			reason = "the level 3 rules are not all met"
		default:
			own, err := michelsOwnCommit(ctx, wd, c, plan, sha)
			if err != nil {
				return prop, err
			}
			if !own {
				reason = "the committed manifest or lockfile is not what Michel's update writes"
			}
		}
		if reason == "" {
			auto := d
			auto.Actor = ActorAuto
			if err := Approve(ctx, auto, attemptID, prop.Hash); err != nil {
				return prop, err
			}
		} else {
			_ = d.record(ctx, "fix.auto", attemptID, "skipped", map[string]any{"attempt_id": attemptID, "reason": reason})
		}
	}
	return prop, nil
}

// plainConstraint is the only shape of constraint Michel's own update leaves
// in a manifest: a plain semver range (^1.2.5, ~1.2, 1.2.5, >=1.2). No
// alias, path, URL, git, dev- or "as" form.
var plainConstraint = regexp.MustCompile(`^(?:[\^~]|>=)?v?[0-9]+(?:\.[0-9]+){0,2}$`)

// michelsOwnCommit reports whether the proposal commit sha holds, for the
// planned package, exactly what Michel's update command writes: read from
// the commit in the mirror (never from the working tree), the manifest
// gives the package a plain semver constraint, and the lockfile resolves
// it to plan.Target from an https registry.
func michelsOwnCommit(ctx context.Context, wd workcopy.Deps, c workcopy.Copy, plan Plan, sha string) (bool, error) {
	manifest := workcopy.ManifestOf(plan.ManifestRel)
	if manifest == "" || plan.Package == "" || plan.Target == "" {
		return false, nil
	}
	mb, ok, err := workcopy.CommitFile(ctx, wd, c, sha, manifest)
	if err != nil || !ok {
		return false, err
	}
	lb, ok, err := workcopy.CommitFile(ctx, wd, c, sha, plan.ManifestRel)
	if err != nil || !ok {
		return false, err
	}
	return manifestConstraintOK(mb, plan.Ecosystem, plan.Package) && lockResolvesTarget(lb, plan.Ecosystem, plan.Package, plan.Target), nil
}

// manifestConstraintOK reports whether every constraint of pkg in the
// manifest is a plain semver range (and there is at least one).
func manifestConstraintOK(manifest []byte, ecosystem, pkg string) bool {
	var doc map[string]any
	if json.Unmarshal(manifest, &doc) != nil || doc == nil {
		return false
	}
	sections := []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}
	if ecosystem == "Packagist" {
		sections = []string{"require", "require-dev"}
	}
	found := false
	for _, s := range sections {
		deps, ok := doc[s].(map[string]any)
		if !ok {
			continue
		}
		v, ok := deps[pkg]
		if !ok {
			continue
		}
		found = true
		cons, ok := v.(string)
		if !ok || !plainConstraint.MatchString(cons) || strings.ContainsAny(cons, ":/@") ||
			strings.Contains(cons, "git") || strings.Contains(cons, "file") || strings.Contains(cons, "http") ||
			strings.Contains(cons, "npm:") || strings.Contains(cons, "dev-") || strings.Contains(cons, " as ") {
			return false
		}
	}
	return found
}

// lockResolvesTarget reports whether the lockfile resolves pkg to exactly
// target, downloaded from an https URL.
func lockResolvesTarget(lock []byte, ecosystem, pkg, target string) bool {
	var doc map[string]any
	if json.Unmarshal(lock, &doc) != nil || doc == nil {
		return false
	}
	sameVersion := func(v any) bool {
		s, ok := v.(string)
		return ok && (s == target || s == "v"+target)
	}
	if ecosystem == "Packagist" {
		found := false
		for _, section := range []string{"packages", "packages-dev"} {
			list, _ := doc[section].([]any)
			for _, e := range list {
				entry, _ := e.(map[string]any)
				if entry == nil || entry["name"] != pkg {
					continue
				}
				dist, _ := entry["dist"].(map[string]any)
				url, _ := dist["url"].(string)
				if !sameVersion(entry["version"]) || !strings.HasPrefix(strings.ToLower(url), "https://") {
					return false
				}
				found = true
			}
		}
		return found
	}
	packages, _ := doc["packages"].(map[string]any)
	entry, _ := packages["node_modules/"+pkg].(map[string]any)
	if entry == nil {
		return false
	}
	resolved, _ := entry["resolved"].(string)
	return sameVersion(entry["version"]) && strings.HasPrefix(strings.ToLower(resolved), "https://")
}

// effectiveRisk is the risk rule of the project: the policy's with its
// overrides.
func effectiveRisk(pol policy.Policy, p project.Project) policy.RiskConfig {
	eff, _ := analyze.EffectiveRisk(pol.Risk, p.RiskOverrides)
	return eff
}

// proposalHash is the fingerprint the user approves.
func proposalHash(raw []byte, sha, tests, summary string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00", len(raw))
	h.Write(raw)
	fmt.Fprintf(h, "\x00%s\x00%s\x00%s", sha, tests, summary)
	return hex.EncodeToString(h.Sum(nil))
}

// rescan reports whether the finding is absent from the copy.
func (d Deps) rescan(ctx context.Context, root string, fi scan.Finding, p project.Project) (bool, error) {
	if d.Rescan != nil {
		return d.Rescan(ctx, root, fi, p)
	}
	findings, err := scan.ScanDir(ctx, scan.Deps{Store: d.Store, Gateway: d.Gateway, Now: d.now, DataDir: d.DataDir},
		root, []string{fi.Ecosystem}, scan.Options{OSVRoot: d.osvRoot(), Exclude: scan.EffectiveExclude(p)})
	if err != nil && !errors.Is(err, scan.ErrScanIncomplete) {
		return false, err
	}
	for _, f := range findings {
		if sameFinding(f, fi) {
			return false, nil
		}
	}
	if err != nil {
		// A lockfile could not be read: absence is not proven.
		return false, err
	}
	return true, nil
}

// sameFinding compares two findings by manifest, ecosystem, package and
// advisory (the copy's findings have no project id).
func sameFinding(a, b scan.Finding) bool {
	norm := func(s string) string { return strings.ToLower(path.Clean(strings.ReplaceAll(s, `\`, "/"))) }
	return norm(a.ManifestRelPath) == norm(b.ManifestRelPath) && a.Ecosystem == b.Ecosystem &&
		strings.EqualFold(a.Package, b.Package) && strings.EqualFold(a.OSVID, b.OSVID)
}

var (
	planPkgRe     = regexp.MustCompile(`^[@A-Za-z0-9][@A-Za-z0-9._/~+-]{0,213}$`)
	planVersionRe = regexp.MustCompile(`^[0-9A-Za-z.+_-]{1,64}$`)
	planDirRe     = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._/-]{0,199}$`)
)

// buildPlan is the closed update command of the finding, from validated
// fields only (controller ruling 33): composer update or require with
// --no-scripts --no-plugins, npm install or update with --ignore-scripts;
// none for yarn, pnpm or an unknown target.
func buildPlan(fi scan.Finding, b brief.Brief) Plan {
	rel := strings.ReplaceAll(fi.ManifestRelPath, `\`, "/")
	plan := Plan{Ecosystem: fi.Ecosystem, ManifestRel: rel, Package: fi.Package, Target: b.Fixed, Jump: b.Jump, Update: []string{}}
	if plan.Target == "" || !planPkgRe.MatchString(fi.Package) || strings.Contains(fi.Package, "..") || !planVersionRe.MatchString(plan.Target) {
		return plan
	}
	dir, base := path.Dir(rel), path.Base(rel)
	if dir != "." && (!planDirRe.MatchString(dir) || !filepath.IsLocal(filepath.FromSlash(dir)) || strings.Contains(dir, "..")) {
		return plan
	}
	var argv []string
	switch {
	case fi.Ecosystem == "Packagist" && base == "composer.lock":
		switch {
		case b.Directness == string(analyze.Transitive):
			argv = []string{"composer", "update", fi.Package, "--with-dependencies"}
		case b.Jump == string(analyze.JumpMajor):
			argv = []string{"composer", "require", fi.Package + ":^" + plan.Target, "--update-with-all-dependencies"}
		default:
			argv = []string{"composer", "update", fi.Package + ":^" + plan.Target, "--with-all-dependencies"}
		}
		argv = append(argv, "--no-scripts", "--no-plugins", "--no-interaction")
		if dir != "." {
			argv = append(argv, "--working-dir="+dir)
		}
	case fi.Ecosystem == "npm" && base == "package-lock.json":
		if b.Directness == string(analyze.Transitive) {
			argv = []string{"npm", "update", fi.Package}
		} else {
			argv = []string{"npm", "install", fi.Package + "@" + plan.Target, "--save-exact"}
		}
		argv = append(argv, "--ignore-scripts", "--no-audit", "--no-fund")
		if dir != "." {
			argv = append(argv, "--prefix", dir)
		}
	default:
		return plan
	}
	plan.Update = argv
	return plan
}

// Approve records the user's approval of the current proposal of the
// attempt (state proposed): hash must be the proposal's (ErrStaleProposal
// otherwise, nothing changes). The actor is kept with the attempt.
func Approve(ctx context.Context, d Deps, attemptID, hash string) error {
	repo := d.repo()
	a, err := repo.GetAttempt(ctx, attemptID)
	if err != nil {
		return err
	}
	if a.State != StateProposed {
		return fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	prop, ok, err := repo.CurrentProposal(ctx, attemptID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNoProposal
	}
	if hash == "" || prop.Hash != hash {
		_ = d.record(ctx, "fix.approve", attemptID, "refused", map[string]any{"attempt_id": attemptID, "reason": "stale proposal", "current_hash": prop.Hash})
		return ErrStaleProposal
	}
	if err := repo.Approve(ctx, attemptID, d.actor(), prop.ID, prop.Hash); err != nil {
		return err
	}
	return d.record(ctx, "fix.approve", attemptID, "ok", map[string]any{
		"attempt_id": attemptID, "finding_id": a.FindingID, "project_id": a.ProjectID, "proposal_id": prop.ID, "hash": prop.Hash, "author": d.actor(),
	})
}

// Apply creates the branch michel/fix-<id> in the user's repository from the
// approved proposal's commit (state approved): the agent's session is
// closed first, a patch holding a mask token is refused (ErrMaskToken, the
// attempt is refused), nothing else of the repository is touched. The
// attempt becomes applied; the copy, the mirror, the skill and the token
// go.
func Apply(ctx context.Context, d Deps, attemptID string) error {
	d.sessions().Close(attemptID)
	lock := d.sessions().attemptLock(attemptID)
	lock.Lock()
	defer lock.Unlock()
	a, err := d.repo().GetAttempt(ctx, attemptID)
	if err != nil {
		return err
	}
	if a.State != StateApproved {
		return fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	return d.applyLocked(ctx, a)
}

func (d Deps) applyLocked(ctx context.Context, a Attempt) error {
	repo := d.repo()
	lang := d.lang()
	actor := d
	if a.ApprovedBy != "" {
		actor.Actor = a.ApprovedBy
	}
	prop, ok, err := repo.CurrentProposal(ctx, a.ID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNoProposal
	}
	// What was approved is what is applied: the current proposal must be
	// the one the approval named.
	if prop.ID != a.ApprovedProposal || prop.Hash != a.ApprovedHash || prop.Hash == "" {
		_ = actor.record(ctx, "fix.apply", a.ID, "refused", map[string]any{"attempt_id": a.ID, "reason": "proposal changed after approval", "approved_hash": a.ApprovedHash, "current_hash": prop.Hash})
		return ErrStaleProposal
	}
	branch := Branch(a.ID)
	if mask.HasToken(string(prop.DiffRaw)) || mask.HasToken(prop.Diff) {
		cause := i18n.T(lang, "fix.cause.mask_token")
		_ = repo.SetState(ctx, a.ID, []State{StateApproved}, StateRefused, cause)
		_, _ = repo.AddMessage(ctx, Message{AttemptID: a.ID, Role: RoleMichel, Text: i18n.T(lang, "fix.msg.mask_token")})
		_ = actor.record(ctx, "fix.apply", a.ID, "refused", map[string]any{"attempt_id": a.ID, "hash": prop.Hash, "reason": "mask token in the change"})
		d.cleanup(ctx, a, true)
		return ErrMaskToken
	}
	p, err := project.NewRepo(d.Store).Get(ctx, a.ProjectID)
	if err != nil {
		return err
	}
	if err := workcopy.Apply(ctx, d.work(), p, a.Work.Copy, prop.CommitSHA, branch); err != nil {
		_ = actor.record(ctx, "fix.apply", a.ID, "error", map[string]any{"attempt_id": a.ID, "hash": prop.Hash, "error": "apply_failed", "detail": auditDetail(d, err)})
		return err
	}
	if err := repo.SetState(ctx, a.ID, []State{StateApproved}, StateApplied, ""); err != nil {
		return err
	}
	_, _ = repo.AddMessage(ctx, Message{AttemptID: a.ID, Role: RoleMichel, Text: i18n.T(lang, "fix.msg.applied", branch)})
	if err := actor.record(ctx, "fix.apply", a.ID, "ok", map[string]any{
		"attempt_id": a.ID, "finding_id": a.FindingID, "project_id": a.ProjectID, "proposal_id": prop.ID, "hash": prop.Hash,
		"commit": prop.CommitSHA, "branch": branch, "files": len(prop.Files), "tests": prop.TestsStatus, "author": actor.actor(),
	}); err != nil {
		return err
	}
	d.cleanup(ctx, a, true)
	return nil
}

// Refuse ends the attempt (preparing, proposed or approved) on the user's
// decision, with an optional reason kept as its cause. The finding goes
// back to the decision circuit untouched: no decision is created. The
// session is closed, the copy, the skill and the token removed.
func Refuse(ctx context.Context, d Deps, attemptID, reason string) error {
	repo := d.repo()
	a, err := repo.GetAttempt(ctx, attemptID)
	if err != nil {
		return err
	}
	if a.State != StatePreparing && a.State != StateProposed && a.State != StateApproved {
		return fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	reason = strings.TrimSpace(scan.SanitizeText(reason))
	if r, ok := d.sessions().get(attemptID); ok {
		reason = r.masker.Mask(reason)
	} else if d.Secrets != nil {
		if m, err := mask.Load(d.Secrets, attemptID); err == nil {
			reason = m.Mask(reason)
		}
	}
	cause := reason
	if cause == "" {
		cause = i18n.T(d.lang(), "fix.cause.refused")
	}
	// The state first, under the attempt's lock: the end of a session that
	// is still running then finds the attempt refused and leaves it so
	// (closing the session first would let it fail the attempt). The lock
	// is released before the session is closed, since the session's end
	// takes it.
	lock := d.sessions().attemptLock(attemptID)
	lock.Lock()
	err = repo.SetState(ctx, attemptID, []State{StatePreparing, StateProposed, StateApproved}, StateRefused, cause)
	lock.Unlock()
	if err != nil {
		return err
	}
	d.sessions().Close(attemptID)
	d.cleanup(ctx, a, true)
	return d.record(ctx, "fix.refuse", attemptID, "ok", map[string]any{
		"attempt_id": attemptID, "finding_id": a.FindingID, "project_id": a.ProjectID, "has_reason": reason != "", "author": d.actor(),
	})
}

// Prove settles the applied attempts of the project after a scan: an
// attempt is proven_fixed when the scan no longer sees the finding and the
// fix commit is in the current branch of the user's repository
// (workcopy.IsMerged); gone without the merge, or merged but still seen, it
// is inconclusive (the finding keeps the status the scan gave it). It
// returns the number proven.
func Prove(ctx context.Context, d Deps, projectID string) (int, error) {
	repo := d.repo()
	lang := d.lang()
	applied, err := repo.ListAttempts(ctx, projectID, string(StateApplied))
	if err != nil {
		return 0, err
	}
	if len(applied) == 0 {
		return 0, nil
	}
	p, err := project.NewRepo(d.Store).Get(ctx, projectID)
	if err != nil {
		return 0, err
	}
	findings, err := scan.NewRepo(d.Store).ListFindings(ctx, projectID, "all")
	if err != nil {
		return 0, err
	}
	status := map[string]string{}
	for _, f := range findings {
		status[f.ID] = f.Status
	}
	proven := 0
	for _, a := range applied {
		prop, ok, err := repo.CurrentProposal(ctx, a.ID)
		if err != nil {
			return proven, err
		}
		if !ok {
			continue
		}
		merged := false
		if workcopy.IsGitRepo(p.Path) {
			if merged, err = workcopy.IsMerged(ctx, d.work(), p, prop.CommitSHA); err != nil {
				return proven, err
			}
		}
		gone := status[a.FindingID] == scan.StatusGone
		switch {
		case gone && merged:
			if err := repo.SetState(ctx, a.ID, []State{StateApplied}, StateProvenFixed, ""); err != nil {
				return proven, err
			}
			proven++
			d.cleanup(ctx, a, false)
			if err := d.record(ctx, "fix.proven", a.ID, "ok", map[string]any{
				"attempt_id": a.ID, "finding_id": a.FindingID, "project_id": a.ProjectID, "hash": prop.Hash, "commit": prop.CommitSHA,
			}); err != nil {
				return proven, err
			}
		case gone && !merged:
			_ = repo.SetState(ctx, a.ID, []State{StateApplied}, StateInconclusive, i18n.T(lang, "fix.cause.gone_not_merged"))
			d.cleanup(ctx, a, false)
		case !gone && merged:
			_ = repo.SetState(ctx, a.ID, []State{StateApplied}, StateInconclusive, i18n.T(lang, "fix.cause.merged_still_seen"))
		}
	}
	return proven, nil
}

// idFolder is a folder named after a project or attempt id.
var idFolder = regexp.MustCompile(`^[0-9A-Za-z]{1,64}$`)

// finished are the states whose copy has no use any more.
func finished(s State) bool {
	switch s {
	case StateRefused, StateFailed, StateApplied, StateProvenFixed, StateInconclusive, StateSuperseded:
		return true
	}
	return false
}

// Sweep is run when michel serve starts: it purges the messages older than
// MessageRetention, removes the generated files of the agents
// (<data>/agent) and the temporary files (<data>/fix-tmp), fails the
// attempts left preparing by a previous serve (their agent is gone), applies
// the approved ones, and removes the copies and mirrors of finished or
// unknown attempts.
func Sweep(ctx context.Context, d Deps) error {
	repo := d.repo()
	lang := d.lang()
	if err := d.purge(ctx); err != nil {
		return err
	}
	for _, sub := range []string{"agent", "fix-tmp"} {
		if err := os.RemoveAll(filepath.Join(d.DataDir, sub)); err != nil {
			return fmt.Errorf("Michel cannot clean its data folder: %w", noPath(err))
		}
	}
	preparing, err := repo.ListAttempts(ctx, "", string(StatePreparing))
	if err != nil {
		return err
	}
	for _, a := range preparing {
		if _, live := d.sessions().get(a.ID); live {
			continue
		}
		_ = repo.SetState(ctx, a.ID, []State{StatePreparing}, StateFailed, i18n.T(lang, "fix.cause.restarted"))
		d.cleanup(ctx, a, true)
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
	keep, liveFinding := map[string]bool{}, map[string]bool{}
	for _, a := range all {
		if !finished(a.State) {
			keep[a.ID] = true
		}
		if a.State == StatePreparing || a.State == StateProposed || a.State == StateApproved {
			liveFinding[a.FindingID] = true
		}
		// A token serves a session of a preparing attempt only.
		if a.State != StatePreparing && d.Secrets != nil {
			_ = DeleteAttemptToken(d.Secrets, a.ID)
		}
	}
	// Skills Michel wrote for findings without a live attempt.
	if skills, err := d.skillsDir(); err == nil {
		entries, _ := os.ReadDir(skills)
		for _, e := range entries {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), "michel-fix-") {
				continue
			}
			key, ok := gitrepo.OwnerKey(filepath.Join(skills, e.Name()))
			fid, isFix := strings.CutPrefix(key, "fix:")
			if ok && isFix && !liveFinding[fid] {
				_ = brief.RemoveSkill(skills, fid)
			}
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
// its copies, mirrors and briefs. The rows go with project.Repo.Purge.
func PurgeProject(ctx context.Context, d Deps, projectID string) error {
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
		if skills, err := d.skillsDir(); err == nil {
			_ = brief.RemoveSkill(skills, a.FindingID)
		}
	}
	// A process that just left a folder can still hold it for an instant
	// (Windows): a few tries.
	for try := 0; try < 5; try++ {
		if err = RemoveProjectFiles(d.DataDir, projectID); err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return err
}
