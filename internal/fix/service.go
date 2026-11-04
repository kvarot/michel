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
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
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
	// re-scan (empty: the policy's db.osv_path).
	DataDir string
	OSVRoot string
	Lang    i18n.Lang
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
	// NotifyHeld is called when a start Michel made alone stopped on a key and
	// waits for a person's answer. Nil sends nothing.
	NotifyHeld func(ctx context.Context, n int)
	Now        func() time.Time
	// Actor is the audit actor of the calls (cli, web, serve).
	Actor string
	// Sessions holds the running agents of this process; nil means a
	// package-wide registry.
	Sessions *Sessions
	// Timeout and MaxTurns bound a session (0: agent.DefaultTimeout,
	// DefaultMaxTurns). WorkerInterval is the pause between two looks at the
	// queue (0: 30 s). PollInterval is how often a running session's state
	// is read (0: 1 s).
	Timeout        time.Duration
	MaxTurns       int
	WorkerInterval time.Duration
	PollInterval   time.Duration

	// Server fixes (StartServer, Apply and AppliedByMe of a server finding).
	//
	// Targets is the server registry; SSH the client's services (every
	// connection goes through the egress gateway and the strict host key
	// check). CheckServer checks a server again (servercheck.Check in
	// michel serve). SiteCheck makes the GET of check_site from the
	// workstation (purpose target.http): nil means "no site check
	// possible", a fix with a check_site is then not proven. Alert tells
	// the user (servercheck.AlertInput kinds rolled_back, rollback_failed,
	// undo_now); nil tells no one. OnStep, when set, is told each step of a
	// run as it is known.
	Targets     *target.Repo
	SSH         sshx.Deps
	CheckServer func(ctx context.Context, targetID string) (servercheck.CheckResult, error)
	SiteCheck   func(ctx context.Context, url string) error
	Alert       func(ctx context.Context, in servercheck.AlertInput)
	OnStep      func(attemptID string, s StepResult)
	// ConfigApplyTimeout and PackageApplyTimeout bound a fix script's run
	// (0: DefaultConfigApplyTimeout, DefaultPackageApplyTimeout). They
	// replace the per-command cap of the collection for the scripts only.
	ConfigApplyTimeout  time.Duration
	PackageApplyTimeout time.Duration
	RecordTimeout       time.Duration
	// SiteCheckTimeout bounds one site check (0: DefaultSiteCheckTimeout),
	// CheckTimeout one recollection (0: DefaultCheckTimeout).
	SiteCheckTimeout time.Duration
	CheckTimeout     time.Duration
	// AllowLocalRemote lets a project attach to a remote on this disk: tests and
	// the trial build only (R28, R33). No variable, option or setting opens it.
	AllowLocalRemote bool
	// BackupKeyWait is how long a process waits for the backup key another
	// one is writing before it takes the key for lost (0: 10 s).
	BackupKeyWait time.Duration
}

// DefaultMaxTurns caps the agentic turns of a session when Deps.MaxTurns
// is 0 (spec § 7.1), on top of the session timeout.
const DefaultMaxTurns = 50

func (d Deps) maxTurns() int {
	if d.MaxTurns > 0 {
		return d.MaxTurns
	}
	return DefaultMaxTurns
}

// timeout is the longest a session runs.
func (d Deps) timeout() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return agent.DefaultTimeout
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
	w.AllowLocalRemote = d.AllowLocalRemote
	if w.DataDir == "" {
		w.DataDir = d.DataDir
	}
	if w.Now == nil {
		w.Now = d.Now
	}
	return w
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
	// gitLocks are the locks of a click on a remote, per project.
	gitLocks map[string]*sync.Mutex
	// gitRuleMu is the lock of the network rules of Git services (lockGitRules).
	gitRuleMu sync.Mutex
	// The level 3 runner's memory (ApplyAutoServer) and the agents' package
	// simulations, per attempt.
	autoErr     map[string]string
	autoTried   map[string]time.Time
	autoAlerted map[string]bool
	sims        map[string]int
}

// running is one attempt's session: the agent, its proxy, its masker and
// the signal of its end.
type running struct {
	sess       Session
	masker     *mask.Masker
	closeProxy func()
	done       chan struct{}
	// mu serializes mask (a Mask and the Save of the table it grew); saved
	// is the size of the table last saved.
	mu    sync.Mutex
	saved int
}

// mask masks text with the session's masker and, when that made a new
// token, saves the table at once: the page's display masker (another
// masker loaded from the store) then numbers its own tokens after it, so
// that one token never stands for two values (final review I8). The
// process that runs the session is the only one that saves its table;
// michel mcp masks with a fresh masker of its own (controller ruling 18).
func (r *running) mask(st secret.Store, attemptID, text string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.masker.Mask(text)
	if n := r.masker.Len(); n != r.saved && st != nil {
		if r.masker.Save(st, attemptID) == nil {
			r.saved = n
		}
	}
	return out
}

// NewSessions returns an empty registry.
func NewSessions() *Sessions {
	return &Sessions{m: map[string]*running{}, lock: map[string]*sync.Mutex{}, proposing: map[string]*sync.Mutex{},
		autoErr: map[string]string{}, autoTried: map[string]time.Time{}, autoAlerted: map[string]bool{}, sims: map[string]int{}}
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
	masked := r.mask(d.Secrets, attemptID, text)
	if _, err := repo.AddMessage(ctx, Message{AttemptID: attemptID, Role: RoleUser, Text: masked}); err != nil {
		return err
	}
	if err := r.sess.Send(masked); err != nil {
		return fmt.Errorf("%w: %v", ErrAgentGone, err)
	}
	return nil
}

// plainCause is the key of the sentence that tells the user, in plain
// words, why an attempt stopped and what to do. stage is the step that
// failed (fix.cause.prepare_failed, change_refused, agent_start_failed,
// apply_failed); a known error of the work copy gets its own sentence. The
// technical detail goes apart (Attempt.CauseDetail).
func plainCause(stage string, err error) string {
	switch {
	case errors.Is(err, ErrNotGit), errors.Is(err, workcopy.ErrNotGitRepo):
		return "fix.cause.not_git"
	case errors.Is(err, workcopy.ErrNoCommit):
		return "fix.cause.no_commit"
	case errors.Is(err, workcopy.ErrCopyTooLarge):
		return "fix.cause.too_large"
	case errors.Is(err, workcopy.ErrUnsafeInstall):
		return "fix.cause.unsafe_install"
	case stage == "fix.cause.change_refused" || changeRefused(err):
		return "fix.cause.change_refused"
	case stage == "fix.cause.agent_start_failed", stage == "fix.cause.apply_failed":
		return stage
	case err != nil && gitFailed.MatchString(err.Error()):
		return "fix.cause.git_failed"
	default:
		return "fix.cause.prepare_failed"
	}
}

// gitFailed matches the error of a failed git command (workcopy's gitErr).
var gitFailed = regexp.MustCompile(`\bgit [a-z-]+ failed\b`)

// changeRefused reports whether err is one of the refusals of the work
// copy that end the attempt with a cause.
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
	// Propose runs in michel mcp, not in the process of the session that
	// owns the saved table: a fresh masker of its own nonce, never saved
	// (controller ruling 18, final review I8), so that its tokens never
	// collide with the session's. The page never unmasks (ruling 38).
	m := mask.New()
	dirs := []string{c.Dir, c.Mirror, d.DataDir}
	tell := func(text string) string { return shown(m, dirs, text) }
	summary := tell(in.Summary)
	notes := tell(in.Notes)
	say := func(text string) {
		_, _ = repo.AddMessage(ctx, Message{AttemptID: attemptID, Role: RoleMichel, Text: tell(text)})
	}
	fail := func(key string, cause error) (Proposal, error) {
		text := i18n.T(lang, plainCause(key, cause))
		say(text)
		if repo.SetState(ctx, attemptID, []State{StatePreparing, StateProposed}, StateFailed, text) == nil {
			_ = repo.SetCauseDetail(ctx, attemptID, auditDetail(d, cause))
		}
		got, _ := repo.GetAttempt(ctx, attemptID)
		// In michel mcp (where Propose runs for a real agent) no session
		// runs in this process, so this Close does nothing: the process of
		// the session (serve or fix prepare) sees the failed state within a
		// poll (PollInterval) and closes its agent. In-process callers
		// (tests) close it here.
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
	// commands are the commands Michel ran, for the proposal's details.
	commands := []RanCommand{}
	if a.Work.UpdateRan && len(plan.Update) > 0 {
		commands = append(commands, RanCommand{What: "update", Argv: strings.Join(plan.Update, " ")})
	}
	installRan := RanCommand{What: "install", Argv: strings.Join(workcopy.InstallCommand(plan.ManifestRel), " ")}
	var cmdErr *workcopy.CmdError
	switch err := workcopy.Install(ctx, wd, run, plan.Ecosystem, plan.ManifestRel); {
	case err == nil:
		installed = true
		commands = append(commands, installRan)
	case errors.Is(err, workcopy.ErrInstallUnsupported):
		lines = append(lines, i18n.T(lang, "fix.msg.install_unsupported"))
	case errors.As(err, &cmdErr):
		commands = append(commands, installRan)
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
			commands = append(commands, RanCommand{What: "tests"})
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
		CommitSHA: sha, DiffRaw: ch.Raw, StepsServer: []string{}, Commands: commands,
		FromVersion: cleanVersion(fi.InstalledVersion), ToVersion: committedVersion(ctx, wd, c, plan, sha),
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

// committedVersion is the version of the planned package the fix commit's
// lockfile resolves (read from the commit in the mirror), else the planned
// target; "" when neither is known.
func committedVersion(ctx context.Context, wd workcopy.Deps, c workcopy.Copy, plan Plan, sha string) string {
	if plan.Package != "" && plan.ManifestRel != "" {
		if lock, ok, err := workcopy.CommitFile(ctx, wd, c, sha, plan.ManifestRel); err == nil && ok {
			if v := cleanVersion(lockVersion(lock, plan.Ecosystem, plan.Package)); v != "" {
				return v
			}
		}
	}
	return cleanVersion(plan.Target)
}

// cleanVersion is v without a leading "v", or "" when it is not a plain
// version string.
func cleanVersion(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if !planVersionRe.MatchString(v) {
		return ""
	}
	return v
}

// lockVersion is the version a composer.lock (Packagist) or a
// package-lock.json (npm) resolves pkg to; "" when absent or unreadable.
func lockVersion(lock []byte, ecosystem, pkg string) string {
	var doc map[string]any
	if json.Unmarshal(lock, &doc) != nil || doc == nil {
		return ""
	}
	if ecosystem == "Packagist" {
		for _, section := range []string{"packages", "packages-dev"} {
			list, _ := doc[section].([]any)
			for _, e := range list {
				if entry, _ := e.(map[string]any); entry != nil && entry["name"] == pkg {
					v, _ := entry["version"].(string)
					return v
				}
			}
		}
		return ""
	}
	packages, _ := doc["packages"].(map[string]any)
	entry, _ := packages["node_modules/"+pkg].(map[string]any)
	v, _ := entry["version"].(string)
	return v
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
	if a.Work.Server != nil {
		return d.approveServer(ctx, a, prop, hash)
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
// attempt fails with Michel's cause), nothing else of the repository is touched. The
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
	if a.Work.Server != nil && a.State == StateRunning {
		return ErrBusy
	}
	if a.State != StateApproved {
		return fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	if a.Work.Server != nil {
		return d.applyServer(ctx, a)
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
	// Only the raw patch, the bytes that reach the branch, is checked:
	// prop.Diff is the masked display copy and holds tokens by design
	// (final review C1). A refusal here is Michel's, not the user's: the
	// attempt fails with its cause (final review C3).
	if mask.HasToken(string(prop.DiffRaw)) {
		cause := i18n.T(lang, "fix.cause.apply_refused")
		if repo.SetState(ctx, a.ID, []State{StateApproved}, StateFailed, cause) == nil {
			_ = repo.SetCauseDetail(ctx, a.ID, auditDetail(d, ErrMaskToken))
		}
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
	// Nothing was proposed to refuse: a held attempt ends as its "no" does.
	if a.State == StateHeld {
		return WithdrawHeld(ctx, d, attemptID)
	}
	if a.State != StatePreparing && a.State != StateProposed && a.State != StateApproved {
		return fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	reason = strings.TrimSpace(scan.SanitizeText(reason))
	if r, ok := d.sessions().get(attemptID); ok {
		reason = r.mask(d.Secrets, attemptID, reason)
	} else {
		// The session (if any) runs elsewhere and owns the saved table: a
		// fresh masker of its own nonce, never saved (final review I8).
		reason = mask.New().Mask(reason)
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

// Pass tells which tools looked at a project in one pass of michel scan. Only
// a tool that looked can settle a fix of what it reports.
type Pass struct {
	// Scanned: the OSV scan read the lockfiles of the project. A scan that
	// found none leaves the findings as they were and proves nothing.
	Scanned bool
	// Sources are the plugin sources that ran and stored their results in
	// this pass. A plugin turned off, not meant to run, or failed is not one.
	Sources map[string]bool
}

// looked tells whether the source of a finding looked in this pass ("" is the
// OSV scan).
func (p Pass) looked(sourceKey string) bool {
	if sourceKey == "" {
		return p.Scanned
	}
	return p.Sources[sourceKey]
}

// Prove settles the applied attempts of the project at the end of a pass,
// once every tool of the pass has run: an attempt is proven_fixed when the
// tool that reported the finding no longer sees it and the fix commit is in
// the current branch of the user's repository (workcopy.IsMerged); gone
// without the merge, or merged but still seen, it is inconclusive (the
// finding keeps the status the tool gave it). When that tool did not look in
// this pass (see Pass), the attempt stays applied, whatever the status says:
// the status is older than this pass. It returns the number proven.
func Prove(ctx context.Context, d Deps, projectID string, pass Pass) (int, error) {
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
	status, sourceOf := map[string]string{}, map[string]string{}
	for _, f := range findings {
		status[f.ID], sourceOf[f.ID] = f.Status, f.SourceKey
	}
	proven := 0
	for _, a := range applied {
		if !pass.looked(sourceOf[a.FindingID]) {
			continue
		}
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
