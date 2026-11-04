package fix

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/egress/allowproxy"
	"github.com/kvarot/michel/internal/gitremote"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/workcopy"
)

// The answers to the question "is this project on a Git service?". No row means
// never answered, and only yes attaches. A suggestion is never an answer.
const (
	GitYes     = "yes"
	GitNo      = "no"
	GitUnknown = "unknown"
)

// Why a project can or cannot be attached, as GitState.Reason says it.
const (
	gitReasonKnown       = "known"
	gitReasonOther       = "other"
	gitReasonNone        = "none"
	gitReasonSeveral     = "several"
	gitReasonUnsupported = "unsupported"
)

// The audit actions of a click (R29).
const (
	auditGitAnswer = "project.git.answer"
	auditGitPush   = "project.git.push"
	auditGitUpdate = "project.git.update"
)

// schemeHTTPS is the scheme of a gitremote.Remote that goes through the proxy.
const schemeHTTPS = "https"

// GitRepoUnreadable is GitState.Repo when Michel could not read the folder, for
// instance a partial clone: an answer can be saved even so.
const GitRepoUnreadable = "unreadable"

// GitState is what the page shows of a project's remote: read without network and
// without writing, each time.
type GitState struct {
	Repo          string // workcopy.RepoNone, RepoEmpty, RepoOK, or GitRepoUnreadable
	Answer        string // "", or the stored answer
	Attached      bool   // yes, for the address the project holds now
	Changed       bool   // yes, for an address the project no longer holds
	Suggested     string // never stored: what the page offers first
	Reason        string
	Provider      string
	Display       string
	Host          string
	RemoteID      string // what a yes must name
	HadCredential bool   // the address holds a secret, neither kept nor used
	CanAttach     bool
	Update        *UpdateState // set for an attached project
}

// UpdateState says whether the update button would work now. Code and Why are the
// refusal, in the same words as a click would get.
type UpdateState struct {
	Ready            bool
	Current, Default string
	Code, Why        string
}

// PushOutcome is the end of a click on the send button.
type PushOutcome struct {
	Outcome  string // workcopy.PushPushed or workcopy.PushAlready
	MergeURL string // empty for a site Michel builds no link for
	Provider string
	Branch   string
	At       time.Time // when the branch first reached the remote
}

// PushState is what the page shows of a fix's branch and the attached service.
type PushState struct {
	Provider, Display string
	Branch            string
	MergeURL          string // set once sent, and only for a site Michel builds a link for
	PushedAt          time.Time
	Pushed, CanPush   bool
}

// gitLock is the lock of a project for a click and a check started from the page:
// a click in the process of michel serve, the only one with these routes (R29, R35).
func (s *Sessions) gitLock(projectID string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gitLocks == nil {
		s.gitLocks = map[string]*sync.Mutex{}
	}
	l := s.gitLocks[projectID]
	if l == nil {
		l = &sync.Mutex{}
		s.gitLocks[projectID] = l
	}
	return l
}

// lockGitRules takes the lock of the network rules of Git services, which several
// projects can share: from who uses a rule to the row that says so, one project at
// a time. It stops only the answers of michel serve and the same process: a command
// line in another process is not held by it.
func (s *Sessions) lockGitRules() (unlock func()) {
	s.gitRuleMu.Lock()
	return s.gitRuleMu.Unlock
}

// GitBusy says whether a click or a check holds the project now.
func GitBusy(d Deps, projectID string) bool {
	l := d.sessions().gitLock(projectID)
	if l.TryLock() {
		l.Unlock()
		return false
	}
	return true
}

// TryGitLock takes the project's lock for a check, which must not read a folder
// during a write (R35) nor let one start. ok is false when it is held.
func TryGitLock(d Deps, projectID string) (unlock func(), ok bool) {
	l := d.sessions().gitLock(projectID)
	if !l.TryLock() {
		return nil, false
	}
	return l.Unlock, true
}

// remoteRead is the project's remote, read again from its own configuration.
type remoteRead struct {
	name   string
	remote gitremote.Remote
	reason string
}

func (r remoteRead) usable() bool { return r.reason == gitReasonKnown || r.reason == gitReasonOther }

// host is what the page and the audit name, a local remote having no host.
func (r remoteRead) host() string {
	if r.remote.Provider == gitremote.Local {
		return r.remote.Display()
	}
	return r.remote.Host
}

// readRemote reads the address, without network. The raw value goes to Parse and
// nowhere else: it may hold a secret.
func (d Deps) readRemote(ctx context.Context, p project.Project) (remoteRead, error) {
	name, raw, several, err := workcopy.ReadRemotes(ctx, d.work(), p)
	switch {
	case err != nil:
		return remoteRead{}, err
	case several:
		return remoteRead{reason: gitReasonSeveral}, nil
	case raw == "":
		return remoteRead{reason: gitReasonNone}, nil
	}
	remote, err := gitremote.Parse(raw, d.AllowLocalRemote)
	if err != nil {
		return remoteRead{reason: gitReasonUnsupported}, nil
	}
	reason := gitReasonKnown
	if remote.Provider == gitremote.Other || remote.Provider == gitremote.Local {
		reason = gitReasonOther
	}
	return remoteRead{name: name, remote: remote, reason: reason}, nil
}

// suggestion is the answer the page offers first for a reason.
func suggestion(reason string) string {
	switch reason {
	case gitReasonKnown, gitReasonOther:
		return GitYes
	case gitReasonNone:
		return GitNo
	}
	return GitUnknown
}

// ProjectGit reads how a project stands with its remote. It starts no click: no
// network and no write, and it runs on each look at the page. When the folder
// cannot be read, the state beside the error still holds the stored answer.
func ProjectGit(ctx context.Context, d Deps, p project.Project) (GitState, error) {
	st := GitState{Repo: GitRepoUnreadable, Reason: gitReasonNone, Suggested: GitNo}
	row, answered, err := d.repo().GitAnswer(ctx, p.ID)
	if err != nil {
		return st, err
	}
	if answered {
		st.Answer = row.Answer
	}
	repoState, err := workcopy.RepoState(ctx, d.work(), p)
	if err != nil {
		return st, err
	}
	st.Repo = repoState
	if repoState == workcopy.RepoNone {
		return st, nil
	}
	read, err := d.readRemote(ctx, p)
	if err != nil {
		st.Repo = GitRepoUnreadable
		return st, err
	}
	st.Reason, st.Suggested = read.reason, suggestion(read.reason)
	if read.usable() {
		st.Provider, st.Display, st.Host = string(read.remote.Provider), read.remote.Display(), read.host()
		st.RemoteID, st.HadCredential = read.remote.ID(), read.remote.HadCredential
		st.CanAttach = repoState == workcopy.RepoOK
	}
	if st.Answer != GitYes {
		return st, nil
	}
	st.Attached = read.usable() && read.remote.Address() == row.URL
	st.Changed = !st.Attached
	if st.Attached && repoState == workcopy.RepoOK {
		st.Update = d.updateState(ctx, p, read)
	}
	return st, nil
}

// updateState reads, without network, whether the update would run now. During a
// click it does not read a folder being written.
func (d Deps) updateState(ctx context.Context, p project.Project, read remoteRead) *UpdateState {
	refused := func(err error) *UpdateState {
		u := &UpdateState{Code: ErrorKey(err), Why: Explain(d.lang(), err)}
		var gf *workcopy.GitFailure
		if errors.As(err, &gf) {
			u.Current, u.Default = gf.Current, gf.Default
		}
		return u
	}
	if GitBusy(d, p.ID) {
		return refused(ErrGitBusy)
	}
	if d.ruleMissing(read) {
		return refused(ErrGitNoRule)
	}
	plan, err := workcopy.UpdateCheck(ctx, d.work(), p, read.name)
	if err != nil {
		return refused(err)
	}
	return &UpdateState{Ready: true, Current: plan.Current, Default: plan.Default}
}

// ruleMissing says the network rule of the remote's host is gone: a click would be
// refused. A local remote has none.
func (d Deps) ruleMissing(read remoteRead) bool {
	if read.remote.Provider == gitremote.Local || d.Gateway == nil {
		return false
	}
	_, ok := d.Gateway.MatchRule(read.remote.Host, policy.PurposeProjectGit)
	return !ok
}

// AttemptPush says how a fix's branch stands with the service its project is
// attached to, without network: nil for a server's fix and for a project that is
// not attached now, whatever stops it (no answer, another address, a folder Michel
// cannot read; ProjectGit says why). CanPush says a click would start, and stays
// true once sent: a second click answers "already" (R29). The link appears once the
// branch left, since it leads nowhere before.
func AttemptPush(ctx context.Context, d Deps, a Attempt, p project.Project) (*PushState, error) {
	if a.Work.Server != nil {
		return nil, nil
	}
	// Only these states can hold a branch (as stateView): no git for the others.
	switch a.State {
	case StateApplied, StateProvenFixed, StateInconclusive:
	default:
		return nil, nil
	}
	row, answered, err := d.repo().GitAnswer(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	if !answered || row.Answer != GitYes {
		return nil, nil
	}
	read, err := d.attached(ctx, p)
	if err != nil {
		return nil, nil //nolint:nilerr // not attached now: the view has nothing to offer
	}
	prop, hasProposal, err := d.repo().CurrentProposal(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	sent, pushed, err := d.repo().Push(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	branch := Branch(a.ID)
	st := &PushState{Provider: string(read.remote.Provider), Display: read.remote.Display(), Branch: branch, Pushed: pushed,
		CanPush: a.State == StateApplied && hasProposal && prop.CommitSHA != "" && !d.ruleMissing(read) && !GitBusy(d, p.ID)}
	if pushed {
		st.MergeURL, st.PushedAt = gitremote.MergeURL(read.remote, branch), sent.PushedAt
	}
	return st, nil
}

// AnswerGit records the person's answer, on their click. A yes is for the address
// the page showed (remoteID) and writes the network rule of its host; any other
// answer takes back what a yes gave, and needs nothing of the folder: it must stay
// possible whatever became of it, and once saved it is answered as saved, even if
// the folder cannot be read (Repo says GitRepoUnreadable).
func AnswerGit(ctx context.Context, d Deps, p project.Project, answer, remoteID string) (GitState, error) {
	if answer != GitYes && answer != GitNo && answer != GitUnknown {
		return GitState{}, fmt.Errorf("the answer %q is not one Michel knows", answer)
	}
	unlock, ok := TryGitLock(d, p.ID)
	if !ok {
		d.auditGitRefusal(ctx, auditGitAnswer, p.Name, map[string]any{"project_id": p.ID, "host": "", "provider": ""}, ErrGitBusy)
		return GitState{}, ErrGitBusy
	}
	err := d.storeGitAnswer(ctx, &d, p, answer, remoteID)
	unlock() // the state below is read as the page reads it
	if err != nil {
		return GitState{}, err
	}
	st, err := ProjectGit(ctx, d, p)
	if err != nil && answer != GitYes {
		return GitState{Repo: GitRepoUnreadable, Answer: answer, Reason: gitReasonNone, Suggested: answer}, nil
	}
	return st, err
}

// storeGitAnswer does the writing of AnswerGit, under the project's lock and the
// lock of the rules. A reload reaches the policy in live, the copy the caller goes
// on with.
//
// A yes goes as GiveConsentWith: the rule, the reload, the row, the audit, and a
// failure takes back a rule it wrote, which nobody would own. Any other answer
// stops the clicks first, since they read only the row: the row, then the rule,
// then the final row. If the rule cannot go, the row still holds it, so that saying
// it again finishes the work.
func (d Deps) storeGitAnswer(ctx context.Context, live *Deps, p project.Project, answer, remoteID string) error {
	unlockRules := d.sessions().lockGitRules()
	defer unlockRules()
	ev := map[string]any{"project_id": p.ID, "host": "", "provider": ""}
	failed := func(err error) error {
		d.auditGitRefusal(ctx, auditGitAnswer, p.Name, ev, err)
		return err
	}
	row := GitAnswerRow{ProjectID: p.ID, Answer: answer}
	prev, _, err := d.repo().GitAnswer(ctx, p.ID)
	if err != nil {
		return failed(err)
	}
	ev["host"], ev["provider"] = prev.Host, prev.Provider
	wrote := false
	switch {
	case answer == GitYes:
		read, err := d.readYes(ctx, p, remoteID)
		if read.usable() {
			ev["host"], ev["provider"] = read.host(), string(read.remote.Provider)
		}
		if err != nil {
			return failed(err)
		}
		row.RemoteName, row.URL, row.Host, row.Provider = read.name, read.remote.Address(), read.remote.Host, string(read.remote.Provider)
		if read.remote.Provider != gitremote.Local {
			wrote, err = live.addGitRule(read.remote.Host)
			if err != nil {
				return failed(err)
			}
			row.RuleWritten = wrote || (prev.RuleWritten && prev.Host == read.remote.Host)
		}
	case prev.RuleWritten:
		stop := GitAnswerRow{ProjectID: p.ID, Answer: answer, Host: prev.Host, Provider: prev.Provider, RuleWritten: true}
		if err := d.repo().SetGitAnswer(ctx, stop); err != nil {
			return failed(err)
		}
	}
	if prev.RuleWritten && prev.Host != row.Host {
		err = live.releaseGitRule(ctx, p.ID, prev.Host)
	}
	if err == nil {
		err = d.repo().SetGitAnswer(ctx, row)
	}
	if err != nil {
		if wrote {
			err = errors.Join(err, live.dropGitRule(row.Host))
		}
		return failed(err)
	}
	ev["outcome"], ev["rule_written"], ev["author"] = answer, row.RuleWritten, d.actor()
	if err := d.recordDone(ctx, auditGitAnswer, p.Name, "ok", ev); err != nil {
		return fmt.Errorf("the answer is recorded, but the audit log could not record it: %w", err)
	}
	return nil
}

// readYes reads what a yes is about, and refuses when it is not what was shown.
func (d Deps) readYes(ctx context.Context, p project.Project, remoteID string) (remoteRead, error) {
	repoState, err := workcopy.RepoState(ctx, d.work(), p)
	switch {
	case err != nil:
		return remoteRead{}, err
	case repoState == workcopy.RepoNone:
		return remoteRead{}, ErrGitNoRepo
	case repoState == workcopy.RepoEmpty:
		return remoteRead{}, ErrGitEmptyRepo
	}
	read, err := d.readRemote(ctx, p)
	switch {
	case err != nil:
		return remoteRead{}, err
	case !read.usable():
		return read, ErrGitNoRemote
	case read.remote.ID() != remoteID:
		return read, ErrGitRemoteChanged
	}
	return read, nil
}

// addGitRule writes the rule of host and reloads. It says whether Michel wrote it.
// A policy that does not load any more is put back as it was.
func (d *Deps) addGitRule(host string) (bool, error) {
	if d.PolicyPath == "" {
		return false, errors.New("cannot write the answer: the policy file path is unknown")
	}
	rule := policy.AllowRule{Host: host, Purpose: policy.PurposeProjectGit}
	added, err := policy.AddAllowRules(d.PolicyPath, rule)
	if err != nil {
		return false, err
	}
	if err := d.reload(); err != nil {
		if added > 0 {
			_, _ = policy.RemoveAllowRules(d.PolicyPath, rule)
		}
		return false, fmt.Errorf("the policy cannot be reloaded, so no rule was kept: %w", err)
	}
	return added > 0, nil
}

// releaseGitRule gives back the rule of host that projectID held as written by
// Michel: removed if no other attached project uses it, else passed on to them, so
// that the last one to leave removes it. A rule the person wrote is never here.
func (d *Deps) releaseGitRule(ctx context.Context, projectID, host string) error {
	others, err := d.repo().PassGitRule(ctx, projectID, host)
	if err != nil || others > 0 {
		return err
	}
	if d.PolicyPath == "" {
		return errors.New("cannot change the answer: the policy file path is unknown")
	}
	if _, err := policy.RemoveAllowRules(d.PolicyPath, policy.AllowRule{Host: host, Purpose: policy.PurposeProjectGit}); err != nil {
		return err
	}
	if err := d.reload(); err != nil {
		return fmt.Errorf("the rule was removed, but the policy cannot be reloaded: %w", err)
	}
	return nil
}

// dropGitRule takes back the rule a yes that failed has just written.
func (d *Deps) dropGitRule(host string) error {
	if _, err := policy.RemoveAllowRules(d.PolicyPath, policy.AllowRule{Host: host, Purpose: policy.PurposeProjectGit}); err != nil {
		return err
	}
	return d.reload()
}

// ReleaseProjectRule gives back the rule Michel wrote for a project about to be
// purged, before anything else of it goes. Once it has succeeded the row owns no
// rule, so calling it again touches nothing. An error leaves the row owning it.
func ReleaseProjectRule(ctx context.Context, d Deps, projectID string) error {
	unlock := d.sessions().lockGitRules()
	defer unlock()
	row, ok, err := d.repo().GitAnswer(ctx, projectID)
	if err != nil || !ok || !row.RuleWritten {
		return err
	}
	if err := d.releaseGitRule(ctx, projectID, row.Host); err != nil {
		return err
	}
	row.RuleWritten = false
	return d.repo().SetGitAnswer(ctx, row)
}

// attached reads the agreement and the address again, at each click: an address
// that is not the one agreed to stops everything. Nothing of git runs before the
// agreement is read, and a project that was removed sends nothing.
func (d Deps) attached(ctx context.Context, p project.Project) (remoteRead, error) {
	if !p.Active {
		return remoteRead{}, ErrGitNotAttached
	}
	if !workcopy.IsGitRepo(p.Path) {
		return remoteRead{}, ErrGitNoRepo
	}
	row, ok, err := d.repo().GitAnswer(ctx, p.ID)
	if err != nil {
		return remoteRead{}, err
	}
	if !ok || row.Answer != GitYes {
		return remoteRead{}, ErrGitNotAttached
	}
	repoState, err := workcopy.RepoState(ctx, d.work(), p)
	switch {
	case err != nil:
		return remoteRead{}, err
	case repoState != workcopy.RepoOK:
		return remoteRead{}, ErrGitEmptyRepo
	}
	read, err := d.readRemote(ctx, p)
	if err != nil {
		return remoteRead{}, err
	}
	if !read.usable() || read.remote.Address() != row.URL {
		return remoteRead{}, ErrGitRemoteChanged
	}
	return read, nil
}

// leave decides and notes the way out before git starts (R27). A local remote has
// none. Only https goes through the proxy: git and ssh open their own connection.
func (d Deps) leave(read remoteRead) (proxyURL string, closeProxy func(), err error) {
	closeProxy = func() {}
	if read.remote.Provider == gitremote.Local {
		return "", closeProxy, nil
	}
	if d.Gateway == nil {
		return "", closeProxy, errors.New("no egress gateway")
	}
	host := read.remote.Host
	if err := d.Gateway.Authorize(host, policy.PurposeProjectGit); err != nil {
		if ok, _ := d.Gateway.Allowed(host, policy.PurposeProjectGit); !ok {
			return "", closeProxy, ErrGitNoRule
		}
		return "", closeProxy, err // the audit log is down
	}
	if read.remote.Scheme != schemeHTTPS {
		return "", closeProxy, nil
	}
	proxyURL, closeProxy, err = allowproxy.Listen(d.Gateway, policy.PurposeProjectGit)
	if err != nil {
		return "", func() {}, err
	}
	return proxyURL, closeProxy, nil
}

// PushFix sends one fix branch to the remote the person agreed to, on their click.
// Nothing but that click starts it (R29). It takes the address from the project's
// configuration, read now and without secret: Clean holds the SSH user, what the
// row does not. git's output is neither shown nor kept (R32).
func PushFix(ctx context.Context, d Deps, attemptID string) (PushOutcome, error) {
	branch := Branch(attemptID)
	ev := map[string]any{"attempt_id": attemptID, "project_id": "", "host": "", "provider": "", "branch": branch, "commit": ""}
	refuse := func(err error) (PushOutcome, error) {
		d.auditGitRefusal(ctx, auditGitPush, attemptID, ev, err)
		return PushOutcome{}, err
	}
	a, err := d.repo().GetAttempt(ctx, attemptID)
	if err != nil {
		return refuse(err)
	}
	ev["project_id"] = a.ProjectID
	if a.Work.Server != nil {
		return refuse(ErrGitNotApplied)
	}
	unlock, ok := TryGitLock(d, a.ProjectID)
	if !ok {
		return refuse(ErrGitBusy)
	}
	defer unlock()
	// Read under the lock: applied is the only state with a branch to send.
	if a, err = d.repo().GetAttempt(ctx, attemptID); err != nil {
		return refuse(err)
	}
	if a.State != StateApplied {
		return refuse(ErrGitNotApplied)
	}
	prop, ok, err := d.repo().CurrentProposal(ctx, a.ID)
	if err != nil {
		return refuse(err)
	}
	if !ok || prop.CommitSHA == "" {
		return refuse(ErrGitBranchMoved)
	}
	ev["commit"] = prop.CommitSHA
	p, err := project.NewRepo(d.Store).Get(ctx, a.ProjectID)
	if err != nil {
		return refuse(err)
	}
	read, err := d.attached(ctx, p)
	if err != nil {
		return refuse(err)
	}
	ev["host"], ev["provider"] = read.host(), string(read.remote.Provider)
	proxyURL, closeProxy, err := d.leave(read)
	if err != nil {
		return refuse(err)
	}
	defer closeProxy()
	res, err := workcopy.Push(ctx, d.work(), p, read.remote.Clean, proxyURL, branch, prop.CommitSHA)
	if err != nil {
		return refuse(err)
	}
	ev["outcome"], ev["author"] = res.Outcome, d.actor()
	out := PushOutcome{Outcome: res.Outcome, Provider: string(read.remote.Provider), Branch: branch,
		MergeURL: gitremote.MergeURL(read.remote, branch), At: d.repo().now()}
	// The branch left: the audit comes first and neither depends on the click's
	// context, so that a failure of one does not hide the send from the other.
	auditErr := d.recordDone(ctx, auditGitPush, a.ID, "ok", ev)
	if auditErr != nil {
		auditErr = fmt.Errorf("the branch was sent, but the audit log could not record it: %w", auditErr)
	}
	done, cancel := d.afterWrite(ctx)
	defer cancel()
	rowErr := d.repo().RecordPush(done, FixPush{AttemptID: a.ID, CommitSHA: prop.CommitSHA, Host: read.host(), PushedAt: out.At})
	if first, ok, err := d.repo().Push(done, a.ID); err == nil && ok {
		out.At = first.PushedAt
	}
	return out, errors.Join(auditErr, rowErr)
}

// UpdateProject brings the folder up to date with the remote it agreed to, on the
// person's click. Nothing but that click starts it (R29).
func UpdateProject(ctx context.Context, d Deps, p project.Project) (workcopy.UpdateResult, error) {
	ev := map[string]any{"project_id": p.ID, "host": "", "provider": ""}
	refuse := func(err error) (workcopy.UpdateResult, error) {
		d.auditGitRefusal(ctx, auditGitUpdate, p.Name, ev, err)
		return workcopy.UpdateResult{}, err
	}
	unlock, ok := TryGitLock(d, p.ID)
	if !ok {
		return refuse(ErrGitBusy)
	}
	defer unlock()
	read, err := d.attached(ctx, p)
	if err != nil {
		return refuse(err)
	}
	ev["host"], ev["provider"] = read.host(), string(read.remote.Provider)
	proxyURL, closeProxy, err := d.leave(read)
	if err != nil {
		return refuse(err)
	}
	defer closeProxy()
	res, err := workcopy.UpdateFolder(ctx, d.work(), p, read.remote.Clean, proxyURL, read.name)
	if err != nil {
		return refuse(err)
	}
	ev["outcome"], ev["commit"], ev["author"] = res.Outcome, res.To, d.actor()
	if err := d.recordDone(ctx, auditGitUpdate, p.Name, "ok", ev); err != nil {
		return res, fmt.Errorf("the folder was updated, but the audit log could not record it: %w", err)
	}
	return res, nil
}

// auditGitRefusal records a click that did nothing, or failed: a key or a class,
// never what git said. A refusal stays one if the record fails.
func (d Deps) auditGitRefusal(ctx context.Context, action, target string, ev map[string]any, err error) {
	result, outcome := "refused", strings.TrimPrefix(ErrorKey(err), "api.git.")
	var gf *workcopy.GitFailure
	if errors.As(err, &gf) && GitServiceFailure(gf.Class) {
		result = "error"
	}
	switch {
	case outcome == "" && errors.Is(err, egress.ErrEgressDenied):
		outcome = "audit_unavailable"
	case outcome == "":
		result, outcome = "error", "internal"
	}
	ev["outcome"], ev["author"] = outcome, d.actor()
	_ = d.recordDone(ctx, action, target, result, ev)
}

// afterWrite is the context of what is recorded after a click: a click that ended
// while it ran, a server shutting down for instance, still leaves its trace.
func (d Deps) afterWrite(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), d.recordTimeout())
}

// recordDone is record under afterWrite.
func (d Deps) recordDone(ctx context.Context, action, target, result string, ev map[string]any) error {
	done, cancel := d.afterWrite(ctx)
	defer cancel()
	return d.record(done, action, target, result, ev)
}

// GitServiceFailure tells whether a class of a GitFailure is an answer, or an
// absence of answer, of the service: the route says 502, and 409 for the others.
func GitServiceFailure(class string) bool {
	switch class {
	case "auth", "host_key", "not_found", "rejected", "network", "timeout", "failed":
		return true
	}
	return false
}

// gitPath is the name of the thing in the way, for the hint of a refusal.
func gitPath(lang i18n.Lang, err error) string {
	var gf *workcopy.GitFailure
	if !errors.As(err, &gf) || gf.Path == "" {
		return ""
	}
	return " " + i18n.T(lang, "api.git.in_the_way", workcopy.FailureName(gf.Path))
}

// ExplainHint is the advice that goes with a refusal of a click, in lang, naming
// what is in the way when the refusal is about one thing; "" when it has none.
func ExplainHint(lang i18n.Lang, err error) string {
	if !lang.Valid() {
		lang = i18n.EN
	}
	key := ErrorKey(err)
	if key == "" || !i18n.Has(key+"_hint") {
		return ""
	}
	return i18n.T(lang, key+"_hint") + gitPath(lang, err)
}
