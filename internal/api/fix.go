package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/agent"
	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/servererr"
	"github.com/kvarot/michel/internal/target"
)

// fixActor is the audit actor and the author of the fixes started,
// approved or refused on the page.
const fixActor = decisionAuthor

// agentStatusTTL is how long the answer of GET /agent/status is kept: the
// detection runs Claude Code three times.
const agentStatusTTL = 10 * time.Second

// fixStatus is the HTTP status of each refusal of the fix service.
var fixStatus = map[string]int{
	"fix.err.not_git":           http.StatusUnprocessableEntity,
	"fix.err.consent_required":  http.StatusConflict,
	"fix.err.health_forbidden":  http.StatusForbidden,
	"fix.err.strict_local":      http.StatusForbidden,
	"fix.err.agent_unavailable": http.StatusServiceUnavailable,
	"fix.err.busy":              http.StatusConflict,
	"fix.err.stale_proposal":    http.StatusConflict,
	"fix.err.mask_token":        http.StatusConflict,
	"fix.err.no_change":         http.StatusConflict,
	"fix.err.no_proposal":       http.StatusConflict,
	"fix.err.agent_gone":        http.StatusConflict,
	"fix.err.change_refused":    http.StatusUnprocessableEntity,
	"fix.err.bad_state":         http.StatusConflict,
	"fix.err.not_found":         http.StatusNotFound,
	"fix.err.hold_stale":        http.StatusConflict,
	"fix.err.hold_person":       http.StatusForbidden,
}

// FixErrorBody is the answer to a refusal of the fix service: the sentence
// in the request's language, its catalog key (the page reacts to some:
// fix.err.consent_required opens the consent screen, fix.err.stale_proposal
// reloads the proposal) and, for a missing consent, the lines to accept.
type FixErrorBody struct {
	Error   string            `json:"error"`
	Hint    string            `json:"hint,omitempty"`
	Code    string            `json:"code"`
	Consent []ConsentLineView `json:"consent,omitempty"`
	// Detail is a short technical detail (sanitized, no path, no secret)
	// the page folds behind "Voir le détail".
	Detail string `json:"detail,omitempty"`
}

// FixFindingView is the finding an attempt works on.
type FixFindingView struct {
	ID               string   `json:"id"`
	ManifestRelPath  string   `json:"manifest_rel_path"`
	Ecosystem        string   `json:"ecosystem"`
	Package          string   `json:"package"`
	OSVID            string   `json:"osv_id"`
	Severity         string   `json:"severity"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersions    []string `json:"fixed_versions"`
	Summary          string   `json:"summary"`
	Status           string   `json:"status"`
}

// CommandView is a command Michel ran for a proposal: what (update,
// install, tests) and its argv ("" for the tests).
type CommandView struct {
	What string `json:"what"`
	Argv string `json:"argv"`
}

// ProposalView is the current proposal of an attempt: what the user
// approves (Hash), in clear. Diff and TestsOutput are left out of lists.
type ProposalView struct {
	ID          string   `json:"id"`
	Summary     string   `json:"summary"`
	Diff        string   `json:"diff,omitempty"`
	Files       []string `json:"files"`
	TestsStatus string   `json:"tests_status"`
	TestsOutput string   `json:"tests_output,omitempty"`
	RescanClean bool     `json:"rescan_clean"`
	Risk        int      `json:"risk"`
	Hash        string   `json:"hash"`
	StepsServer []string `json:"steps_server"`
	// Commands are the commands Michel ran for the proposal (update,
	// install, tests), Michel's own closed argv; the tests' argv, a
	// declared project command, is never answered.
	Commands []CommandView `json:"commands"`
	// FromVersion and ToVersion are the package's versions before and
	// after the fix: the installed one, and the one the fix commit's
	// lockfile resolves, else the planned target ("" when unknown).
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
	CreatedAt   string `json:"created_at"`
}

// MessageView is one line of the conversation. Role is user, agent, michel
// or tool (a line of progress: the stream sends it as an activity event).
type MessageView struct {
	ID   string `json:"id"`
	Role string `json:"role"`
	Text string `json:"text"`
	At   string `json:"at"`
}

// StateView is the state event of the stream.
type StateView struct {
	State string `json:"state"`
	Cause string `json:"cause"`
	// CauseDetail is the technical detail behind Cause (sanitized).
	CauseDetail string `json:"cause_detail"`
	ApprovedBy  string `json:"approved_by"`
	Branch      string `json:"branch,omitempty"`
	UpdatedAt   string `json:"updated_at"`
}

// AttemptView is one fix attempt. Branch is the branch created in the
// user's repository, once applied. Messages is the conversation, oldest
// first (null in lists).
type AttemptView struct {
	ID      string         `json:"id"`
	Finding FixFindingView `json:"finding"`
	Project string         `json:"project"`
	Origin  string         `json:"origin"`
	State   string         `json:"state"`
	Cause   string         `json:"cause"`
	// CauseDetail is the technical detail behind Cause (sanitized).
	CauseDetail string        `json:"cause_detail"`
	ApprovedBy  string        `json:"approved_by"`
	Branch      string        `json:"branch,omitempty"`
	CreatedAt   string        `json:"created_at"`
	UpdatedAt   string        `json:"updated_at"`
	Proposal    *ProposalView `json:"proposal"`
	Messages    []MessageView `json:"messages"`
	// Server is set for a fix of a server (Project is then the server's name).
	Server *ServerAttemptView `json:"server,omitempty"`
	// Hold is set while the attempt waits for the person's answer about the
	// possible keys found in its copy: files and lines, never a value.
	Hold *HoldView `json:"hold,omitempty"`
}

// HoldFileView is one file with a possible key, and its lines.
type HoldFileView struct {
	File  string `json:"file"`
	Lines []int  `json:"lines"`
}

// HoldView is what a held attempt asks about. More is how many other files
// hold one; Hash goes back with the yes.
type HoldView struct {
	Count int            `json:"count"`
	Files []HoldFileView `json:"files"`
	More  int            `json:"more"`
	Hash  string         `json:"hash"`
}

// holdView renders the hold of a, nil when it waits for nothing. A file name
// goes through the display masker like every other stored text.
func holdView(m *mask.Masker, a fix.Attempt) *HoldView {
	h, ok := fix.HoldOf(a)
	if !ok {
		return nil
	}
	v := &HoldView{Count: h.Count, Files: []HoldFileView{}, More: h.More, Hash: h.Hash}
	for _, f := range h.Files {
		v.Files = append(v.Files, HoldFileView{File: shown(m, f.File), Lines: f.Lines})
	}
	return v
}

// ConsentLineView is one line of the AI consent screen: its catalog key,
// the sentence in the request's language and, for a destination, the host
// and the purpose of the allow rule written on consent.
type ConsentLineView struct {
	What    string `json:"what"`
	Text    string `json:"text"`
	Host    string `json:"host,omitempty"`
	Purpose string `json:"purpose,omitempty"`
}

// AIConsentView is GET /projects/{name}/ai-consent. Consented: the project
// gave its consent (GivenAt, RFC 3339); Ready: an agent may work on it now
// (consent given and every rule in force). Lines is what to accept, empty
// when ready. Refusal and RefusalCode say why no consent can be given
// (health project, strict_local policy).
type AIConsentView struct {
	Project     string            `json:"project"`
	Consented   bool              `json:"consented"`
	GivenAt     string            `json:"given_at"`
	Ready       bool              `json:"ready"`
	Lines       []ConsentLineView `json:"lines"`
	Refusal     string            `json:"refusal,omitempty"`
	RefusalCode string            `json:"refusal_code,omitempty"`
	// SwitchMode is true when the policy is strict_local (and the project
	// not health): the page may offer « Autoriser les IA externes (mode
	// standard) », sent as switch_to_standard (controller ruling 41).
	SwitchMode bool `json:"switch_mode"`
}

// AgentStatusView is GET /agent/status: whether Claude Code can be used
// and, when it cannot, what to do (Hint, in the request's language).
type AgentStatusView struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version"`
	LoggedIn  bool   `json:"logged_in"`
	Ready     bool   `json:"ready"`
	HintCode  string `json:"hint_code,omitempty"`
	Hint      string `json:"hint,omitempty"`
}

// FixMessageRequest, FixApproveRequest and FixRefuseRequest are the bodies
// of the fix routes.
type (
	FixMessageRequest struct {
		Text string `json:"text"`
	}
	FixApproveRequest struct {
		Hash string `json:"hash"`
	}
	FixRefuseRequest struct {
		Reason string `json:"reason"`
	}
	FixContinueRequest struct {
		Hash string `json:"hash"`
	}
)

// agentCache keeps the last detection of Claude Code.
type agentCache struct {
	mu     sync.Mutex
	at     time.Time
	status agent.Status
}

func (s *server) fixRoutes() {
	m := s.mux
	m.HandleFunc("POST /api/v1/findings/{id}/fix", s.fixStart)
	m.HandleFunc("GET /api/v1/fix/{attempt}", s.fixAttempt)
	m.HandleFunc("GET /api/v1/fix/{attempt}/events", s.fixEvents)
	m.HandleFunc("POST /api/v1/fix/{attempt}/message", s.fixMessage)
	m.HandleFunc("POST /api/v1/fix/{attempt}/approve", s.fixApprove)
	m.HandleFunc("POST /api/v1/fix/{attempt}/refuse", s.fixRefuse)
	m.HandleFunc("POST /api/v1/fix/{attempt}/continue", s.fixContinue)
	m.HandleFunc("POST /api/v1/fix/{attempt}/withdraw", s.fixWithdraw)
	m.HandleFunc("POST /api/v1/fix/{attempt}/snapshot-done", s.fixSnapshotDone)
	m.HandleFunc("POST /api/v1/fix/{attempt}/applied-by-me", s.fixAppliedByMe)
	m.HandleFunc("POST /api/v1/fix/{attempt}/resolve", s.fixResolve)
	m.HandleFunc("GET /api/v1/fixes", s.fixList)
	m.HandleFunc("GET /api/v1/agent/status", s.agentStatus)
	m.HandleFunc("GET /api/v1/projects/{name}/ai-consent", s.aiConsent)
	m.HandleFunc("POST /api/v1/projects/{name}/ai-consent", s.aiConsentGive)
	m.HandleFunc("GET /api/v1/projects/{name}/git", s.projectGit)
	m.HandleFunc("POST /api/v1/projects/{name}/git/answer", s.projectGitAnswer)
	m.HandleFunc("POST /api/v1/projects/{name}/git/update", s.projectGitUpdate)
	m.HandleFunc("POST /api/v1/fix/{attempt}/push", s.fixPush)
}

// fixDeps are the fix service's collaborators for one request: serve's,
// with the policy in force, the request's language (Michel's messages are
// written in it) and the page as author. ok is false (503 answered) when
// the server runs without the fix service.
func (s *server) fixDeps(w http.ResponseWriter, r *http.Request, lang i18n.Lang) (fix.Deps, bool) {
	if s.deps.Fix == nil {
		s.fail(w, http.StatusServiceUnavailable, i18n.T(lang, "api.fix.unavailable"), "")
		return fix.Deps{}, false
	}
	d := *s.deps.Fix
	d.Policy = s.currentPolicy()
	d.LivePolicy = s.currentPolicy
	d.Lang = lang
	d.Actor = fixActor
	if s.deps.Reload != nil {
		d.Reload = s.reload
	}
	return d, true
}

// fixWorker is serve's loop of the level 2 queue, on the server's
// background context (Close stops it). It reads the server's policy at each
// pass: a consent given on the page (which reloads it) counts at once.
func (s *server) fixWorker(ctx context.Context) {
	d := *s.deps.Fix
	d.Policy = s.currentPolicy()
	d.LivePolicy = s.currentPolicy
	d.Lang = s.deps.Lang
	fix.Worker(ctx, d)
}

// detached is a context for work a request starts that must not stop when
// the page goes away (the copy, Michel's update, the branch), bounded by
// longTimeout and cancelled when the handler closes.
func (s *server) detached(r *http.Request) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), longTimeout)
	stop := context.AfterFunc(s.bg, cancel)
	return ctx, func() { stop(); cancel() }
}

// consentLines renders the lines of the consent screen in lang.
func consentLines(lang i18n.Lang, texts []fix.ConsentText) []ConsentLineView {
	out := []ConsentLineView{}
	for _, c := range texts {
		v := ConsentLineView{What: c.What, Host: c.Host, Purpose: c.Purpose}
		if c.Host != "" {
			v.Text = i18n.T(lang, c.What, c.Host)
		} else {
			v.Text = i18n.T(lang, c.What)
		}
		out = append(out, v)
	}
	return out
}

// fixRefused answers a refusal of the fix service with its status and its
// sentence; any other error is a 500 without its cause. For a missing
// consent the lines to accept come along.
func (s *server) fixRefused(w http.ResponseWriter, r *http.Request, lang i18n.Lang, err error, p *project.Project) {
	key := fix.ErrorKey(err)
	status, ok := fixStatusOf(key)
	if !ok {
		// A server fix can also end on a refusal of the registry or of SSH.
		if st, k := targetFailure(err); k != "" {
			s.failedBody(w, st, lang, k, k+"_hint")
			return
		}
		s.internal(w, r)
		return
	}
	body := FixErrorBody{Error: fix.Explain(lang, err), Code: key}
	if key == "fix.err.consent_required" && p != nil {
		_, _, consented, cerr := fix.NewRepo(s.deps.Store).Consent(r.Context(), p.ID)
		if cerr == nil {
			body.Consent = consentLines(lang, fix.ConsentNeeded(*p, s.currentPolicy(), consented))
		}
	}
	writeJSON(w, status, body)
}

// displayMasker is the masker the texts of an attempt are shown through:
// its own table (its tokens stay as they are), else a fresh one. A secret
// or an absolute path that reached the store unmasked never leaves.
func (s *server) displayMasker(attemptID string) *mask.Masker {
	if s.deps.Secrets != nil {
		if m, err := mask.Load(s.deps.Secrets, attemptID); err == nil {
			return m
		}
	}
	return mask.New()
}

// shown makes a stored text safe to answer: control characters removed,
// secrets and absolute paths masked.
func shown(m *mask.Masker, text string) string {
	return m.Mask(scan.SanitizeText(text))
}

func messageView(m *mask.Masker, msg fix.Message) MessageView {
	return MessageView{ID: msg.ID, Role: msg.Role, Text: shown(m, msg.Text), At: stamp(msg.At)}
}

func proposalView(m *mask.Masker, p fix.Proposal, full bool) *ProposalView {
	v := &ProposalView{ID: p.ID, Summary: shown(m, p.Summary), Files: sanitizeAll(p.Files), TestsStatus: p.TestsStatus,
		RescanClean: p.RescanClean, Risk: p.Risk, Hash: p.Hash, StepsServer: sanitizeAll(p.StepsServer),
		Commands: commandViews(p.Commands), FromVersion: scan.SanitizeText(p.FromVersion), ToVersion: scan.SanitizeText(p.ToVersion), CreatedAt: stamp(p.CreatedAt)}
	if full {
		// The diff keeps its lines: only secrets and absolute paths go.
		v.Diff = m.Mask(strings.ToValidUTF8(p.Diff, "�"))
		v.TestsOutput = shown(m, p.TestsOutput)
	}
	return v
}

// commandViews renders the commands of a proposal, paths removed.
func commandViews(list []fix.RanCommand) []CommandView {
	out := []CommandView{}
	for _, c := range list {
		argv := ""
		if c.What != "tests" {
			argv = noPaths(c.Argv)
		}
		out = append(out, CommandView{What: scan.SanitizeText(c.What), Argv: argv})
	}
	return out
}

func stateView(m *mask.Masker, a fix.Attempt, lang i18n.Lang) StateView {
	v := StateView{State: string(a.State), Cause: shown(m, fix.CauseText(lang, a.Cause)), CauseDetail: shown(m, noPaths(a.CauseDetail)), ApprovedBy: a.ApprovedBy,
		UpdatedAt: stamp(a.UpdatedAt)}
	if a.State == fix.StateApplied || a.State == fix.StateProvenFixed || a.State == fix.StateInconclusive {
		v.Branch = fix.Branch(a.ID)
	}
	return v
}

// attemptView builds the view of a; full adds the diff, the tests' output
// and the conversation.
func (s *server) attemptView(ctx context.Context, a fix.Attempt, full bool, lang i18n.Lang) (AttemptView, error) {
	m := s.displayMasker(a.ID)
	st := stateView(m, a, lang)
	v := AttemptView{ID: a.ID, Origin: a.Origin, State: st.State, Cause: st.Cause, CauseDetail: st.CauseDetail, ApprovedBy: a.ApprovedBy, Branch: st.Branch,
		CreatedAt: stamp(a.CreatedAt), UpdatedAt: stamp(a.UpdatedAt), Hold: holdView(m, a)}
	repo := fix.NewRepo(s.deps.Store)
	prop, ok, err := repo.CurrentProposal(ctx, a.ID)
	if err != nil {
		return AttemptView{}, err
	}
	if a.Work.Server != nil {
		var pp *fix.Proposal
		if ok {
			pp = &prop
		}
		if err := s.serverAttempt(ctx, &v, a, pp, full, lang); err != nil {
			return AttemptView{}, err
		}
	} else {
		fi, p, found, err := s.lookup(ctx, a.FindingID)
		if err != nil {
			return AttemptView{}, err
		}
		if found {
			v.Project = p.Name
			v.Finding = FixFindingView{ID: fi.ID, ManifestRelPath: scan.SanitizeText(fi.ManifestRelPath), Ecosystem: fi.Ecosystem,
				Package: scan.SanitizeText(fi.Package), OSVID: scan.SanitizeText(fi.OSVID), Severity: severityOf(effective(fi)),
				InstalledVersion: scan.SanitizeText(fi.InstalledVersion), FixedVersions: sanitizeAll(fi.FixedVersions),
				Summary: scan.SanitizeText(fi.Summary), Status: fi.Status}
		} else {
			v.Finding = FixFindingView{ID: a.FindingID, FixedVersions: []string{}}
		}
	}
	if ok {
		v.Proposal = proposalView(m, prop, full)
	}
	if full {
		msgs, err := repo.ListMessages(ctx, a.ID)
		if err != nil {
			return AttemptView{}, err
		}
		v.Messages = make([]MessageView, 0, len(msgs))
		for _, msg := range msgs {
			v.Messages = append(v.Messages, messageView(m, msg))
		}
	}
	return v, nil
}

// attempt reads the attempt of the route's {attempt}; it answers 404 itself.
func (s *server) attempt(w http.ResponseWriter, r *http.Request, lang i18n.Lang) (fix.Attempt, bool) {
	a, err := fix.NewRepo(s.deps.Store).GetAttempt(r.Context(), r.PathValue("attempt"))
	switch {
	case errors.Is(err, fix.ErrNotFound):
		s.fixRefused(w, r, lang, fix.ErrNotFound, nil)
		return fix.Attempt{}, false
	case err != nil:
		s.internal(w, r)
		return fix.Attempt{}, false
	}
	return a, true
}

// answerAttempt answers the full view of the attempt id with status.
func (s *server) answerAttempt(w http.ResponseWriter, r *http.Request, status int, id string) {
	a, err := fix.NewRepo(s.deps.Store).GetAttempt(r.Context(), id)
	if err != nil {
		s.internal(w, r)
		return
	}
	v, err := s.attemptView(r.Context(), a, true, s.answerLang(r))
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, status, v)
}

// fixStart starts an attempt on the finding: 202 with the attempt (its
// agent works in the background; the attempt may already be failed, with
// its cause, when the copy could not be prepared), or the refusal.
func (s *server) fixStart(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	d, ok := s.fixDeps(w, r, lang)
	if !ok {
		return
	}
	// A finding of a server is fixed by Michel's own rules first.
	if fix.IsServerFinding(r.Context(), d, r.PathValue("id")) {
		s.runServerFix(w, r, lang, d, r.PathValue("id"), false)
		return
	}
	fi, p, found, err := s.lookup(r.Context(), r.PathValue("id"))
	if err != nil {
		s.internal(w, r)
		return
	}
	if !found {
		s.fail(w, http.StatusNotFound, i18n.T(lang, "api.finding_not_found"), "")
		return
	}
	// Preparing the copy and running Michel's update may outlast the
	// server's write timeout.
	extend(w)
	ctx, cancel := s.detached(r)
	defer cancel()
	a, err := fix.Start(ctx, d, fi.ID, fix.OriginAgent)
	if err != nil {
		if fix.ErrorKey(err) == "" && a.ID != "" {
			// The attempt exists and failed with its cause in clear.
			s.answerStarted(w, r, a)
			return
		}
		s.fixRefused(w, r, lang, err, &p)
		return
	}
	s.answerStarted(w, r, a)
}

func (s *server) answerStarted(w http.ResponseWriter, r *http.Request, a fix.Attempt) {
	got, err := fix.NewRepo(s.deps.Store).GetAttempt(r.Context(), a.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	v, err := s.attemptView(r.Context(), got, true, s.answerLang(r))
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]AttemptView{"attempt": v})
}

func (s *server) fixAttempt(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	a, ok := s.attempt(w, r, lang)
	if !ok {
		return
	}
	v, err := s.attemptView(r.Context(), a, true, s.answerLang(r))
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *server) fixMessage(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req FixMessageRequest
	if !s.readJSONHint(w, r, &req, i18n.T(lang, "api.fix.message_hint")) {
		return
	}
	if strings.TrimSpace(scan.SanitizeText(req.Text)) == "" {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.fix.empty_message"), "")
		return
	}
	d, ok := s.fixDeps(w, r, lang)
	if !ok {
		return
	}
	a, ok := s.attempt(w, r, lang)
	if !ok {
		return
	}
	if err := fix.SendMessage(r.Context(), d, a.ID, req.Text); err != nil {
		s.fixRefused(w, r, lang, err, nil)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"sent": true})
}

// fixApprove approves the proposal the page showed (its hash) and applies
// it: the branch is created in the user's repository. 409 when the
// proposal changed since (nothing applied).
func (s *server) fixApprove(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req FixApproveRequest
	if !s.readJSONHint(w, r, &req, i18n.T(lang, "api.fix.approve_hint")) {
		return
	}
	if strings.TrimSpace(req.Hash) == "" {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.fix.need_hash"), i18n.T(lang, "api.fix.approve_hint"))
		return
	}
	d, ok := s.fixDeps(w, r, lang)
	if !ok {
		return
	}
	a, ok := s.attempt(w, r, lang)
	if !ok {
		return
	}
	if err := fix.Approve(r.Context(), d, a.ID, strings.TrimSpace(req.Hash)); err != nil {
		s.fixRefused(w, r, lang, err, nil)
		return
	}
	// A server fix the user runs waits for their word (applied-by-me): the
	// approval is all there is to do now.
	if a.Work.Server != nil {
		if prop, ok, err := fix.NewRepo(s.deps.Store).CurrentProposal(r.Context(), a.ID); err == nil && ok && prop.Server != nil &&
			prop.Server.Executor == target.ExecUser {
			s.answerAttempt(w, r, http.StatusOK, a.ID)
			return
		}
	}
	extend(w)
	ctx, cancel := s.detached(r)
	defer cancel()
	if err := fix.Apply(ctx, d, a.ID); err != nil {
		s.applyFailed(w, r, lang, a, err)
		return
	}
	s.answerAttempt(w, r, http.StatusOK, a.ID)
}

func (s *server) fixRefuse(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req FixRefuseRequest
	if !s.readBody(w, r, &req, true) {
		return
	}
	d, ok := s.fixDeps(w, r, lang)
	if !ok {
		return
	}
	a, ok := s.attempt(w, r, lang)
	if !ok {
		return
	}
	if err := fix.Refuse(r.Context(), d, a.ID, req.Reason); err != nil {
		s.fixRefused(w, r, lang, err, nil)
		return
	}
	s.answerAttempt(w, r, http.StatusOK, a.ID)
}

// fixContinue is the person's yes to a held attempt, for the list of keys the
// page showed (its hash): 202 with the attempt, its agent working in the
// background (the attempt may already be failed, with its cause, when the
// agent could not start). 409 when the code changed since: nothing started.
func (s *server) fixContinue(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req FixContinueRequest
	if !s.readJSONHint(w, r, &req, i18n.T(lang, "api.fix.continue_hint")) {
		return
	}
	if strings.TrimSpace(req.Hash) == "" {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.fix.continue_need_hash"), i18n.T(lang, "api.fix.continue_hint"))
		return
	}
	d, ok := s.fixDeps(w, r, lang)
	if !ok {
		return
	}
	a, ok := s.attempt(w, r, lang)
	if !ok {
		return
	}
	// As at a start: Michel's update may outlast the server's write timeout.
	extend(w)
	ctx, cancel := s.detached(r)
	defer cancel()
	got, err := fix.ContinueHeld(ctx, d, a.ID, strings.TrimSpace(req.Hash))
	if err != nil && (fix.ErrorKey(err) != "" || got.ID == "") {
		s.fixRefused(w, r, lang, err, nil)
		return
	}
	s.answerAttempt(w, r, http.StatusAccepted, a.ID)
}

// fixWithdraw is the person's no to a held attempt: no agent, the attempt ends.
func (s *server) fixWithdraw(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	d, ok := s.fixDeps(w, r, lang)
	if !ok {
		return
	}
	a, ok := s.attempt(w, r, lang)
	if !ok {
		return
	}
	if err := fix.WithdrawHeld(r.Context(), d, a.ID); err != nil {
		s.fixRefused(w, r, lang, err, nil)
		return
	}
	s.answerAttempt(w, r, http.StatusOK, a.ID)
}

// fixStates are the accepted values of GET /fixes?state= (several, comma
// separated).
var fixStates = []string{string(fix.StatePreparing), string(fix.StateHeld), string(fix.StateProposed), string(fix.StateApproved), string(fix.StateRefused),
	string(fix.StateApplied), string(fix.StateProvenFixed), string(fix.StateInconclusive), string(fix.StateFailed), string(fix.StateWithdrawn), string(fix.StateSuperseded),
	string(fix.StateRunning), string(fix.StateUnknown)}

// fixList lists the attempts, newest first, without their conversation:
// ?state= keeps some states, ?project= one active project.
func (s *server) fixList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	var states []string
	for _, st := range strings.Split(q.Get("state"), ",") {
		if st = strings.TrimSpace(st); st == "" {
			continue
		}
		if !slices.Contains(fixStates, st) {
			s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.bad_status"), i18n.T(lang, "api.bad_status_hint", strings.Join(fixStates, ", ")))
			return
		}
		states = append(states, st)
	}
	projectID := ""
	if name := strings.TrimSpace(q.Get("project")); name != "" {
		p, found, err := s.activeProject(ctx, name)
		if err != nil {
			s.internal(w, r)
			return
		}
		if !found {
			s.fail(w, http.StatusNotFound, i18n.T(lang, "api.project_not_found"), "")
			return
		}
		projectID = p.ID
	}
	// ?target= keeps the attempts of one server (its id or its name).
	if ref := strings.TrimSpace(q.Get("target")); ref != "" {
		t, err := s.targets().Get(ctx, ref)
		if err != nil {
			s.targetRefused(w, r, lang, err, false)
			return
		}
		projectID = t.ID
	}
	list, err := fix.NewRepo(s.deps.Store).ListAttempts(ctx, projectID, "")
	if err != nil {
		s.internal(w, r)
		return
	}
	out := []AttemptView{}
	for _, a := range list {
		if len(states) > 0 && !slices.Contains(states, string(a.State)) {
			continue
		}
		v, err := s.attemptView(ctx, a, false, lang)
		if err != nil {
			s.internal(w, r)
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// agentStatus says whether Claude Code can be used, kept agentStatusTTL.
func (s *server) agentStatus(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	d, ok := s.fixDeps(w, r, lang)
	if !ok {
		return
	}
	c := &s.agentSt
	c.mu.Lock()
	if c.at.IsZero() || time.Since(c.at) > agentStatusTTL {
		if d.AgentStatus != nil {
			c.status = d.AgentStatus(r.Context())
		} else {
			ad := d.AgentDeps
			ad.DataDir, ad.Now = d.DataDir, d.Now
			c.status = agent.Detect(r.Context(), ad)
		}
		c.at = time.Now()
	}
	st := c.status
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, AgentStatusView{Installed: st.Installed, Version: scan.SanitizeText(st.Version), LoggedIn: st.LoggedIn,
		Ready: st.Hint == "", HintCode: st.Hint, Hint: st.Message(lang)})
}

// consentView is the consent screen of p in lang.
func (s *server) consentView(ctx context.Context, p project.Project, lang i18n.Lang) (AIConsentView, error) {
	at, _, consented, err := fix.NewRepo(s.deps.Store).Consent(ctx, p.ID)
	if err != nil {
		return AIConsentView{}, err
	}
	pol := s.currentPolicy()
	lines := fix.ConsentNeeded(p, pol, consented)
	v := AIConsentView{Project: p.Name, Consented: consented, Ready: consented && len(lines) == 0, Lines: consentLines(lang, lines)}
	if consented {
		v.GivenAt = stamp(at)
	}
	switch {
	case p.Classification == policy.ClassHealth:
		v.Ready, v.RefusalCode = false, fix.ErrorKey(fix.ErrHealthForbidden)
		v.Refusal = fix.Explain(lang, fix.ErrHealthForbidden)
	case pol.Sovereignty.Mode == policy.ModeStrictLocal:
		v.Ready, v.RefusalCode, v.SwitchMode = false, fix.ErrorKey(fix.ErrStrictLocal), true
		v.Refusal = fix.Explain(lang, fix.ErrStrictLocal)
	}
	return v, nil
}

// consentProject reads the active project of the route's {name}; it
// answers 404 itself.
func (s *server) consentProject(w http.ResponseWriter, r *http.Request, lang i18n.Lang) (project.Project, bool) {
	p, found, err := s.activeProject(r.Context(), r.PathValue("name"))
	if err != nil {
		s.internal(w, r)
		return project.Project{}, false
	}
	if !found {
		s.fail(w, http.StatusNotFound, i18n.T(lang, "api.project_not_found"), "")
		return project.Project{}, false
	}
	return p, true
}

func (s *server) aiConsent(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	p, ok := s.consentProject(w, r, lang)
	if !ok {
		return
	}
	v, err := s.consentView(r.Context(), p, lang)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// aiConsentGive records the project's AI consent: the allow rules go into
// the policy file, external providers are turned on, the gateway learns
// the rules and ai.consent is audited. It answers the new consent screen.
func (s *server) aiConsentGive(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	// switch_to_standard is the user's click on « Autoriser les IA
	// externes (mode standard) »: only then does a strict_local policy
	// change.
	var body struct {
		SwitchToStandard bool `json:"switch_to_standard"`
	}
	if !s.readBody(w, r, &body, true) {
		return
	}
	p, ok := s.consentProject(w, r, lang)
	if !ok {
		return
	}
	s.policyMu.Lock()
	d, ok := s.fixDeps(w, r, lang)
	if !ok {
		s.policyMu.Unlock()
		return
	}
	err := fix.GiveConsentWith(r.Context(), d, p.ID, fix.ConsentOptions{SwitchToStandard: body.SwitchToStandard})
	s.policyMu.Unlock()
	if err != nil {
		s.fixRefused(w, r, lang, err, nil)
		return
	}
	v, err := s.consentView(r.Context(), p, lang)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// applyFailed answers an Apply that failed after the approval. A refusal of
// the fix service keeps its status and sentence. For a server fix, a refusal
// of SSH is answered in clear, never with the error's text (it names the
// user, the host, the agent) and without a repository branch; for a code
// fix, the approval stands and Michel applies it again at its next start.
func (s *server) applyFailed(w http.ResponseWriter, r *http.Request, lang i18n.Lang, a fix.Attempt, err error) {
	if fix.ErrorKey(err) != "" {
		s.fixRefused(w, r, lang, err, nil)
		return
	}
	if a.Work.Server != nil {
		if st, k := targetFailure(err); k != "" {
			s.failedBody(w, st, lang, k, k+"_hint")
			return
		}
		s.failedBody(w, http.StatusBadGateway, lang, servererr.Unreachable, servererr.Unreachable+"_hint")
		return
	}
	detail := mask.New().Mask(noPaths(err.Error()))
	writeJSON(w, http.StatusBadGateway, FixErrorBody{Error: i18n.T(lang, "api.fix.apply_failed"),
		Hint: i18n.T(lang, "api.fix.apply_failed_hint"), Code: "api.fix.apply_failed", Detail: detail})
}
