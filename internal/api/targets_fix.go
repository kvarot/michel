package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

// StepView is one step of a server fix as Michel saw it run.
type StepView struct {
	Op     string `json:"op"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// ServerAttemptView is what a fix of a server adds to its attempt: where it
// runs, who runs it, whether it needs the user's snapshot, the steps as they
// ran and the backups to put back by hand ("backup -> file").
type ServerAttemptView struct {
	Target         TargetRef  `json:"target"`
	Executor       string     `json:"executor"`
	RunAsRoot      bool       `json:"run_as_root"`
	NeedsSnapshot  bool       `json:"needs_snapshot"`
	SnapshotDone   bool       `json:"snapshot_done"`
	SnapshotDoneAt string     `json:"snapshot_done_at,omitempty"`
	Mitigation     bool       `json:"mitigation"`
	Steps          []StepView `json:"steps"`
	BackupList     []string   `json:"backup_list"`
	// ForProduction names the production server a preprod fix is tried for.
	ForProduction *TargetRef `json:"for_production,omitempty"`
	// ProdFindingID is the production flaw it is tried for: its card finds the
	// attempt by this id.
	ProdFindingID string `json:"prod_finding_id,omitempty"`
	// Scripts are the two scripts the user validates, exactly as they run
	// (the full view only): to read, and to copy when the user runs them.
	Scripts *ScriptsView `json:"scripts,omitempty"`
	// ScriptsUnreadable: the scripts are not valid text and are not shown
	// (never altered to fit).
	ScriptsUnreadable bool `json:"scripts_unreadable,omitempty"`
	// Backups are the copies of the server files kept on this computer, and
	// whether each one still opens (the full view only).
	Backups []BackupView `json:"backups,omitempty"`
}

// ScriptsView is the apply and the undo script of a server fix. They hold
// paths and values of the server only, never a secret value (a secret
// directive is never written by a fix).
type ScriptsView struct {
	Apply string `json:"apply"`
	Undo  string `json:"undo"`
}

// BackupView is a backup kept on this computer: the server file it copies,
// when, and its state: kept, key_lost (sealed with a key that was replaced:
// it no longer opens, the copy on the server stays) or damaged (it does not
// match).
type BackupView struct {
	File  string `json:"file"`
	At    string `json:"at"`
	State string `json:"state"`
}

// serverAttempt fills the server part of an attempt view: its finding, its
// server and, when the attempt has a proposal, the scripts' facts and the
// steps. The caller has checked a.Work.Server is set.
func (s *server) serverAttempt(ctx context.Context, v *AttemptView, a fix.Attempt, prop *fix.Proposal, full bool, lang i18n.Lang) error {
	repo := s.targets()
	t, err := repo.Get(ctx, a.Work.Server.TargetID)
	if err != nil && !errors.Is(err, target.ErrNotFound) {
		return err
	}
	user := t.User
	sv := &ServerAttemptView{Target: TargetRef{ID: a.Work.Server.TargetID, Name: srvText("", t.Name)}, Steps: []StepView{}, BackupList: []string{}}
	v.Project = sv.Target.Name
	list, err := scan.NewRepo(s.deps.Store).FindByIDPrefix(ctx, a.FindingID)
	if err != nil {
		return err
	}
	v.Finding = FixFindingView{ID: a.FindingID, FixedVersions: []string{}}
	for _, f := range list {
		if f.ID != a.FindingID {
			continue
		}
		v.Finding = FixFindingView{ID: f.ID, ManifestRelPath: srvText(user, f.Location), Ecosystem: f.Ecosystem, Package: srvText(user, f.Package),
			OSVID: srvText(user, f.OSVID), Severity: severityOf(effective(f)), InstalledVersion: srvText(user, f.InstalledVersion),
			FixedVersions: srvTexts(user, f.FixedVersions), Summary: srvText(user, f.Summary), Status: f.Status}
	}
	if w := a.Work.Server; w.ProdTargetID != "" {
		ref := &TargetRef{ID: w.ProdTargetID}
		if pt, err := repo.Get(ctx, w.ProdTargetID); err == nil {
			ref.Name = srvText("", pt.Name)
		}
		sv.ForProduction = ref
		sv.ProdFindingID = w.ProdFindingID
	}
	if at, _, ok, err := fix.NewRepo(s.deps.Store).SnapshotAck(ctx, a.ID); err != nil {
		return err
	} else if ok {
		sv.SnapshotDone, sv.SnapshotDoneAt = true, stamp(at)
	}
	if prop != nil {
		for _, st := range prop.Steps {
			sv.Steps = append(sv.Steps, StepView{Op: srvText(user, st.Op), OK: st.OK, Detail: srvText(user, st.Detail)})
		}
		if prop.Server != nil {
			sv.Executor, sv.NeedsSnapshot, sv.Mitigation = string(prop.Server.Executor), prop.Server.NeedsSnapshot, prop.Server.Mitigation
		}
		if prop.Scripts != nil {
			sv.RunAsRoot = prop.Scripts.RunAsRoot
		}
		sv.BackupList = srvTexts(user, fix.BackupList(*prop))
		if sv.BackupList == nil {
			sv.BackupList = []string{}
		}
		if full && prop.Scripts != nil {
			// Exactly as validated: the text the hash covers, the one to copy.
			// A script that is not valid UTF-8 is never rewritten to fit: it
			// is left out, and the page says it cannot show it.
			if utf8.ValidString(prop.Scripts.Apply) && utf8.ValidString(prop.Scripts.Undo) {
				sv.Scripts = &ScriptsView{Apply: prop.Scripts.Apply, Undo: prop.Scripts.Undo}
			} else {
				sv.ScriptsUnreadable = true
			}
		}
	}
	if full {
		if d, ok := s.fixDepsQuiet(lang); ok {
			if list, err := fix.BackupStates(ctx, d, a.ID); err == nil {
				for _, b := range list {
					sv.Backups = append(sv.Backups, BackupView{File: srvText(user, b.RemotePath), At: stamp(b.CreatedAt), State: b.State})
				}
			}
		}
	}
	v.Server = sv
	return nil
}

// fixStatusOf is the HTTP status of a refusal key of the fix service.
func fixStatusOf(key string) (int, bool) {
	if st, ok := fixStatus[key]; ok {
		return st, true
	}
	switch key {
	case "fix.server.not_server":
		return http.StatusNotFound, true
	case "fix.server.refused", "fix.server.untestable_binary", "fix.server.major_upgrade", "fix.server.ambiguous", "fix.server.link":
		return http.StatusUnprocessableEntity, true
	}
	if strings.HasPrefix(key, "fix.server.") {
		return http.StatusConflict, true
	}
	return 0, false
}

// serverFindingOf reads the finding of the route's {finding} and checks it
// is a finding of the route's server; it answers 404 itself.
func (s *server) serverFindingOf(w http.ResponseWriter, r *http.Request, lang i18n.Lang, t target.Target) (scan.Finding, bool) {
	list, err := scan.NewRepo(s.deps.Store).ListServerFindings(r.Context(), t.ID)
	if err != nil {
		s.internal(w, r)
		return scan.Finding{}, false
	}
	id := r.PathValue("finding")
	for _, f := range list {
		if f.ID == id {
			return f, true
		}
	}
	s.failedBody(w, http.StatusNotFound, lang, "api.target.finding_not_found", "")
	return scan.Finding{}, false
}

// targetFix prepares Michel's own fix of a finding of the server (no agent,
// nothing written on the server): 202 with the attempt, in state proposed
// once it is ready, or the refusal in clear.
func (s *server) targetFix(w http.ResponseWriter, r *http.Request) {
	s.targetFixStart(w, r, false)
}

// targetAgentFix starts an agent on the masked inventory of the server for a
// finding Michel has no ready-made fix for. The agent never connects to the
// server.
func (s *server) targetAgentFix(w http.ResponseWriter, r *http.Request) {
	s.targetFixStart(w, r, true)
}

func (s *server) targetFixStart(w http.ResponseWriter, r *http.Request, withAgent bool) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	d, ok := s.fixDeps(w, r, lang)
	if !ok {
		return
	}
	t, ok := s.targetOf(w, r, lang)
	if !ok {
		return
	}
	f, ok := s.serverFindingOf(w, r, lang, t)
	if !ok {
		return
	}
	s.runServerFix(w, r, lang, d, f.ID, withAgent)
}

// runServerFix prepares the fix of a server finding (Michel's own, or the
// agent's) and answers 202 with the attempt, or the refusal.
func (s *server) runServerFix(w http.ResponseWriter, r *http.Request, lang i18n.Lang, d fix.Deps, findingID string, withAgent bool) {
	// The simulation of a package upgrade and the agent's start may outlast
	// the server's write timeout.
	extend(w)
	ctx, cancel := s.detached(r)
	defer cancel()
	var a fix.Attempt
	var err error
	if withAgent {
		a, err = fix.StartServerAgent(ctx, d, findingID)
	} else {
		a, err = fix.StartServer(ctx, d, findingID)
	}
	if err != nil {
		if fix.ErrorKey(err) == "" && a.ID != "" {
			s.answerStarted(w, r, a)
			return
		}
		if errors.Is(err, fix.ErrBusy) {
			s.serverBusyRefused(ctx, w, r, lang, d, findingID, err)
			return
		}
		s.fixRefused(w, r, lang, err, nil)
		return
	}
	s.answerStarted(w, r, a)
}

// serverBusyRefused says where the fix waits or runs. A server with a preprod
// starts there first, so only its preprod can be the busy one.
func (s *server) serverBusyRefused(ctx context.Context, w http.ResponseWriter, r *http.Request, lang i18n.Lang, d fix.Deps, findingID string, busy error) {
	t, err := fix.ServerOfFinding(ctx, d, findingID)
	if err != nil {
		s.fixRefused(w, r, lang, busy, nil)
		return
	}
	key, text := "fix.server.busy", i18n.T(lang, "fix.server.busy")
	if t.PreprodID != "" {
		name := t.PreprodID
		if pt, err := s.targets().Get(ctx, t.PreprodID); err == nil {
			name = srvText("", pt.Name)
		}
		key, text = "fix.server.busy_preprod", i18n.T(lang, "fix.server.busy_preprod", name)
	}
	writeJSON(w, http.StatusConflict, FixErrorBody{Error: text, Code: key})
}

// ---- the server's AI consent -----------------------------------------------------

// ServerConsentView is GET /targets/{id}/ai-consent: like a project's, for
// the agent that helps with a fix of this server.
type ServerConsentView struct {
	Target      TargetRef         `json:"target"`
	Consented   bool              `json:"consented"`
	GivenAt     string            `json:"given_at"`
	Ready       bool              `json:"ready"`
	Lines       []ConsentLineView `json:"lines"`
	Refusal     string            `json:"refusal,omitempty"`
	RefusalCode string            `json:"refusal_code,omitempty"`
	SwitchMode  bool              `json:"switch_mode"`
}

func (s *server) targetConsentView(ctx context.Context, d fix.Deps, t target.Target, lang i18n.Lang) (ServerConsentView, error) {
	at, consented, err := fix.ServerConsentAt(ctx, d, t.ID)
	if err != nil {
		return ServerConsentView{}, err
	}
	pol := s.currentPolicy()
	lines := fix.ServerConsentNeeded(t, pol, consented)
	v := ServerConsentView{Target: TargetRef{ID: t.ID, Name: srvText("", t.Name)}, Consented: consented, Ready: consented && len(lines) == 0,
		Lines: consentLines(lang, lines)}
	if consented {
		v.GivenAt = stamp(at)
	}
	switch {
	case t.Kind == target.KindHDS || t.Classification == policy.ClassHealth:
		v.Ready, v.RefusalCode = false, fix.ErrorKey(fix.ErrHealthForbidden)
		v.Refusal = fix.Explain(lang, fix.ErrHealthForbidden)
	case pol.Sovereignty.Mode == policy.ModeStrictLocal:
		v.Ready, v.RefusalCode, v.SwitchMode = false, fix.ErrorKey(fix.ErrStrictLocal), true
		v.Refusal = fix.Explain(lang, fix.ErrStrictLocal)
	}
	return v, nil
}

func (s *server) targetConsent(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	d, ok := s.fixDeps(w, r, lang)
	if !ok {
		return
	}
	t, ok := s.targetOf(w, r, lang)
	if !ok {
		return
	}
	v, err := s.targetConsentView(r.Context(), d, t, lang)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// targetConsentGive records the server's AI consent: the agent's allow rules
// go into the policy file, external providers are turned on when needed,
// and ai.consent is audited. A health server never gets one.
func (s *server) targetConsentGive(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var body struct {
		SwitchToStandard bool `json:"switch_to_standard"`
	}
	if !s.readBody(w, r, &body, true) {
		return
	}
	t, ok := s.targetOf(w, r, lang)
	if !ok {
		return
	}
	s.policyMu.Lock()
	d, ok := s.fixDeps(w, r, lang)
	if !ok {
		s.policyMu.Unlock()
		return
	}
	err := fix.GiveServerConsentWith(r.Context(), d, t.ID, fix.ConsentOptions{SwitchToStandard: body.SwitchToStandard})
	s.policyMu.Unlock()
	if err != nil {
		s.fixRefused(w, r, lang, err, nil)
		return
	}
	d, _ = s.fixDeps(w, r, lang)
	v, err := s.targetConsentView(r.Context(), d, t, lang)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// targetConsentRevoke forgets the server's consent: the agents on it stop and
// none starts without a new consent.
func (s *server) targetConsentRevoke(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	d, ok := s.fixDeps(w, r, lang)
	if !ok {
		return
	}
	t, ok := s.targetOf(w, r, lang)
	if !ok {
		return
	}
	if err := fix.RevokeServerConsent(r.Context(), d, t.ID); err != nil {
		s.fixRefused(w, r, lang, err, nil)
		return
	}
	v, err := s.targetConsentView(r.Context(), d, t, lang)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// ---- the user's two words about a server fix ------------------------------------

// fixSnapshotDone records the user's word that a snapshot of the server was
// made before a package upgrade: Approve refuses such a fix without it.
func (s *server) fixSnapshotDone(w http.ResponseWriter, r *http.Request) {
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
	if err := fix.SnapshotDone(r.Context(), d, a.ID, fixActor); err != nil {
		s.fixRefused(w, r, lang, err, nil)
		return
	}
	s.answerAttempt(w, r, http.StatusOK, a.ID)
}

// fixAppliedByMe is the user's word that they ran the apply script of an
// approved fix themselves: Michel then fetches the backups, checks the site
// and the server again.
func (s *server) fixAppliedByMe(w http.ResponseWriter, r *http.Request) {
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
	extend(w)
	ctx, cancel := s.detached(r)
	defer cancel()
	if err := fix.AppliedByMe(ctx, d, a.ID); err != nil {
		s.fixRefused(w, r, lang, err, nil)
		return
	}
	s.answerAttempt(w, r, http.StatusOK, a.ID)
}

// fixResolve is the user's word that they checked the server themselves after
// a fix whose outcome Michel could not tell (state unknown): the attempt ends
// failed, and the server can leave Michel.
func (s *server) fixResolve(w http.ResponseWriter, r *http.Request) {
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
	if err := fix.ResolveUnknown(r.Context(), d, a.ID, fixActor); err != nil {
		s.fixRefused(w, r, lang, err, nil)
		return
	}
	s.answerAttempt(w, r, http.StatusOK, a.ID)
}
