package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/workcopy"
)

// GitView is how a project stands with its Git service (fix.GitState). It holds no
// absolute path and no secret, and reading it starts neither network nor write.
type GitView struct {
	Repo          string         `json:"repo"`
	Answer        string         `json:"answer"`
	Attached      bool           `json:"attached"`
	Changed       bool           `json:"changed"`
	Suggested     string         `json:"suggested"`
	Reason        string         `json:"reason"`
	Provider      string         `json:"provider"`
	Display       string         `json:"display"`
	Host          string         `json:"host"`
	RemoteID      string         `json:"remote_id"`
	HadCredential bool           `json:"had_credential"`
	CanAttach     bool           `json:"can_attach"`
	Update        *GitUpdateView `json:"update"`
}

// GitUpdateView says whether the update button would work now.
type GitUpdateView struct {
	Ready   bool   `json:"ready"`
	Current string `json:"current"`
	Default string `json:"default"`
	Code    string `json:"code"`
	Why     string `json:"why"`
}

// GitViewRefused is the refusal of GET /projects/{name}/git: the folder cannot be
// read, and the person can still see and change what they answered.
type GitViewRefused struct {
	FixErrorBody
	Answer string `json:"answer"`
}

// GitAnswerRequest is the body of POST /projects/{name}/git/answer. RemoteID is the
// address shown when the person said yes.
type GitAnswerRequest struct {
	Answer   string `json:"answer"`
	RemoteID string `json:"remote_id"`
}

// GitPushResponse is the answer to a click on the send button.
type GitPushResponse struct {
	Outcome  string `json:"outcome"`
	Provider string `json:"provider"`
	Branch   string `json:"branch"`
	MergeURL string `json:"merge_url"`
	PushedAt string `json:"pushed_at"`
}

// GitUpdateResponse is the answer to a click on the update button.
type GitUpdateResponse struct {
	Outcome string `json:"outcome"`
}

func gitView(st fix.GitState) GitView {
	v := GitView{Repo: st.Repo, Answer: st.Answer, Attached: st.Attached, Changed: st.Changed, Suggested: st.Suggested,
		Reason: st.Reason, Provider: st.Provider, Display: st.Display, Host: st.Host, RemoteID: st.RemoteID,
		HadCredential: st.HadCredential, CanAttach: st.CanAttach}
	if u := st.Update; u != nil {
		v.Update = &GitUpdateView{Ready: u.Ready, Current: u.Current, Default: u.Default, Code: u.Code, Why: u.Why}
	}
	return v
}

// gitRefused answers a refusal of a click: 409 for what Michel refused, 502 for
// what the service answered or did not answer, never 401 nor 403, which the page
// takes for a wrong token. Any other error is a 500 without its cause.
func (s *server) gitRefused(w http.ResponseWriter, r *http.Request, lang i18n.Lang, err error) {
	status, body, known := gitRefusal(lang, err)
	if !known {
		s.internal(w, r)
		return
	}
	writeJSON(w, status, body)
}

// gitRefusal is the status and body of a refusal; known is false for any other error.
func gitRefusal(lang i18n.Lang, err error) (status int, body FixErrorBody, known bool) {
	key := fix.ErrorKey(err)
	if key == "" {
		return 0, FixErrorBody{}, false
	}
	status = http.StatusConflict
	var gf *workcopy.GitFailure
	if errors.As(err, &gf) && fix.GitServiceFailure(gf.Class) {
		status = http.StatusBadGateway
	}
	return status, FixErrorBody{Error: fix.Explain(lang, err), Hint: fix.ExplainHint(lang, err), Code: key}, true
}

// gitProject reads the fix service's collaborators and the project of the route.
func (s *server) gitProject(w http.ResponseWriter, r *http.Request, lang i18n.Lang) (fix.Deps, project.Project, bool) {
	d, ok := s.fixDeps(w, r, lang)
	if !ok {
		return fix.Deps{}, project.Project{}, false
	}
	p, found, err := s.activeProject(r.Context(), r.PathValue("name"))
	if err != nil {
		s.internal(w, r)
		return fix.Deps{}, project.Project{}, false
	}
	if !found {
		s.fail(w, http.StatusNotFound, i18n.T(lang, "api.project_not_found"), "")
		return fix.Deps{}, project.Project{}, false
	}
	return d, p, true
}

// projectGit is GET /projects/{name}/git: read at each look, no network, no write.
func (s *server) projectGit(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	d, p, ok := s.gitProject(w, r, lang)
	if !ok {
		return
	}
	st, err := fix.ProjectGit(r.Context(), d, p)
	if err != nil {
		if status, body, known := gitRefusal(lang, err); known {
			writeJSON(w, status, GitViewRefused{FixErrorBody: body, Answer: st.Answer})
			return
		}
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, gitView(st))
}

// projectGitAnswer records the answer to the question on the project's page.
func (s *server) projectGitAnswer(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req GitAnswerRequest
	if !s.readJSONHint(w, r, &req, i18n.T(lang, "api.git.bad_answer_hint")) {
		return
	}
	req.Answer, req.RemoteID = strings.TrimSpace(req.Answer), strings.TrimSpace(req.RemoteID)
	if req.Answer != fix.GitYes && req.Answer != fix.GitNo && req.Answer != fix.GitUnknown || (req.Answer == fix.GitYes && req.RemoteID == "") {
		s.failedBody(w, http.StatusBadRequest, lang, "api.git.bad_answer", "api.git.bad_answer_hint")
		return
	}
	d, p, ok := s.gitProject(w, r, lang)
	if !ok {
		return
	}
	// The answer changes a rule and a row together: it ends even if the page goes
	// away, like fixApprove.
	extend(w)
	ctx, cancel := s.detached(r)
	defer cancel()
	st, err := fix.AnswerGit(ctx, d, p, req.Answer, req.RemoteID)
	if err != nil {
		s.gitRefused(w, r, lang, err)
		return
	}
	writeJSON(w, http.StatusOK, gitView(st))
}

// fixPush sends the fix branch: one click, one send, and the work goes on if the
// page goes away, like fixApprove.
func (s *server) fixPush(w http.ResponseWriter, r *http.Request) {
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
	out, err := fix.PushFix(ctx, d, a.ID)
	if err != nil {
		s.gitRefused(w, r, lang, err)
		return
	}
	writeJSON(w, http.StatusOK, GitPushResponse{Outcome: out.Outcome, Provider: out.Provider, Branch: out.Branch,
		MergeURL: out.MergeURL, PushedAt: stamp(out.At)})
}

// projectGitUpdate brings the folder up to date: one click, and the work goes on if
// the page goes away, like fixApprove.
func (s *server) projectGitUpdate(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	d, p, ok := s.gitProject(w, r, lang)
	if !ok {
		return
	}
	extend(w)
	ctx, cancel := s.detached(r)
	defer cancel()
	res, err := fix.UpdateProject(ctx, d, p)
	if err != nil {
		s.gitRefused(w, r, lang, err)
		return
	}
	writeJSON(w, http.StatusOK, GitUpdateResponse{Outcome: res.Outcome})
}
