package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/feed"
	"github.com/kvarot/michel/internal/gitrepo"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sourceupdate"

	// The readers of each kind of source register themselves.
	_ "github.com/kvarot/michel/internal/sourceupdate/readers"
)

// sourceActor is the audit actor and the consent author of the changes
// made on the page.
const sourceActor = "api"

// longTimeout bounds the routes that read the network for the user (an
// update, a preview, an installation): synchronous, but never for ever.
const longTimeout = 5 * time.Minute

// maxItems is how many recent items the detail of a feed shows.
const maxItems = 10

func (s *server) sourceRoutes() {
	m := s.mux
	m.HandleFunc("GET /api/v1/sources", s.sourcesList)
	m.HandleFunc("POST /api/v1/sources", s.sourceAdd)
	m.HandleFunc("POST /api/v1/sources/reset", s.sourceReset)
	m.HandleFunc("POST /api/v1/sources/update", s.sourcesUpdate)
	m.HandleFunc("GET /api/v1/sources/items", s.sourceItems)
	m.HandleFunc("POST /api/v1/sources/items/{id}/read", s.sourceItemRead)
	m.HandleFunc("GET /api/v1/sources/discoveries", s.discoveries)
	m.HandleFunc("POST /api/v1/sources/discoveries/{owner}/{name}", s.discoveryAction)
	m.HandleFunc("GET /api/v1/sources/{key}", s.sourceDetail)
	m.HandleFunc("DELETE /api/v1/sources/{key}", s.sourceRemove)
	m.HandleFunc("POST /api/v1/sources/{key}/enable", s.sourceEnable)
	m.HandleFunc("POST /api/v1/sources/{key}/disable", s.sourceDisable)
	m.HandleFunc("POST /api/v1/sources/{key}/update", s.sourcesUpdate)
	m.HandleFunc("GET /api/v1/sources/{key}/preview", s.sourcePreview)
	m.HandleFunc("POST /api/v1/sources/{key}/install", s.sourceInstall)
	m.HandleFunc("POST /api/v1/sources/{key}/upgrade", s.sourceInstall)
	m.HandleFunc("POST /api/v1/sources/{key}/run", s.sourceRun)
	m.HandleFunc("GET /api/v1/plugin-runs/{id}", s.pluginRun)
	m.HandleFunc("GET /api/v1/tech", s.techList)
	m.HandleFunc("POST /api/v1/tech", s.techChange)
	m.HandleFunc("DELETE /api/v1/tech/{tag}", s.techChange)
}

// allowed says whether the gateway in force allows host for purpose.
func (s *server) allowed(host, purpose string) bool {
	ok, _ := s.deps.Sources.Gateway.Allowed(host, purpose)
	return ok
}

// state is the displayed state of e: a plugin is never waiting for consent
// (its hosts, if any, are asked when it is turned on). A reference with
// hosts (discover.github) follows the rule of the others, like the digest's
// catalog line; one without hosts cannot wait.
func (s *server) state(e source.Entry) source.State {
	st := e.State(s.allowed)
	if st == source.StateWaitingConsent && e.Kind == source.KindPlugin {
		return source.StateOn
	}
	return st
}

// reload reads the policy file again; the server keeps the new policy.
func (s *server) reload() (policy.Policy, error) {
	p, err := s.deps.Reload()
	if err == nil {
		s.mu.Lock()
		s.policy = p
		s.mu.Unlock()
	}
	return p, err
}

// consentDeps wires source.Enable and source.Disable: the policy file of the
// server receives the allow rules, the gateway learns them.
func (s *server) consentDeps() source.Deps {
	d := source.Deps{Repo: source.NewRepo(s.deps.Store), Audit: s.deps.Audit, Gateway: s.deps.Sources.Gateway,
		PolicyPath: s.deps.PolicyPath, Now: s.deps.Now, Actor: sourceActor}
	if s.deps.Reload != nil {
		d.Reload = s.reload
	}
	return d
}

// dataDir is the data folder: the configured one, else the store's.
func (s *server) dataDir() string {
	if s.deps.Sources.DataDir != "" {
		return s.deps.Sources.DataDir
	}
	return filepath.Dir(s.deps.Store.Path())
}

// record writes an audit event of the source routes: keys and counts only.
func (s *server) record(ctx context.Context, action, target, result string, ev map[string]any) error {
	_, err := s.deps.Audit.Record(ctx, audit.Event{Actor: sourceActor, Action: action, Target: target, Result: result, Evidence: ev})
	return err
}

// auditFailed answers 500: the change is made but the audit log refused it.
func (s *server) auditFailed(w http.ResponseWriter, r *http.Request) {
	s.fail(w, http.StatusInternalServerError, i18n.T(s.answerLang(r), "api.source.audit_failed"), i18n.T(s.answerLang(r), "api.internal_hint"))
}

// failed answers 500 with the cause, without any local path.
func (s *server) failed(w http.ResponseWriter, r *http.Request, key string, err error) {
	s.fail(w, http.StatusInternalServerError, i18n.T(s.answerLang(r), "api.source.failed", key, noPaths(err.Error())), i18n.T(s.answerLang(r), "api.internal_hint"))
}

// readBody decodes the JSON body of a source route into v; an empty body is
// an empty object when optional.
func (s *server) readBody(w http.ResponseWriter, r *http.Request, v any, optional bool) bool {
	if optional && r.ContentLength == 0 {
		return true
	}
	return s.readJSONHint(w, r, v, i18n.T(s.answerLang(r), "api.source.bad_json_hint"))
}

// extend lets a long route write its answer after the server's write
// timeout.
func extend(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(longTimeout + time.Minute))
}

// entry reads the source of the route's {key}; it answers 404 itself.
func (s *server) entry(w http.ResponseWriter, r *http.Request) (source.Entry, bool) {
	e, err := source.NewRepo(s.deps.Store).Get(r.Context(), r.PathValue("key"))
	switch {
	case errors.Is(err, source.ErrNotFound):
		s.fail(w, http.StatusNotFound, i18n.T(s.answerLang(r), "api.source.not_found"), "")
		return source.Entry{}, false
	case err != nil:
		s.internal(w, r)
		return source.Entry{}, false
	}
	return e, true
}

// configView is the merged settings of e that the page may show.
func configView(e source.Entry) map[string]any {
	out := map[string]any{}
	for k, v := range e.Config.Merged() {
		if strings.HasSuffix(k, "_secret") || k == "install_dir" || k == "input" || k == "launch" {
			continue
		}
		if str, ok := v.(string); ok {
			if filepath.IsAbs(str) || strings.HasPrefix(str, "/") || strings.HasPrefix(str, `\`) {
				continue
			}
			v = scan.SanitizeText(str)
		}
		out[k] = v
	}
	switch e.Kind {
	case source.KindSkill, source.KindMCP:
		out["installed"] = e.Config.Str("installed_sha") != ""
	case source.KindPlugin:
		out["has_input"] = e.Config.Str("input") != ""
	}
	return out
}

// statusView is the repository status of e, its texts cleaned.
func statusView(st map[string]any) map[string]any {
	out := make(map[string]any, len(st))
	for k, v := range st {
		if str, ok := v.(string); ok {
			v = scan.SanitizeText(str)
		}
		out[k] = v
	}
	return out
}

// badges are the marks of e: new_version, suggested (a feed off whose
// technology is declared or detected), archived.
func badges(e source.Entry, declared []string) []string {
	out := []string{}
	if _, _, ok := e.NewVersion(); ok {
		out = append(out, "new_version")
	}
	if e.Kind == source.KindFeed && !e.Enabled && !e.Hidden && slices.ContainsFunc(e.Tech, func(t string) bool { return slices.Contains(declared, t) }) {
		out = append(out, "suggested")
	}
	if a, _ := e.Status["archived"].(bool); a {
		out = append(out, "archived")
	}
	return out
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// sourceView builds the view of e in lang; declared are the technologies in
// use (for the suggested badge).
func (s *server) sourceView(e source.Entry, lang i18n.Lang, declared []string) SourceView {
	v := SourceView{Key: e.Key, Kind: string(e.Kind), Origin: string(e.Origin), Name: scan.SanitizeText(e.Name), URL: scan.SanitizeText(e.URL),
		Hosts: append([]string{}, e.Hosts...), Purpose: e.Purpose, State: string(s.state(e)), Enabled: e.Enabled, Hidden: e.Hidden,
		Tech: append([]string{}, e.Tech...), Config: configView(e), Status: statusView(e.Status), Badges: badges(e, declared),
		LastRead: LastReadView{At: stamp(e.LastReadAt), Result: e.LastReadResult, Error: noPaths(e.LastReadError), Items: e.LastReadItems}}
	if note := source.NoteKey(e.Key); e.Origin == source.OriginCatalog && i18n.Has(note) {
		v.Note = i18n.T(lang, note)
	}
	return v
}

// viewOf reads key again and answers its view with status.
func (s *server) viewOf(w http.ResponseWriter, r *http.Request, status int, key string, lang i18n.Lang) {
	e, err := source.NewRepo(s.deps.Store).Get(r.Context(), key)
	if err != nil {
		s.internal(w, r)
		return
	}
	declared, err := feed.DeclaredAll(r.Context(), s.deps.Store)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, status, s.sourceView(e, lang, declared))
}

func (s *server) sourcesList(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	kind := source.Kind(strings.TrimSpace(q.Get("kind")))
	if kind != "" && !kind.Valid() {
		names := make([]string, 0, len(source.Kinds))
		for _, k := range source.Kinds {
			names = append(names, string(k))
		}
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.source.bad_kind"), i18n.T(lang, "api.bad_status_hint", strings.Join(names, ", ")))
		return
	}
	all := q.Get("all") == "1" || q.Get("all") == "true"
	list, err := source.NewRepo(s.deps.Store).List(r.Context(), kind, all)
	if err != nil {
		s.internal(w, r)
		return
	}
	declared, err := feed.DeclaredAll(r.Context(), s.deps.Store)
	if err != nil {
		s.internal(w, r)
		return
	}
	out := make([]SourceView, 0, len(list))
	for _, e := range list {
		out = append(out, s.sourceView(e, lang, declared))
	}
	writeJSON(w, http.StatusOK, out)
}

// rule is the allow rule of a host, as written in the policy file.
func rule(host, purpose string) string {
	return fmt.Sprintf("{host: %s, purpose: %s}", host, purpose)
}

func (s *server) sourceDetail(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	e, ok := s.entry(w, r)
	if !ok {
		return
	}
	declared, err := feed.DeclaredAll(r.Context(), s.deps.Store)
	if err != nil {
		s.internal(w, r)
		return
	}
	d := SourceDetailView{SourceView: s.sourceView(e, lang, declared), Rules: []HostRuleView{}, Items: []ReadingView{}}
	for _, h := range e.Hosts {
		d.Rules = append(d.Rules, HostRuleView{Host: h, Purpose: e.Purpose, Rule: rule(h, e.Purpose), Allowed: s.allowed(h, e.Purpose)})
	}
	if e.Kind == source.KindFeed {
		items, err := feed.NewRepo(s.deps.Store).List(r.Context(), time.Time{}, false)
		if err != nil {
			s.internal(w, r)
			return
		}
		for _, it := range items {
			if it.SourceKey == e.Key && len(d.Items) < maxItems {
				d.Items = append(d.Items, readingView(it, lang))
			}
		}
	}
	writeJSON(w, http.StatusOK, d)
}

// EnableRequest is the body of POST /sources/{key}/enable.
type EnableRequest struct {
	Consent bool `json:"consent"`
}

func (s *server) sourceEnable(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req EnableRequest
	if !s.readBody(w, r, &req, true) {
		return
	}
	key := r.PathValue("key")
	texts, err := s.enable(r.Context(), key, req.Consent)
	switch {
	case errors.Is(err, source.ErrConsentRequired):
		body := ConsentBody{Error: i18n.T(lang, "api.source.consent_needed"), Hint: i18n.T(lang, "api.source.consent_needed_hint"), Consent: []ConsentView{}}
		for _, t := range texts {
			body.Consent = append(body.Consent, ConsentView{Host: t.Host, Purpose: t.Purpose, What: i18n.T(lang, t.What, t.Host), Rule: rule(t.Host, t.Purpose)})
		}
		writeJSON(w, http.StatusConflict, body)
		return
	case errors.Is(err, source.ErrNotFound):
		s.fail(w, http.StatusNotFound, i18n.T(lang, "api.source.not_found"), "")
		return
	case err != nil:
		s.failed(w, r, key, err)
		return
	}
	s.viewOf(w, r, http.StatusOK, key, lang)
}

// enable and disable change a source and the policy file it writes, one
// change at a time.
func (s *server) enable(ctx context.Context, key string, consent bool) ([]source.ConsentText, error) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	_, texts, err := source.Enable(ctx, s.consentDeps(), key, consent)
	return texts, err
}

func (s *server) disable(ctx context.Context, key string, forget bool) error {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	return source.Disable(ctx, s.consentDeps(), key, forget)
}

// DisableRequest is the body of POST /sources/{key}/disable.
type DisableRequest struct {
	Forget bool `json:"forget"`
}

func (s *server) sourceDisable(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req DisableRequest
	if !s.readBody(w, r, &req, true) {
		return
	}
	key := r.PathValue("key")
	err := s.disable(r.Context(), key, req.Forget)
	var shared source.ErrRuleShared
	switch {
	case errors.As(err, &shared):
		s.fail(w, http.StatusConflict, i18n.T(lang, "cli.source.disable.shared", key, shared.Key, shared.Key), "")
		return
	case errors.Is(err, source.ErrNotFound):
		s.fail(w, http.StatusNotFound, i18n.T(lang, "api.source.not_found"), "")
		return
	case err != nil:
		s.failed(w, r, key, err)
		return
	}
	s.viewOf(w, r, http.StatusOK, key, lang)
}

// AddSourceRequest is the body of POST /sources: the same fields as michel
// source add. Input is the full path of a plugin's fixed report.
type AddSourceRequest struct {
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	Format    string   `json:"format"`
	Repo      string   `json:"repo"`
	Ecosystem string   `json:"ecosystem"`
	Input     string   `json:"input"`
	Tool      string   `json:"tool"`
	Path      string   `json:"path"`
	Pin       string   `json:"pin"`
	Tech      []string `json:"tech"`
}

// addEntry stores a new user entry, runs after (nil for nothing; a
// discovery marks itself added), audits it and answers its view; from says
// where it comes from ("" for the form). It answers the request itself.
func (s *server) addEntry(w http.ResponseWriter, r *http.Request, lang i18n.Lang, e source.Entry, from string, after func() error) {
	repo := source.NewRepo(s.deps.Store)
	refused := i18n.T(lang, "api.source.add.refused")
	if _, err := repo.Get(r.Context(), e.Key); err == nil {
		s.fail(w, http.StatusConflict, refused, i18n.T(lang, "api.source.add.exists", e.Key))
		return
	} else if !errors.Is(err, source.ErrNotFound) {
		s.internal(w, r)
		return
	}
	added, err := repo.Upsert(r.Context(), e)
	if err != nil {
		s.fail(w, http.StatusBadRequest, refused, noPaths(err.Error()))
		return
	}
	if after != nil {
		if err := after(); err != nil {
			s.failed(w, r, added.Key, err)
			return
		}
	}
	ev := map[string]any{"key": added.Key, "kind": string(added.Kind)}
	if from != "" {
		ev["from"] = from
	}
	if err := s.record(r.Context(), "source.add", added.Key, "ok", ev); err != nil {
		s.auditFailed(w, r)
		return
	}
	s.viewOf(w, r, http.StatusCreated, added.Key, lang)
}

// refusalText is the reason of a refused user entry (source.NewUserEntry),
// in lang and without the command line's flags.
func refusalText(lang i18n.Lang, r *source.Refusal) string {
	switch r.Code {
	case "bad_tag":
		return i18n.T(lang, "cli.tech.bad_tag", r.Args...)
	case "bad_url":
		return i18n.T(lang, "cli.source.add.bad_url", r.Args...)
	case "bad_format":
		return i18n.T(lang, "cli.source.add.bad_format", r.Args...)
	case "bad_repo":
		return i18n.T(lang, "cli.source.add.bad_repo", r.Args...)
	case "feed_target":
		return i18n.T(lang, "api.source.add.feed_target")
	case "no_ecosystem":
		return i18n.T(lang, "api.source.add.no_ecosystem")
	case "bad_ecosystem":
		return i18n.T(lang, "cli.source.add.bad_ecosystem", r.Args...)
	case "no_format":
		return i18n.T(lang, "api.source.add.no_format")
	case "bad_tool":
		return i18n.T(lang, "cli.source.add.bad_tool", r.Args...)
	case "no_name":
		return i18n.T(lang, "api.source.add.no_name")
	case "bad_input":
		return i18n.T(lang, "api.source.add.bad_input")
	case "no_repo":
		return i18n.T(lang, "api.source.add.no_repo", r.Args...)
	case "bad_pin":
		return i18n.T(lang, "cli.source.add.bad_pin", r.Args...)
	case "bad_path":
		return i18n.T(lang, "cli.source.add.bad_path", r.Args...)
	case "bad_kind":
		return i18n.T(lang, "cli.source.add.bad_kind", r.Args...)
	}
	return r.Code
}

func (s *server) sourceAdd(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req AddSourceRequest
	if !s.readBody(w, r, &req, false) {
		return
	}
	e, refusal := source.NewUserEntry(source.UserEntryRequest{Kind: source.Kind(strings.TrimSpace(req.Kind)), Name: req.Name, URL: req.URL,
		Format: req.Format, Repo: req.Repo, Ecosystem: req.Ecosystem, Input: req.Input, Tool: req.Tool, Path: req.Path, Pin: req.Pin, Tech: req.Tech})
	if refusal != nil {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.source.add.refused"), refusalText(lang, refusal))
		return
	}
	s.addEntry(w, r, lang, e, "", nil)
}

// RemoveRequest is the optional body of DELETE /sources/{key}: confirm
// uninstalls an installed skill or MCP server first.
type RemoveRequest struct {
	Confirm bool `json:"confirm"`
}

func (s *server) sourceRemove(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req RemoveRequest
	if !s.readBody(w, r, &req, true) {
		return
	}
	e, ok := s.entry(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if e.Config.Str("installed_sha") != "" {
		if !req.Confirm {
			s.fail(w, http.StatusConflict, i18n.T(lang, "api.source.remove.confirm", e.Key), i18n.T(lang, "api.source.remove.confirm_hint"))
			return
		}
		gd, err := s.repoDeps(ctx)
		if err != nil {
			s.failed(w, r, e.Key, err)
			return
		}
		if err := gitrepo.Uninstall(ctx, gd, e); err != nil {
			if errors.Is(err, gitrepo.ErrForeignDir) {
				s.fail(w, http.StatusConflict, i18n.T(lang, "cli.source.remove.foreign", e.Key), "")
				return
			}
			s.failed(w, r, e.Key, err)
			return
		}
	}
	repo := source.NewRepo(s.deps.Store)
	mode, err := "hidden", error(nil)
	if e.Origin == source.OriginUser {
		mode, err = "deleted", repo.Delete(ctx, e.Key)
	} else {
		err = repo.SetHidden(ctx, e.Key, true)
	}
	if err != nil {
		s.failed(w, r, e.Key, err)
		return
	}
	if err := s.record(ctx, "source.remove", e.Key, "ok", map[string]any{"key": e.Key, "mode": mode}); err != nil {
		s.auditFailed(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"key": e.Key, "mode": mode})
}

// ResetRequest is the body of POST /sources/reset: a key, or all.
type ResetRequest struct {
	Key string `json:"key"`
	All bool   `json:"all"`
}

func (s *server) sourceReset(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req ResetRequest
	if !s.readBody(w, r, &req, false) {
		return
	}
	req.Key = strings.TrimSpace(req.Key)
	if (req.Key != "") == req.All {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.source.reset.usage"), "")
		return
	}
	n, err := source.Reset(r.Context(), source.NewRepo(s.deps.Store), req.Key, req.All, false)
	switch {
	case errors.Is(err, source.ErrUserEntry):
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.source.reset.user", req.Key), "")
		return
	case errors.Is(err, source.ErrNotFound):
		s.fail(w, http.StatusNotFound, i18n.T(lang, "api.source.not_found"), "")
		return
	case err != nil:
		s.failed(w, r, req.Key, err)
		return
	}
	target := req.Key
	if req.All {
		target = "all"
	}
	if err := s.record(r.Context(), "source.reset", target, "ok", map[string]any{"key": target, "purge_user": false, "count": n}); err != nil {
		s.auditFailed(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": n})
}

// UpdateView is the outcome of POST /sources/update (every enabled source)
// or /sources/{key}/update (Source is then the source read). Errors maps a
// failed key to its error, in English, without any local path.
type UpdateView struct {
	Updated        []string          `json:"updated"`
	WaitingConsent []string          `json:"waiting_consent"`
	Failed         []string          `json:"failed"`
	Skipped        []string          `json:"skipped"`
	SkipReasons    map[string]string `json:"skip_reasons"`
	Errors         map[string]string `json:"errors"`
	Source         *SourceView       `json:"source,omitempty"`
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// updateView is the view of an update report: its errors and reasons
// without any local path.
func updateView(rep sourceupdate.Report) UpdateView {
	v := UpdateView{Updated: nonNil(rep.Updated), WaitingConsent: nonNil(rep.WaitingConsent), Failed: nonNil(rep.Failed), Skipped: nonNil(rep.Skipped),
		SkipReasons: map[string]string{}, Errors: map[string]string{}}
	for k, reason := range rep.SkipReasons {
		v.SkipReasons[k] = noPaths(reason)
	}
	for k, e := range rep.Errors {
		v.Errors[k] = noPaths(e)
	}
	return v
}

func (s *server) sourcesUpdate(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var keys []string
	if r.PathValue("key") != "" {
		e, ok := s.entry(w, r)
		if !ok {
			return
		}
		keys = []string{e.Key}
	}
	if !s.updating.TryLock() {
		s.fail(w, http.StatusConflict, i18n.T(lang, "api.source.update.busy"), "")
		return
	}
	defer s.updating.Unlock()
	extend(w)
	ctx, cancel := context.WithTimeout(r.Context(), longTimeout)
	defer cancel()
	repo := source.NewRepo(s.deps.Store)
	rep, err := sourceupdate.Run(ctx, sourceupdate.Deps{Store: s.deps.Store, Repo: repo, Audit: s.deps.Audit, Gateway: s.deps.Sources.Gateway,
		Secrets: s.deps.Secrets, OSVRoot: s.deps.OSVRoot, Now: s.deps.Now, Budget: sourceupdate.BudgetFor(s.deps.Secrets), Actor: sourceActor}, keys, "")
	if err != nil && !errors.Is(err, sourceupdate.ErrSomeFailed) {
		s.failed(w, r, strings.Join(keys, ", "), err)
		return
	}
	v := updateView(rep)
	if len(keys) == 1 {
		e, err := repo.Get(r.Context(), keys[0])
		if err != nil {
			s.internal(w, r)
			return
		}
		declared, err := feed.DeclaredAll(r.Context(), s.deps.Store)
		if err != nil {
			s.internal(w, r)
			return
		}
		sv := s.sourceView(e, lang, declared)
		v.Source = &sv
	}
	writeJSON(w, http.StatusOK, v)
}

// todayView adds to the digest the catalog line in lang and the number of
// repositories to discover.
func todayView(d digest.Digest, lang i18n.Lang) TodayView {
	v := TodayView{Digest: d, Catalog: CatalogView{Catalog: d.Catalog}, DiscoverNew: d.Catalog.DiscoverNew}
	if !d.Catalog.Silent {
		v.Catalog.Line = digest.CatalogLine(lang, d.Catalog)
	}
	return v
}
