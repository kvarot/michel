package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/feed"
	"github.com/kvarot/michel/internal/gitrepo"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/plugin"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
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

var (
	repoName  = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	commitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// repoHosts are the hosts of a pinned repository: its state and its archive.
var repoHosts = []string{"api.github.com", "codeload.github.com"}

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

// state is the displayed state of e: a plugin or a reference is never
// waiting for consent (their hosts, if any, are asked when they are turned
// on).
func (s *server) state(e source.Entry) source.State {
	st := e.State(s.allowed)
	if st == source.StateWaitingConsent && (e.Kind == source.KindPlugin || e.Kind == source.KindReference) {
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

// readingView is the view of a feed item in lang.
func readingView(it feed.Item, lang i18n.Lang) ReadingView {
	date := it.PublishedAt
	if date == "" {
		date = it.SeenAt
	}
	tech := it.Tech
	if tech == nil {
		tech = []string{}
	}
	return ReadingView{ID: it.ID, SourceKey: it.SourceKey, Source: scan.SanitizeText(it.SourceName), Title: scan.SanitizeText(feed.Title(lang, it)),
		URL: scan.SanitizeText(it.URL), PublishedAt: date, Tech: tech, Read: it.ReadAt != ""}
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
	_, texts, err := source.Enable(r.Context(), s.consentDeps(), key, req.Consent)
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
	err := source.Disable(r.Context(), s.consentDeps(), key, req.Forget)
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

// cleanRepoPath checks a folder inside a repository and returns it in slash
// form: relative, no "..", no backslash or drive.
func cleanRepoPath(p string) (string, bool) {
	if strings.ContainsAny(p, `\:`) || filepath.IsAbs(p) || strings.HasPrefix(p, "/") {
		return "", false
	}
	clean := filepath.ToSlash(filepath.Clean(p))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}

// cleanTech trims and deduplicates the technology tags.
func cleanTech(in []string) []string {
	out := []string{}
	for _, t := range in {
		if t = strings.TrimSpace(t); t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// newEntry builds the user entry of req, mirroring michel source add. On a
// refusal it returns the reason in lang ("" when the entry is valid).
func newEntry(lang i18n.Lang, req AddSourceRequest) (source.Entry, string) {
	kind, format := strings.TrimSpace(req.Kind), strings.TrimSpace(req.Format)
	e := source.Entry{Kind: source.Kind(kind), Origin: source.OriginUser, Name: strings.TrimSpace(req.Name), Tech: cleanTech(req.Tech)}
	for _, t := range e.Tech {
		if !project.ValidTech(t) {
			return e, i18n.T(lang, "cli.tech.bad_tag", t)
		}
	}
	user := map[string]any{}
	switch e.Kind {
	case source.KindFeed:
		switch {
		case req.URL != "":
			u, err := url.Parse(req.URL)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
				return e, i18n.T(lang, "cli.source.add.bad_url", req.URL)
			}
			if format == "" {
				format = "auto"
			}
			if !slices.Contains([]string{"auto", "rss", "atom", "page"}, format) {
				return e, i18n.T(lang, "cli.source.add.bad_format", format, kind, "auto, rss, atom, page")
			}
			e.URL, e.Hosts = req.URL, []string{u.Hostname()}
			if e.Name == "" {
				e.Name = u.Hostname()
			}
		case req.Repo != "" && format == "github_advisories":
			if !repoName.MatchString(req.Repo) {
				return e, i18n.T(lang, "cli.source.add.bad_repo", req.Repo)
			}
			e.URL, e.Hosts = "https://github.com/"+req.Repo+"/security/advisories", []string{"api.github.com"}
			user["repo"] = req.Repo
			if e.Name == "" {
				e.Name = req.Repo
			}
		default:
			return e, i18n.T(lang, "api.source.add.feed_target")
		}
		e.Purpose = policy.PurposeFeed
		user["format"] = format
	case source.KindOSV:
		eco := strings.TrimSpace(req.Ecosystem)
		if eco == "" {
			return e, i18n.T(lang, "api.source.add.no_ecosystem")
		}
		if strings.ContainsAny(eco, `/\`) || strings.Contains(eco, "..") || len(eco) > 64 {
			return e, i18n.T(lang, "cli.source.add.bad_ecosystem", eco)
		}
		e.Name, e.URL = "OSV "+eco, "https://osv.dev/list?ecosystem="+url.QueryEscape(eco)
		e.Hosts, e.Purpose = []string{"osv-vulnerabilities.storage.googleapis.com"}, policy.PurposeOSV
		user["ecosystem"] = eco
		e.Key = source.KeyFor(source.KindOSV, eco)
	case source.KindPlugin:
		if format == "" {
			return e, i18n.T(lang, "api.source.add.no_format")
		}
		if format != "sarif" && format != "trivy_json" {
			return e, i18n.T(lang, "cli.source.add.bad_format", format, kind, "sarif, trivy_json")
		}
		tool := strings.TrimSpace(req.Tool)
		if tool == "" {
			tool = "generic"
		}
		if !slices.Contains([]string{"generic", "trivy", "semgrep", "codeql", "zap"}, tool) {
			return e, i18n.T(lang, "cli.source.add.bad_tool", tool)
		}
		if e.Name == "" {
			return e, i18n.T(lang, "api.source.add.no_name")
		}
		user["format"], user["tool"], user["run"] = format, tool, false
		if in := strings.TrimSpace(req.Input); in != "" {
			if !filepath.IsAbs(in) {
				return e, i18n.T(lang, "api.source.add.bad_input")
			}
			user["input"] = filepath.Clean(in)
		}
	case source.KindSkill, source.KindMCP:
		if req.Repo == "" || req.Pin == "" {
			return e, i18n.T(lang, "api.source.add.no_repo", kind)
		}
		if !repoName.MatchString(req.Repo) {
			return e, i18n.T(lang, "cli.source.add.bad_repo", req.Repo)
		}
		if !commitSHA.MatchString(req.Pin) {
			return e, i18n.T(lang, "cli.source.add.bad_pin", req.Pin)
		}
		user["repo"], user["pinned"] = req.Repo, req.Pin
		if req.Path != "" {
			clean, ok := cleanRepoPath(req.Path)
			if !ok {
				return e, i18n.T(lang, "cli.source.add.bad_path", req.Path)
			}
			user["path"] = clean
		}
		if e.Name == "" {
			e.Name = req.Repo[strings.Index(req.Repo, "/")+1:]
		}
		e.URL, e.Hosts, e.Purpose = "https://github.com/"+req.Repo, repoHosts, policy.PurposeRepo
	default:
		return e, i18n.T(lang, "cli.source.add.bad_kind", kind)
	}
	if e.Key == "" {
		e.Key = source.KeyFor(e.Kind, e.Name)
	}
	if !source.ValidKey(e.Key) {
		return e, i18n.T(lang, "api.source.add.no_name")
	}
	e.Config = source.Config{Catalog: map[string]any{}, User: user}
	return e, ""
}

// addEntry stores a new user entry and audits it; from says where it comes
// from ("" for the form). It answers the request itself.
func (s *server) addEntry(w http.ResponseWriter, r *http.Request, lang i18n.Lang, e source.Entry, from string) bool {
	repo := source.NewRepo(s.deps.Store)
	refused := i18n.T(lang, "api.source.add.refused")
	if _, err := repo.Get(r.Context(), e.Key); err == nil {
		s.fail(w, http.StatusConflict, refused, i18n.T(lang, "api.source.add.exists", e.Key))
		return false
	} else if !errors.Is(err, source.ErrNotFound) {
		s.internal(w, r)
		return false
	}
	added, err := repo.Upsert(r.Context(), e)
	if err != nil {
		s.fail(w, http.StatusBadRequest, refused, noPaths(err.Error()))
		return false
	}
	ev := map[string]any{"key": added.Key, "kind": string(added.Kind)}
	if from != "" {
		ev["from"] = from
	}
	if err := s.record(r.Context(), "source.add", added.Key, "ok", ev); err != nil {
		s.auditFailed(w, r)
		return false
	}
	s.viewOf(w, r, http.StatusCreated, added.Key, lang)
	return true
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
	e, reason := newEntry(lang, req)
	if reason != "" {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.source.add.refused"), reason)
		return
	}
	s.addEntry(w, r, lang, e, "")
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
	budget := sourceupdate.BudgetWithoutToken
	if s.deps.Secrets != nil {
		if _, err := s.deps.Secrets.Get(gitrepo.GitHubTokenSecret); err == nil {
			budget = sourceupdate.BudgetWithToken
		}
	}
	repo := source.NewRepo(s.deps.Store)
	rep, err := sourceupdate.Run(ctx, sourceupdate.Deps{Store: s.deps.Store, Repo: repo, Audit: s.deps.Audit, Gateway: s.deps.Sources.Gateway,
		Secrets: s.deps.Secrets, OSVRoot: s.deps.OSVRoot, Now: s.deps.Now, Budget: &sourceupdate.Budget{Remaining: budget}, Actor: sourceActor}, keys, "")
	if err != nil && !errors.Is(err, sourceupdate.ErrSomeFailed) {
		s.failed(w, r, strings.Join(keys, ", "), err)
		return
	}
	v := UpdateView{Updated: nonNil(rep.Updated), WaitingConsent: nonNil(rep.WaitingConsent), Failed: nonNil(rep.Failed), Skipped: nonNil(rep.Skipped),
		SkipReasons: map[string]string{}, Errors: map[string]string{}}
	for k, reason := range rep.SkipReasons {
		v.SkipReasons[k] = reason
	}
	for k, e := range rep.Errors {
		v.Errors[k] = noPaths(e)
	}
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

// repoDeps wires the installation of skills and MCP servers, like the
// command line: the archive client (purpose source.repo), the skills folder
// and the folders of the scanned projects, where Michel never writes.
func (s *server) repoDeps(ctx context.Context) (gitrepo.Deps, error) {
	skills, err := gitrepo.DefaultSkillsDir()
	if err != nil {
		return gitrepo.Deps{}, err
	}
	projects, err := project.NewRepo(s.deps.Store).List(ctx)
	if err != nil {
		return gitrepo.Deps{}, err
	}
	var forbidden []string
	for _, p := range projects {
		if p.Path != "" {
			forbidden = append(forbidden, p.Path)
		}
	}
	return gitrepo.Deps{Repo: source.NewRepo(s.deps.Store), Audit: s.deps.Audit, Client: s.deps.Sources.Gateway.Client(policy.PurposeRepo),
		DataDir: s.dataDir(), SkillsDir: skills, Forbidden: forbidden, Now: s.deps.Now, Actor: sourceActor}, nil
}

// installable checks that e is a skill or an MCP server that is on; it
// answers the refusal itself.
func (s *server) installable(w http.ResponseWriter, r *http.Request, lang i18n.Lang, e source.Entry) bool {
	if e.Kind != source.KindSkill && e.Kind != source.KindMCP {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "cli.source.install.wrong_kind", e.Key), "")
		return false
	}
	if s.state(e) != source.StateOn {
		s.fail(w, http.StatusConflict, i18n.T(lang, "api.source.install.not_enabled", e.Key), "")
		return false
	}
	return true
}

// newVersion is the version an upgrade of e would install, "" when there is
// none (not installed, or no newer version found).
func newVersion(e source.Entry) string {
	installed := e.Config.Str("installed_sha")
	_, to, ok := e.NewVersion()
	if installed == "" || !ok || !gitrepo.ValidSHA(to) || to == installed {
		return ""
	}
	return to
}

// installErr answers an installation error in lang, without any path.
func (s *server) installErr(w http.ResponseWriter, r *http.Request, lang i18n.Lang, key string, err error) {
	switch {
	case errors.Is(err, gitrepo.ErrForeignDir):
		s.fail(w, http.StatusConflict, i18n.T(lang, "cli.source.install.foreign", key), "")
	case errors.Is(err, gitrepo.ErrInsideProject):
		s.fail(w, http.StatusConflict, i18n.T(lang, "cli.source.install.inside_project"), "")
	case errors.Is(err, gitrepo.ErrBadName):
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "cli.source.install.bad_name", key, noPaths(err.Error())), "")
	default:
		s.fail(w, http.StatusBadGateway, i18n.T(lang, "cli.source.install.failed", key, noPaths(err.Error())), i18n.T(lang, "api.internal_hint"))
	}
}

func (s *server) sourcePreview(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	e, ok := s.entry(w, r)
	if !ok || !s.installable(w, r, lang, e) {
		return
	}
	sha, pinned, to := strings.TrimSpace(r.URL.Query().Get("sha")), e.Config.Str("pinned"), newVersion(e)
	upgrade := to != "" && (sha == "" || sha == to)
	if !upgrade {
		if !gitrepo.ValidSHA(pinned) {
			s.fail(w, http.StatusConflict, i18n.T(lang, "cli.source.install.no_pin", e.Key), "")
			return
		}
		if sha != "" && sha != pinned {
			s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.source.install.bad_sha"), "")
			return
		}
	}
	extend(w)
	ctx, cancel := context.WithTimeout(r.Context(), longTimeout)
	defer cancel()
	gd, err := s.repoDeps(ctx)
	if err != nil {
		s.failed(w, r, e.Key, err)
		return
	}
	if upgrade {
		diff, err := gitrepo.Upgrade(ctx, gd, e, to)
		if err != nil {
			s.installErr(w, r, lang, e.Key, err)
			return
		}
		writeJSON(w, http.StatusOK, PreviewView{Kind: "upgrade", Upgrade: &diff})
		return
	}
	p, err := gitrepo.PreviewInstall(ctx, gd, e, pinned)
	if err != nil {
		s.installErr(w, r, lang, e.Key, err)
		return
	}
	writeJSON(w, http.StatusOK, PreviewView{Kind: "install", Install: &p})
}

// InstallRequest is the body of POST /sources/{key}/install and /upgrade:
// the version the preview showed.
type InstallRequest struct {
	SHA string `json:"sha"`
}

// InstallView is the source after an installation; Warning says the
// previous folder of a moved skill could not be removed.
type InstallView struct {
	Source  SourceView `json:"source"`
	Warning string     `json:"warning,omitempty"`
}

// sourceInstall installs (…/install) or upgrades (…/upgrade) a skill or an
// MCP server to the version the preview showed: posting it is the consent.
func (s *server) sourceInstall(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req InstallRequest
	if !s.readBody(w, r, &req, false) {
		return
	}
	e, ok := s.entry(w, r)
	if !ok || !s.installable(w, r, lang, e) {
		return
	}
	upgrade := strings.HasSuffix(r.URL.Path, "/upgrade")
	want := e.Config.Str("pinned")
	if upgrade {
		if want = newVersion(e); want == "" {
			s.fail(w, http.StatusConflict, i18n.T(lang, "api.source.upgrade.nothing", e.Key), "")
			return
		}
	}
	if !gitrepo.ValidSHA(req.SHA) || req.SHA != want {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.source.install.bad_sha"), "")
		return
	}
	extend(w)
	ctx, cancel := context.WithTimeout(r.Context(), longTimeout)
	defer cancel()
	gd, err := s.repoDeps(ctx)
	if err != nil {
		s.failed(w, r, e.Key, err)
		return
	}
	v := InstallView{}
	_, err = gitrepo.Install(ctx, gd, e, req.SHA)
	if errors.Is(err, gitrepo.ErrOldFolderKept) {
		v.Warning, err = i18n.T(lang, "api.source.install.old_folder_kept"), nil
	}
	if err != nil {
		s.installErr(w, r, lang, e.Key, err)
		return
	}
	if upgrade {
		st := map[string]any{}
		for k, x := range e.Status {
			if k != "new_version" {
				st[k] = x
			}
		}
		st["new_version_available"] = false
		if err := gd.Repo.SetStatus(r.Context(), e.Key, st); err != nil {
			s.failed(w, r, e.Key, err)
			return
		}
	}
	e, err = gd.Repo.Get(r.Context(), e.Key)
	if err != nil {
		s.internal(w, r)
		return
	}
	declared, err := feed.DeclaredAll(r.Context(), s.deps.Store)
	if err != nil {
		s.internal(w, r)
		return
	}
	v.Source = s.sourceView(e, lang, declared)
	writeJSON(w, http.StatusOK, v)
}

// RunRequest is the body of POST /sources/{key}/run.
type RunRequest struct {
	Project string `json:"project"`
}

// pluginTool is the name of a plugin's tool, as the messages show it.
func pluginTool(e source.Entry) string {
	if t := e.Config.Str("tool"); t != "" {
		return t
	}
	return strings.TrimPrefix(e.Key, "plugin.")
}

// sourceRun starts a plugin on a project (or reads its fixed report) and
// answers 202 with the run's id as soon as the run is recorded; GET
// /plugin-runs/{id} follows it.
func (s *server) sourceRun(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req RunRequest
	if !s.readBody(w, r, &req, false) {
		return
	}
	e, ok := s.entry(w, r)
	if !ok {
		return
	}
	if e.Kind != source.KindPlugin {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.source.run.not_plugin", e.Key), "")
		return
	}
	if strings.TrimSpace(req.Project) == "" {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.source.run.need_project"), "")
		return
	}
	if s.state(e) != source.StateOn {
		s.fail(w, http.StatusConflict, i18n.T(lang, "api.source.run.off", e.Key), "")
		return
	}
	p, found, err := s.activeProject(r.Context(), req.Project)
	if err != nil {
		s.internal(w, r)
		return
	}
	if !found {
		s.fail(w, http.StatusNotFound, i18n.T(lang, "api.project_not_found"), "")
		return
	}
	started := make(chan string, 1)
	done := make(chan error, 1)
	rd := plugin.RunDeps{Store: s.deps.Store, Audit: s.deps.Audit, Repo: source.NewRepo(s.deps.Store), DataDir: s.dataDir(), Now: s.deps.Now,
		Exec: s.deps.Sources.PluginExec, Proxy: s.deps.Sources.PluginProxy, Started: func(id string) { started <- id }}
	// The run outlives the request: the page follows it.
	ctx := context.WithoutCancel(r.Context())
	go func() {
		_, err := plugin.RunPlugin(ctx, rd, e, p, e.Config.Str("input"))
		done <- err
	}()
	select {
	case id := <-started:
		writeJSON(w, http.StatusAccepted, map[string]string{"run_id": id})
		return
	case err = <-done:
	}
	select {
	case id := <-started:
		writeJSON(w, http.StatusAccepted, map[string]string{"run_id": id})
		return
	default:
	}
	tool := pluginTool(e)
	switch {
	case errors.Is(err, plugin.ErrNotRunnable):
		s.fail(w, http.StatusConflict, i18n.T(lang, "cli.source.run.not_runnable", tool, e.Key, p.Name), "")
	case errors.Is(err, plugin.ErrDisabled):
		s.fail(w, http.StatusConflict, i18n.T(lang, "api.source.run.off", e.Key), "")
	case err != nil:
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "cli.source.run.failed", tool, p.Name, noPaths(err.Error())), "")
	default:
		s.internal(w, r)
	}
}

func (s *server) pluginRun(w http.ResponseWriter, r *http.Request) {
	var v PluginRunView
	err := s.deps.Store.DB().QueryRowContext(r.Context(), `SELECT r.id, COALESCE(s.key, ''), COALESCE(p.name, ''), r.started_at, r.finished_at,
		r.tool_version, r.status, r.error, r.findings FROM plugin_run r LEFT JOIN source s ON s.id = r.source_id
		LEFT JOIN project p ON p.id = r.project_id WHERE r.id = ?`, r.PathValue("id")).Scan(&v.ID, &v.SourceKey, &v.Project, &v.StartedAt,
		&v.FinishedAt, &v.ToolVersion, &v.Status, &v.Error, &v.Findings)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		s.fail(w, http.StatusNotFound, i18n.T(s.answerLang(r), "api.plugin_run_not_found"), "")
		return
	case err != nil:
		s.internal(w, r)
		return
	}
	v.Project, v.ToolVersion, v.Error = scan.SanitizeText(v.Project), scan.SanitizeText(v.ToolVersion), noPaths(v.Error)
	writeJSON(w, http.StatusOK, v)
}

// parseSince reads "7d", "48h" or "2026-10-01" ("" is no bound).
func parseSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return time.Time{}, errors.New("bad number of days")
		}
		return now.AddDate(0, 0, -n), nil
	}
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		return now.Add(-d), nil
	}
	return time.Parse(time.DateOnly, s)
}

// sourceItems lists the feed items to read: those about a technology in use.
func (s *server) sourceItems(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	since, err := parseSince(q.Get("since"), s.deps.Now())
	if err != nil {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.source.bad_since"), i18n.T(lang, "api.source.bad_since_hint"))
		return
	}
	declared, err := feed.DeclaredAll(r.Context(), s.deps.Store)
	if err != nil {
		s.internal(w, r)
		return
	}
	items, err := feed.NewRepo(s.deps.Store).ListToRead(r.Context(), since, q.Get("unread") == "1", declared)
	if err != nil {
		s.internal(w, r)
		return
	}
	out := make([]ReadingView, 0, len(items))
	for _, it := range items {
		out = append(out, readingView(it, lang))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) sourceItemRead(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := feed.NewRepo(s.deps.Store).MarkRead(r.Context(), id, s.deps.Now())
	switch {
	case errors.Is(err, feed.ErrItemNotFound):
		s.fail(w, http.StatusNotFound, i18n.T(s.answerLang(r), "api.item_not_found"), "")
		return
	case err != nil:
		s.internal(w, r)
		return
	}
	if err := s.record(r.Context(), "source.item_read", id, "ok", map[string]any{"count": 1}); err != nil {
		s.auditFailed(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "read": true})
}

func (s *server) discoveries(w http.ResponseWriter, r *http.Request) {
	list, err := gitrepo.NewDiscoveryRepo(s.deps.Store).List(r.Context(), gitrepo.StateNew)
	if err != nil {
		s.internal(w, r)
		return
	}
	out := make([]gitrepo.Discovery, 0, len(list))
	for _, d := range list {
		d.Repo, d.Topic, d.Description, d.HTMLURL = scan.SanitizeText(d.Repo), scan.SanitizeText(d.Topic), scan.SanitizeText(d.Description), scan.SanitizeText(d.HTMLURL)
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, out)
}

// DiscoveryRequest is the body of POST /sources/discoveries/{owner}/{name}:
// ignore, or add as a skill or MCP server pinned to Pin.
type DiscoveryRequest struct {
	Action string `json:"action"`
	Kind   string `json:"kind"`
	Pin    string `json:"pin"`
	Path   string `json:"path"`
	Name   string `json:"name"`
}

func (s *server) discoveryAction(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req DiscoveryRequest
	if !s.readBody(w, r, &req, false) {
		return
	}
	ctx := r.Context()
	repo := r.PathValue("owner") + "/" + r.PathValue("name")
	if req.Action != "add" && req.Action != "ignore" {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.discover.bad_action"), "")
		return
	}
	dr := gitrepo.NewDiscoveryRepo(s.deps.Store)
	found, err := dr.List(ctx, "")
	if err != nil {
		s.internal(w, r)
		return
	}
	known := false
	for _, d := range found {
		if strings.EqualFold(d.Repo, repo) {
			known, repo = true, d.Repo
		}
	}
	if !known {
		s.fail(w, http.StatusNotFound, i18n.T(lang, "cli.source.discover.unknown", repo), "")
		return
	}
	if req.Action == "ignore" {
		if err := dr.SetState(ctx, repo, gitrepo.StateIgnored); err != nil {
			s.internal(w, r)
			return
		}
		if err := s.record(ctx, "source.discover", repo, "ok", map[string]any{"repo": repo, "state": gitrepo.StateIgnored}); err != nil {
			s.auditFailed(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"repo": repo, "state": gitrepo.StateIgnored})
		return
	}
	if req.Kind != string(source.KindSkill) && req.Kind != string(source.KindMCP) {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.source.add.refused"), i18n.T(lang, "api.discover.add_kind"))
		return
	}
	e, reason := newEntry(lang, AddSourceRequest{Kind: req.Kind, Name: req.Name, Repo: repo, Pin: req.Pin, Path: req.Path})
	if reason != "" {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.source.add.refused"), reason)
		return
	}
	if !s.addEntry(w, r, lang, e, "discover") {
		return
	}
	// The source is added: a failure to mark the discovery only leaves it
	// in the list.
	_ = dr.SetState(ctx, repo, gitrepo.StateAdded)
}

func (s *server) techList(w http.ResponseWriter, r *http.Request) {
	tags, err := source.ListTech(r.Context(), s.deps.Store)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, tags)
}

// TechRequest is the body of POST /tech.
type TechRequest struct {
	Tag string `json:"tag"`
}

// techChange declares (POST /tech) or forgets (DELETE /tech/{tag}) a
// technology used outside the projects, and answers the list.
func (s *server) techChange(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	action, tag := "remove", r.PathValue("tag")
	var err error
	if r.Method == http.MethodPost {
		var req TechRequest
		if !s.readBody(w, r, &req, false) {
			return
		}
		action, tag = "add", strings.TrimSpace(req.Tag)
		err = source.AddTech(r.Context(), s.deps.Store, tag)
	} else {
		err = source.RemoveTech(r.Context(), s.deps.Store, tag)
	}
	if errors.Is(err, project.ErrInvalidTech) {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "cli.tech.bad_tag", tag), "")
		return
	}
	if err != nil {
		s.internal(w, r)
		return
	}
	if err := s.record(r.Context(), "tech.set", tag, "ok", map[string]any{"tag": tag, "action": action}); err != nil {
		s.auditFailed(w, r)
		return
	}
	s.techList(w, r)
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
