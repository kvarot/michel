package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/explain"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/source"
)

// decisionAuthor is the author and the audit actor of decisions taken on the page.
const decisionAuthor = "web"

// defaultDigests and maxDigests bound GET /digests?last=.
const (
	defaultDigests = 7
	maxDigests     = 100
)

// severities are the severity labels, most severe first.
var severities = []string{"critical", "high", "medium", "low", "unknown"}

// findingStatuses are the accepted ?status= values (see scan.ListFindings).
var findingStatuses = []string{"", "all", "actionable", scan.StatusNew, scan.StatusPending, scan.StatusDecided, scan.StatusGone}

func oneOf(s string, list []string) bool {
	for _, v := range list {
		if s == v {
			return true
		}
	}
	return false
}

// severityOf maps any stored label to one of severities.
func severityOf(label string) string {
	if oneOf(label, severities) {
		return label
	}
	return "unknown"
}

// requestLang is the answer's language, or a 400 for an unknown ?lang=.
func (s *server) requestLang(w http.ResponseWriter, r *http.Request) (i18n.Lang, bool) {
	l, ok := s.lang(r)
	if !ok {
		s.fail(w, http.StatusBadRequest, i18n.T(s.answerLang(r), "api.bad_lang"), i18n.T(s.answerLang(r), "api.bad_lang_hint"))
	}
	return l, ok
}

func (s *server) meta(w http.ResponseWriter, r *http.Request) {
	m := MetaView{Version: s.deps.Version, Lang: s.deps.Lang, Languages: []string{string(i18n.EN), string(i18n.FR)},
		Assistant: s.currentPolicy().Assistant.Name}
	if m.Assistant == "" {
		m.Assistant = digest.DefaultAssistant
	}
	if s.deps.OSVRoot != "" {
		// Only the databases of the enabled ecosystems count.
		ecos, err := osvdb.Enabled(r.Context(), source.NewRepo(s.deps.Store), nil)
		if err != nil {
			s.internal(w, r)
			return
		}
		sts, err := osvdb.Statuses(s.deps.OSVRoot, ecos)
		if err != nil {
			s.internal(w, r)
			return
		}
		var oldest time.Time
		for _, st := range sts {
			if st.Present && !st.FetchedAt.IsZero() && (oldest.IsZero() || st.FetchedAt.Before(oldest)) {
				oldest = st.FetchedAt
			}
		}
		if !oldest.IsZero() {
			m.OSVFetchedAt = oldest.UTC().Format(time.RFC3339)
			m.OSVStale = s.deps.Now().Sub(oldest) > digest.StaleAfter
		}
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *server) today(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	// The page shows the last digest's window extended to now: after the
	// morning digest, what it reported stays on the page all day.
	opt := digest.Options{Assistant: s.currentPolicy().Assistant.Name, OSVRoot: s.deps.OSVRoot, Allowed: s.allowed}
	last, ok, err := digest.NewRepo(s.deps.Store).Last(r.Context())
	if err != nil {
		s.internal(w, r)
		return
	}
	if ok {
		opt.Since = last.Since
	}
	d, err := digest.Compute(r.Context(), s.deps.Store, s.deps.Now(), lang, opt)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, todayView(d, lang))
}

func (s *server) projects(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := project.NewRepo(s.deps.Store).List(ctx)
	if err != nil {
		s.internal(w, r)
		return
	}
	out := []ProjectView{}
	for _, p := range list {
		if !p.Active {
			continue
		}
		v, err := s.projectView(ctx, p)
		if err != nil {
			s.internal(w, r)
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// projectView counts p's findings the way the digest does.
func (s *server) projectView(ctx context.Context, p project.Project) (ProjectView, error) {
	v := ProjectView{Name: scan.SanitizeText(p.Name), Classification: string(p.Classification), FixLevel: p.FixLevel,
		AutoFixMinor: p.AutoFixMinor,
		Open:         map[string]int{}, Decided: map[string]int{}, LastScanStatus: "never"}
	for _, sev := range severities {
		v.Open[sev] = 0
	}
	for _, a := range []decide.Action{decide.Fix, decide.Defer, decide.Ignore} {
		v.Decided[string(a)] = 0
	}
	findings, err := scan.NewRepo(s.deps.Store).ListFindings(ctx, p.ID, "")
	if err != nil {
		return ProjectView{}, err
	}
	current, err := decide.NewRepo(s.deps.Store).CurrentByProject(ctx, p.ID)
	if err != nil {
		return ProjectView{}, err
	}
	for _, f := range findings {
		v.Total++
		if dec, ok := current[f.ID]; ok && f.Status == scan.StatusDecided {
			v.Decided[string(dec.Action)]++
			if dec.Action == decide.Ignore {
				continue
			}
		}
		v.Open[severityOf(effective(f))]++
	}
	var at, status string
	err = s.deps.Store.DB().QueryRowContext(ctx, `SELECT started_at, status FROM scan WHERE project_id = ?
		ORDER BY started_at DESC, id DESC LIMIT 1`, p.ID).Scan(&at, &status)
	switch {
	case err == nil:
		v.LastScanAt, v.LastScanStatus = at, status
	case !errors.Is(err, sql.ErrNoRows):
		return ProjectView{}, err
	}
	return v, nil
}

// projectPatch is the body of PATCH /projects/{name}: only the fields sent
// change.
type projectPatch struct {
	FixLevel     *int  `json:"fix_level"`
	AutoFixMinor *bool `json:"auto_fix_minor"`
}

// patchProject changes the fix levels and the automatic minor fixes of a
// project, audits it and answers the project's view.
func (s *server) patchProject(w http.ResponseWriter, r *http.Request) {
	ctx, lang := r.Context(), s.answerLang(r)
	var body projectPatch
	if !s.readJSONHint(w, r, &body, i18n.T(lang, "api.project.patch.bad_json_hint")) {
		return
	}
	if body.FixLevel == nil && body.AutoFixMinor == nil {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.project.patch.nothing"), i18n.T(lang, "api.project.patch.bad_json_hint"))
		return
	}
	if l := body.FixLevel; l != nil && (*l < 0 || *l > 3) {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.project.patch.bad_level"), i18n.T(lang, "api.project.patch.bad_level_hint"))
		return
	}
	p, found, err := s.activeProject(ctx, r.PathValue("name"))
	if err != nil {
		s.internal(w, r)
		return
	}
	if !found {
		s.fail(w, http.StatusNotFound, i18n.T(lang, "api.project_not_found"), "")
		return
	}
	ev := map[string]any{}
	if body.FixLevel != nil {
		p.FixLevel, ev["fix_level"] = *body.FixLevel, *body.FixLevel
	}
	if body.AutoFixMinor != nil {
		p.AutoFixMinor, ev["auto_fix_minor"] = *body.AutoFixMinor, *body.AutoFixMinor
	}
	if err := project.NewRepo(s.deps.Store).Update(ctx, p); err != nil {
		if errors.Is(err, project.ErrInvalidFixLevel) {
			s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.project.patch.bad_level"), i18n.T(lang, "api.project.patch.bad_level_hint"))
			return
		}
		s.internal(w, r)
		return
	}
	if _, err := s.deps.Audit.Record(ctx, audit.Event{Actor: decisionAuthor, Action: "project.update", Target: p.Name, Result: "ok", Evidence: ev}); err != nil {
		s.auditFailed(w, r)
		return
	}
	v, err := s.projectView(ctx, p)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// activeProject returns the active project named name.
func (s *server) activeProject(ctx context.Context, name string) (project.Project, bool, error) {
	list, err := project.NewRepo(s.deps.Store).List(ctx)
	if err != nil {
		return project.Project{}, false, err
	}
	for _, p := range list {
		if p.Active && p.Name == name {
			return p, true, nil
		}
	}
	return project.Project{}, false, nil
}

func (s *server) projectFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	status, severity := strings.TrimSpace(q.Get("status")), strings.ToLower(strings.TrimSpace(q.Get("severity")))
	if !oneOf(status, findingStatuses) {
		s.fail(w, http.StatusBadRequest, i18n.T(s.answerLang(r), "api.bad_status"), i18n.T(s.answerLang(r), "api.bad_status_hint", strings.Join(findingStatuses[1:], ", ")))
		return
	}
	if severity != "" && !oneOf(severity, severities) {
		s.fail(w, http.StatusBadRequest, i18n.T(s.answerLang(r), "api.bad_severity"), i18n.T(s.answerLang(r), "api.bad_severity_hint", strings.Join(severities, ", ")))
		return
	}
	p, found, err := s.activeProject(ctx, r.PathValue("name"))
	if err != nil {
		s.internal(w, r)
		return
	}
	if !found {
		s.fail(w, http.StatusNotFound, i18n.T(s.answerLang(r), "api.project_not_found"), "")
		return
	}
	findings, err := scan.NewRepo(s.deps.Store).ListFindings(ctx, p.ID, status)
	if err != nil {
		s.internal(w, r)
		return
	}
	current, err := decide.NewRepo(s.deps.Store).CurrentByProject(ctx, p.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	analyses := analyze.NewRepo(s.deps.Store)
	out := []FindingView{}
	for _, f := range findings {
		if severity != "" && severityOf(effective(f)) != severity {
			continue
		}
		a, has, err := analyses.Get(ctx, f.ID)
		if err != nil {
			s.internal(w, r)
			return
		}
		facts := explain.FactsFrom(f, a, has)
		facts.FixLevel = p.FixLevel
		ex, err := explain.Render(lang, facts)
		if err != nil {
			s.internal(w, r)
			return
		}
		var dec *decide.Decision
		if d, ok := current[f.ID]; ok {
			dec = &d
		}
		out = append(out, findingView(f, p, ex, nil, dec, nil))
	}
	writeJSON(w, http.StatusOK, out)
}

// lookup finds a finding by its exact id, with its project.
func (s *server) lookup(ctx context.Context, id string) (scan.Finding, project.Project, bool, error) {
	if id == "" {
		return scan.Finding{}, project.Project{}, false, nil
	}
	list, err := scan.NewRepo(s.deps.Store).FindByIDPrefix(ctx, id)
	if err != nil {
		return scan.Finding{}, project.Project{}, false, err
	}
	for _, f := range list {
		if f.ID != id {
			continue
		}
		p, err := project.NewRepo(s.deps.Store).Get(ctx, f.ProjectID)
		if errors.Is(err, project.ErrNotFound) {
			return scan.Finding{}, project.Project{}, false, nil
		}
		if err != nil {
			return scan.Finding{}, project.Project{}, false, err
		}
		return f, p, true, nil
	}
	return scan.Finding{}, project.Project{}, false, nil
}

// detail is the full view of one finding in lang.
func (s *server) detail(ctx context.Context, f scan.Finding, p project.Project, lang i18n.Lang) (FindingView, error) {
	a, has, err := analyze.NewRepo(s.deps.Store).Get(ctx, f.ID)
	if err != nil {
		return FindingView{}, err
	}
	facts := explain.FactsFrom(f, a, has)
	facts.FixLevel = p.FixLevel
	ex, err := explain.Render(lang, facts)
	if err != nil {
		return FindingView{}, err
	}
	var ap *analyze.Analysis
	if has {
		ap = &a
	}
	var dec *decide.Decision
	if d, ok, err := decide.NewRepo(s.deps.Store).Current(ctx, f.ID); err != nil {
		return FindingView{}, err
	} else if ok {
		dec = &d
	}
	return findingView(f, p, ex, ap, dec, glossaryOf(lang, facts, f.Aliases)), nil
}

func (s *server) finding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	f, p, found, err := s.lookup(ctx, r.PathValue("id"))
	if err != nil {
		s.internal(w, r)
		return
	}
	if !found {
		s.fail(w, http.StatusNotFound, i18n.T(s.answerLang(r), "api.finding_not_found"), "")
		return
	}
	v, err := s.detail(ctx, f, p, lang)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// readJSON decodes the body of r into v: JSON only, at most maxBody bytes,
// one document, no unknown field. It answers the error itself.
func (s *server) readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return s.readJSONHint(w, r, v, i18n.T(s.answerLang(r), "api.bad_json_hint"))
}

// readJSONHint is readJSON with hint as the hint of an unreadable body.
func (s *server) readJSONHint(w http.ResponseWriter, r *http.Request, v any, hint string) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		s.fail(w, http.StatusUnsupportedMediaType, i18n.T(s.answerLang(r), "api.need_json"), "")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	err = dec.Decode(v)
	if err == nil {
		if _, extra := dec.Token(); !errors.Is(extra, io.EOF) {
			err = errors.New("more than one JSON document")
		}
	}
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		s.fail(w, http.StatusRequestEntityTooLarge, i18n.T(s.answerLang(r), "api.too_large"), "")
		return false
	case err != nil:
		s.fail(w, http.StatusBadRequest, i18n.T(s.answerLang(r), "api.bad_json"), hint)
		return false
	}
	return true
}

func (s *server) decision(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req DecisionRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	refuse := func(key string, args ...any) {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.decision.refused"), i18n.T(lang, key, args...))
	}
	action := decide.Action(strings.ToLower(strings.TrimSpace(req.Action)))
	if action != decide.Fix && action != decide.Defer && action != decide.Ignore {
		refuse("api.decision.unknown_action")
		return
	}
	now := s.deps.Now()
	d := decide.Decision{Action: action, Justification: req.Why, Author: decisionAuthor}
	if until := strings.TrimSpace(req.Until); until != "" {
		if action != decide.Defer {
			refuse("api.decision.date_not_defer")
			return
		}
		t, err := time.Parse("2006-01-02", until)
		if err != nil {
			refuse("api.decision.bad_until")
			return
		}
		d.DueAt = t
	}
	if err := decide.Validate(&d, now); err != nil {
		switch {
		case errors.Is(err, decide.ErrJustificationRequired):
			refuse("api.decision.why_required")
		case errors.Is(err, decide.ErrJustificationTooLong):
			refuse("api.decision.why_too_long", decide.MaxJustification)
		case errors.Is(err, decide.ErrDueInPast):
			refuse("api.decision.due_in_past")
		default:
			refuse("api.decision.unknown_action")
		}
		return
	}
	f, p, found, err := s.lookup(ctx, r.PathValue("id"))
	if err != nil {
		s.internal(w, r)
		return
	}
	if !found {
		s.fail(w, http.StatusNotFound, i18n.T(s.answerLang(r), "api.finding_not_found"), "")
		return
	}
	d.FindingID = f.ID
	_, _, evID, err := decide.Apply(ctx, decide.NewRepo(s.deps.Store), s.deps.Audit, decisionAuthor, d, f.Package, f.OSVID, now)
	var auditErr *decide.AuditError
	switch {
	case errors.Is(err, decide.ErrFindingGone):
		s.fail(w, http.StatusConflict, i18n.T(s.answerLang(r), "api.decision.gone"), i18n.T(s.answerLang(r), "api.decision.gone_hint"))
		return
	case errors.Is(err, decide.ErrFindingNotFound):
		s.fail(w, http.StatusNotFound, i18n.T(s.answerLang(r), "api.finding_not_found"), "")
		return
	case errors.As(err, &auditErr):
		s.fail(w, http.StatusInternalServerError, i18n.T(s.answerLang(r), "api.decision.audit_failed"), i18n.T(s.answerLang(r), "api.internal_hint"))
		return
	case err != nil:
		s.internal(w, r)
		return
	}
	// Read the finding again: its status changed.
	f, p, found, err = s.lookup(ctx, f.ID)
	if err != nil || !found {
		s.internal(w, r)
		return
	}
	v, err := s.detail(ctx, f, p, lang)
	if err != nil {
		s.internal(w, r)
		return
	}
	v.AuditEventID = evID
	writeJSON(w, http.StatusOK, v)
}

func (s *server) digests(w http.ResponseWriter, r *http.Request) {
	last := defaultDigests
	if q := strings.TrimSpace(r.URL.Query().Get("last")); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 || n > maxDigests {
			s.fail(w, http.StatusBadRequest, i18n.T(s.answerLang(r), "api.bad_last"), i18n.T(s.answerLang(r), "api.bad_last_hint", maxDigests))
			return
		}
		last = n
	}
	runs, err := digest.NewRepo(s.deps.Store).List(r.Context(), last)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, runs)
}

// effective is the effective severity label of f (scan.EffectiveSeverity).
func effective(f scan.Finding) string {
	l, _ := scan.EffectiveSeverity(f)
	return l
}
