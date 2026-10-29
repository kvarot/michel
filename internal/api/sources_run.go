package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/plugin"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/source"
)

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
