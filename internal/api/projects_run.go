package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
)

// ErrNothingToScan is what Deps.ScanProject returns for a folder holding no
// list of dependencies Michel reads.
var ErrNothingToScan = errors.New("nothing to scan")

// scanBound bounds a scan started from the page: past it, the sweep of the
// next start would call it interrupted anyway.
const scanBound = scan.StaleScanAfter

// AddProjectRequest is the body of POST /projects. Nothing else: a test
// command stays on the command line (R13), and an unknown field is refused.
type AddProjectRequest struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

// addProject registers a folder of this computer, as michel project add does:
// same checks and defaults (classification of the policy, level 1), audited,
// refusals included (project.Register). The answer holds no path.
func (s *server) addProject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req AddProjectRequest
	if !s.readJSONHint(w, r, &req, i18n.T(lang, "api.project.add.bad_json_hint")) {
		return
	}
	repo := project.NewRepo(s.deps.Store)
	repo.DefaultClassification = s.currentPolicy().Sovereignty.DataClassification
	added, err := project.Register(ctx, repo, s.deps.Audit, project.RegisterRequest{
		Actor: decisionAuthor, Name: req.Name, Path: req.Path,
		Folders: project.Folders{DataDir: s.dataDir(), Home: s.deps.Servers.Home},
	})
	var refused *project.RefusalError
	switch {
	case errors.As(err, new(*project.AuditError)):
		s.auditFailed(w, r)
		return
	case errors.As(err, &refused):
		status := http.StatusBadRequest
		if refused.Key == "api.project.duplicate" {
			status = http.StatusConflict
		}
		s.failedBody(w, status, lang, refused.Key, refused.Key+"_hint")
		return
	case err != nil:
		s.internal(w, r)
		return
	}
	v, err := s.projectView(ctx, lang, added)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

// scanProject starts the check of a project in the background and answers
// 202; GET /projects follows it (scanning, last_failure). One at a time per
// project: a second click is told so.
func (s *server) scanProject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	if s.deps.ScanProject == nil {
		s.failedBody(w, http.StatusServiceUnavailable, lang, "api.project.scan_unavailable", "api.project.scan_unavailable_hint")
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
	// A check of this project that runs holds the lock: its own sentence first.
	if run, _ := s.scans.get(p.ID); run.running {
		s.failedBody(w, http.StatusConflict, lang, "api.project.scan_running", "api.project.scan_running_hint")
		return
	}
	// A check does not read a folder a click is writing, and no click starts
	// during a check (R35).
	unlock := func() {}
	if s.deps.Fix != nil {
		var free bool
		if unlock, free = fix.TryGitLock(*s.deps.Fix, p.ID); !free {
			s.failedBody(w, http.StatusConflict, lang, "api.git.busy", "api.git.busy_hint")
			return
		}
	}
	if !s.scans.begin(p.ID) {
		unlock()
		s.failedBody(w, http.StatusConflict, lang, "api.project.scan_running", "api.project.scan_running_hint")
		return
	}
	if _, err := s.deps.Audit.Record(ctx, audit.Event{Actor: decisionAuthor, Action: "project.scan", Target: p.Name, Result: "started",
		Evidence: map[string]any{}}); err != nil {
		s.scans.end(p.ID, s.deps.Now(), "api.project.scan_failed")
		unlock()
		s.auditFailed(w, r)
		return
	}
	run := s.deps.ScanProject
	started := s.goBackground(func(ctx context.Context) {
		defer unlock()
		ctx, cancel := context.WithTimeout(ctx, scanBound)
		defer cancel()
		code := "api.project.scan_failed"
		defer func() {
			// A parser that panics on an odd file ends this check, not michel
			// serve. The reason may name files: the terminal only.
			if r := recover(); r != nil {
				fmt.Fprintln(os.Stderr, i18n.T(s.deps.Lang, "api.project.scan_panic", p.Name, scan.SanitizeText(fmt.Sprint(r))))
			}
			s.scans.end(p.ID, s.deps.Now(), code)
		}()
		code = codeOfScan(run(ctx, p))
	})
	if !started {
		s.scans.end(p.ID, s.deps.Now(), "api.project.scan_failed")
		unlock()
		s.fail(w, http.StatusServiceUnavailable, i18n.T(lang, "api.closing"), "")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"started": true})
}

// codeOfScan is the catalog key of how a scan ended, "" for done: only a code
// reaches the page, the error may name files.
func codeOfScan(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, osvdb.ErrDatabaseMissing):
		return "api.project.no_database"
	case errors.Is(err, ErrNothingToScan):
		return "api.project.nothing_to_scan"
	case errors.Is(err, scan.ErrScanRunning):
		return "api.project.scan_elsewhere"
	}
	return "api.project.scan_failed"
}

// scanState adds to v how the scan started from the page stands.
func (s *server) scanState(lang i18n.Lang, p project.Project, v *ProjectView) {
	run, tracked := s.scans.get(p.ID)
	if !tracked {
		return
	}
	v.Scanning = run.running
	if run.running || run.ok {
		return
	}
	v.LastFailure = &TargetLastCheck{At: stamp(run.at), Code: run.code, Error: i18n.T(lang, run.code)}
	if i18n.Has(run.code + "_hint") {
		v.LastFailure.Hint = i18n.T(lang, run.code+"_hint")
	}
}
