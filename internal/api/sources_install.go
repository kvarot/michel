package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/kvarot/michel/internal/feed"
	"github.com/kvarot/michel/internal/gitrepo"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/source"
)

// repoDeps wires the installation of skills and MCP servers, like the
// command line: the archive client (purpose source.repo), the skills folder
// and the folders of the scanned projects, where Michel never writes.
func (s *server) repoDeps(ctx context.Context) (gitrepo.Deps, error) {
	return gitrepo.NewDeps(ctx, s.deps.Store, s.deps.Audit, s.deps.Sources.Gateway, s.dataDir(), s.deps.Now, sourceActor)
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
		if err := gd.Repo.SetStatus(r.Context(), e.Key, gitrepo.WithoutNewVersion(e.Status)); err != nil {
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
