package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/feed"
	"github.com/kvarot/michel/internal/gitrepo"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/source"
)

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
	e, refusal := source.NewUserEntry(source.UserEntryRequest{Kind: source.Kind(req.Kind), Name: req.Name, Repo: repo, Pin: req.Pin, Path: req.Path})
	if refusal != nil {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.source.add.refused"), refusalText(lang, refusal))
		return
	}
	s.addEntry(w, r, lang, e, "discover", func() error { return dr.SetState(ctx, repo, gitrepo.StateAdded) })
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
