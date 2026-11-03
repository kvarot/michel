package api

import (
	"context"
	"net/http"
	"slices"
	"strconv"

	"github.com/kvarot/michel/internal/collect"
	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/serverrules"
	"github.com/kvarot/michel/internal/target"
)

// ExposureView is GET /targets/{id}/exposure: what the last check saw listen
// on the server, from inside it. It does not say that anything can be reached
// from outside: the firewall of the host is never read.
//
// Read is false when Michel does not know what listens: no check yet, ss
// missing or failed, an answer it could not read, a stored check from before
// this reading, or a list with no row at all. Then Services is empty and says
// nothing: an empty list that was read is not possible, since Michel has just
// come in through a service that listens. Closed holds the services that were
// open and that a complete read no longer shows open to all; LastSeenOpen is
// the last time Michel saw each one open, not the time it was closed. A port
// the stored read shows open to all again is not listed as closed.
type ExposureView struct {
	Read      bool               `json:"read"`
	CheckedAt string             `json:"checked_at"`
	Kind      string             `json:"kind"`
	Services  []ExposureService  `json:"services"`
	Unseen    []TargetUnseenView `json:"unseen"`
	Closed    []ExposureClosed   `json:"closed"`
}

// ExposureService is one port seen listening, for one scope (open, private,
// server). Verdict is normal, close or unknown, judged by the port number
// alone. FindingID is the finding it opened, when it opened one; DecidedWhy is
// what the person wrote when they said it is blocked or wanted.
type ExposureService struct {
	Port       int      `json:"port"`
	Addresses  []string `json:"addresses"`
	Scope      string   `json:"scope"`
	Service    string   `json:"service"`
	Verdict    string   `json:"verdict"`
	FindingID  string   `json:"finding_id"`
	DecidedWhy string   `json:"decided_why"`
}

// ExposureClosed is a service Michel no longer sees open to all.
type ExposureClosed struct {
	Port         int    `json:"port"`
	Service      string `json:"service"`
	LastSeenOpen string `json:"last_seen_open"`
}

// ExposureDecisionRequest is the body of the decision route: the reason. The
// action is always ignore (R12).
type ExposureDecisionRequest struct {
	Why string `json:"why"`
}

var scopeOrder = []target.ListenScope{target.ScopeOpen, target.ScopePrivate, target.ScopeServer}

// exposureView builds the view of t.
func (s *server) exposureView(ctx context.Context, t target.Target, lang i18n.Lang) (ExposureView, error) {
	v := ExposureView{Kind: string(t.Kind), Services: []ExposureService{}, Unseen: []TargetUnseenView{}, Closed: []ExposureClosed{}}
	inv, haveInv, err := s.targets().LatestInventory(ctx, t.ID)
	if err != nil {
		return v, err
	}
	findings, err := scan.NewRepo(s.deps.Store).ListServerFindings(ctx, t.ID)
	if err != nil {
		return v, err
	}
	set, err := serverrules.Rules()
	if err != nil {
		return v, err
	}
	service := map[string]string{}
	for _, r := range set.Listen {
		if r.Rule != "" {
			service[r.Rule] = r.Service
		}
	}
	byPort := map[int]scan.Finding{}
	decisions := decide.NewRepo(s.deps.Store)
	for _, f := range findings {
		if f.Kind != scan.KindServerExposure {
			continue
		}
		port, err := strconv.Atoi(f.Package)
		if err != nil {
			continue
		}
		if f.Status == scan.StatusGone {
			v.Closed = append(v.Closed, ExposureClosed{Port: port, Service: service[f.OSVID], LastSeenOpen: f.LastSeenAt})
			continue
		}
		byPort[port] = f
	}
	slices.SortFunc(v.Closed, func(a, b ExposureClosed) int { return a.Port - b.Port })

	if haveInv {
		v.CheckedAt = stamp(inv.At)
		v.Read = serverrules.ListenersKnown(inv)
	}
	if v.Read {
		// The stored read is the newer fact: a port open to all again is not closed.
		v.Closed = slices.DeleteFunc(v.Closed, func(c ExposureClosed) bool {
			return slices.ContainsFunc(inv.Listeners, func(l target.Listener) bool { return l.Port == c.Port && l.Scope == target.ScopeOpen })
		})
		type key struct {
			port  int
			scope target.ListenScope
		}
		groups := map[key][]string{}
		for _, l := range inv.Listeners {
			k := key{l.Port, l.Scope}
			if !slices.Contains(groups[k], l.Address) {
				groups[k] = append(groups[k], l.Address)
			}
		}
		for k, addrs := range groups {
			j := serverrules.JudgeListener(set, t, target.Listener{Port: k.port})
			sv := ExposureService{Port: k.port, Addresses: srvTexts(t.User, addrs), Scope: string(k.scope), Service: j.Service, Verdict: j.Verdict}
			slices.Sort(sv.Addresses)
			if f, ok := byPort[k.port]; ok && k.scope == target.ScopeOpen {
				sv.FindingID = f.ID
				if d, ok, err := decisions.Current(ctx, f.ID); err != nil {
					return v, err
				} else if ok && d.Action == decide.Ignore {
					sv.DecidedWhy = srvText(t.User, d.Justification)
				}
			}
			v.Services = append(v.Services, sv)
		}
		slices.SortFunc(v.Services, func(a, b ExposureService) int {
			if a.Port != b.Port {
				return a.Port - b.Port
			}
			return slices.Index(scopeOrder, target.ListenScope(a.Scope)) - slices.Index(scopeOrder, target.ListenScope(b.Scope))
		})
	}
	if haveInv && !v.Read {
		said := false
		for _, u := range inv.Unseen {
			if u.Reason == collect.ReasonListeners {
				v.Unseen = append(v.Unseen, TargetUnseenView{What: i18n.T(lang, "api.exposure.listeners.what"), Reason: reasonText(lang, t.User, u.Reason)})
				said = true
			}
		}
		if !said {
			// Stored before this reading existed, or a list with no row.
			v.Unseen = append(v.Unseen, TargetUnseenView{What: i18n.T(lang, "api.exposure.listeners.what"), Reason: i18n.T(lang, collect.ReasonListeners)})
		}
	}
	// What Michel never reads, whatever the check saw.
	v.Unseen = append(v.Unseen,
		TargetUnseenView{What: i18n.T(lang, "api.exposure.firewall.what"), Reason: i18n.T(lang, "api.exposure.firewall.reason")},
		TargetUnseenView{What: i18n.T(lang, "api.exposure.udp.what"), Reason: i18n.T(lang, "api.exposure.udp.reason")})
	return v, nil
}

func (s *server) targetExposure(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	t, ok := s.targetOf(w, r, lang)
	if !ok {
		return
	}
	v, err := s.exposureView(r.Context(), t, lang)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// targetExposureDecision records "I know, it is blocked or wanted" on the
// exposure finding of this server (R12): the action is always ignore, and a
// reason is required. The rules and the audit are those of POST
// /findings/{id}/decision; only the finding lookup differs, since the finding
// of a server has no project.
func (s *server) targetExposureDecision(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req ExposureDecisionRequest
	if !s.readJSON(w, r, &req) {
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
	if f.Kind != scan.KindServerExposure {
		s.failedBody(w, http.StatusNotFound, lang, "api.target.finding_not_found", "")
		return
	}
	now := s.deps.Now()
	d := decide.Decision{Action: decide.Ignore, Justification: req.Why, Author: decisionAuthor}
	refuse := func(key string, args ...any) {
		s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.decision.refused"), i18n.T(lang, key, args...))
	}
	if !validateDecision(refuse, &d, now) {
		return
	}
	if _, ok := s.applyDecision(w, r, d, f, now); !ok {
		return
	}
	v, err := s.exposureView(r.Context(), t, lang)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
