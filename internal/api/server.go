// Package api is the local JSON API behind the "Today" page: a token
// protected HTTP handler meant to listen on loopback only (michel serve).
// It reads the store, computes the digest on the fly and records the
// decisions taken on the page, with the same rules and audit events as the
// command line. Its answers never hold code, the projects' folders, their
// declared commands or a secret.
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/store"
)

// Deps is what the handler needs.
type Deps struct {
	Store   *store.Store
	Audit   *audit.Logger
	Policy  policy.Policy
	Secrets secret.Store
	Now     func() time.Time
	Version string
	// OSVRoot is the folder of the offline databases; "" skips freshness.
	OSVRoot string
	// Lang is the language when the request names none.
	Lang i18n.Lang
	// Web is the built front (index.html at its root); nil means no front.
	Web fs.FS
	// AllowedHosts are the accepted Host headers ("127.0.0.1:7331"...);
	// empty accepts localhost and loopback addresses on any port.
	AllowedHosts []string
	// PolicyPath is the policy file that receives the allow rules a consent
	// on the Sources page gives; Reload reads it again and validates it (the
	// server then keeps the new policy, and the gateway its rules).
	PolicyPath string
	Reload     func() (policy.Policy, error)
	// Sources is what the source routes need.
	Sources Sources
}

// Sources are the collaborators of the source routes: the egress gateway
// in force (it decides which sources wait for consent and carries every
// request), the data folder (downloads, plugin runs) and, for the tests, the
// way a plugin's tool is run.
type Sources struct {
	// Gateway nil means a gateway of Policy, with no audit of the attempts.
	Gateway *egress.Gateway
	DataDir string
	// PluginExec and PluginProxy replace the real tool run and deny proxy
	// (tests); nil keeps the real ones.
	PluginExec  func(ctx context.Context, name string, args, env []string, dir string) (stdout, stderr []byte, err error)
	PluginProxy func() (addr string, close func())
}

// maxBody bounds a request body.
const maxBody = 64 << 10

// csp keeps the page to its own origin. Inline styles are allowed because
// the component library injects some; scripts are not.
const csp = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// LoadOrCreateToken returns the api token from the secret store (name
// secret.ReservedAPIToken), creating 32 random bytes (hex) if absent.
func LoadOrCreateToken(s secret.Store) (string, error) {
	v, err := s.Get(secret.ReservedAPIToken)
	if err == nil && strings.TrimSpace(string(v)) != "" {
		return strings.TrimSpace(string(v)), nil
	}
	if err != nil && !errors.Is(err, secret.ErrNotFound) {
		return "", fmt.Errorf("cannot read the api token: %w", err)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cannot create the api token: %w", err)
	}
	tok := hex.EncodeToString(b)
	if err := s.Set(secret.ReservedAPIToken, []byte(tok)); err != nil {
		return "", fmt.Errorf("cannot save the api token: %w", err)
	}
	return tok, nil
}

// server is the handler's state. policy is the policy in force: a consent
// given on the page reloads it, so it is read under mu.
type server struct {
	deps   Deps
	token  []byte
	mux    *http.ServeMux
	mu     sync.RWMutex
	policy policy.Policy
	// updating is held while a source update runs: one at a time.
	updating sync.Mutex
}

// currentPolicy is the policy in force.
func (s *server) currentPolicy() policy.Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy
}

// New builds the handler. Token is required on every /api/v1 route
// (Authorization: Bearer or, for the first page load only, ?token= on "/").
func New(deps Deps, token string) http.Handler {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if !deps.Lang.Valid() {
		deps.Lang = i18n.EN
	}
	if deps.Sources.Gateway == nil {
		deps.Sources.Gateway = egress.New(deps.Policy, nil)
	}
	s := &server{deps: deps, token: []byte(token), mux: http.NewServeMux(), policy: deps.Policy}
	s.routes()
	return s
}

func (s *server) routes() {
	m := s.mux
	m.HandleFunc("GET /api/v1/meta", s.meta)
	m.HandleFunc("GET /api/v1/today", s.today)
	m.HandleFunc("GET /api/v1/projects", s.projects)
	m.HandleFunc("GET /api/v1/projects/{name}/findings", s.projectFindings)
	m.HandleFunc("GET /api/v1/findings/{id}", s.finding)
	m.HandleFunc("POST /api/v1/findings/{id}/decision", s.decision)
	m.HandleFunc("GET /api/v1/digests", s.digests)
	s.sourceRoutes()
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		s.fail(w, http.StatusNotFound, i18n.T(s.answerLang(r), "api.not_found"), "")
	})
	m.HandleFunc("GET /{$}", s.index)
	m.HandleFunc("GET /assets/", s.static)
	m.HandleFunc("GET /icons/", s.static)
	m.HandleFunc("GET /sw.js", s.static)
	m.HandleFunc("GET /manifest.webmanifest", s.static)
	m.HandleFunc("GET /sw-manifest.json", s.static)
}

// ServeHTTP applies the checks every request goes through, in order: the
// security headers, the Host (DNS rebinding), the Origin (cross-site
// requests) and, on the API, the token.
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	isAPI := strings.HasPrefix(r.URL.Path, "/api/")
	if isAPI {
		h.Set("Cache-Control", "no-store")
	}
	if !s.hostAllowed(r.Host) {
		s.fail(w, http.StatusMisdirectedRequest, i18n.T(s.answerLang(r), "api.bad_host"), "")
		return
	}
	if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
		s.fail(w, http.StatusForbidden, i18n.T(s.answerLang(r), "api.bad_origin"), "")
		return
	}
	if isAPI && !s.validToken(bearer(r)) {
		s.fail(w, http.StatusUnauthorized, i18n.T(s.answerLang(r), "api.unauthorized"), i18n.T(s.answerLang(r), "api.unauthorized_hint"))
		return
	}
	s.mux.ServeHTTP(w, r)
}

// hostAllowed checks the Host header against the listener's names.
func (s *server) hostAllowed(host string) bool {
	if len(s.deps.AllowedHosts) > 0 {
		for _, a := range s.deps.AllowedHosts {
			if strings.EqualFold(host, a) {
				return true
			}
		}
		return false
	}
	name, _, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	if strings.EqualFold(name, "localhost") {
		return true
	}
	ip := net.ParseIP(name)
	return ip != nil && (ip.Equal(net.IPv4(127, 0, 0, 1)) || ip.Equal(net.IPv6loopback))
}

// bearer is the token of an "Authorization: Bearer <token>" header, or "".
func bearer(r *http.Request) string {
	const prefix = "Bearer "
	a := r.Header.Get("Authorization")
	if len(a) <= len(prefix) || !strings.EqualFold(a[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(a[len(prefix):])
}

// validToken compares in constant time; an empty token is never valid.
func (s *server) validToken(t string) bool {
	if len(s.token) == 0 || t == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(t), s.token) == 1
}

// lang is the language of the answer: ?lang=, else Accept-Language (fr*
// means French), else the server's. ok is false for an unknown ?lang=.
func (s *server) lang(r *http.Request) (i18n.Lang, bool) {
	if q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("lang"))); q != "" {
		l := i18n.Lang(q)
		return l, l.Valid()
	}
	if al := r.Header.Get("Accept-Language"); al != "" {
		first := strings.ToLower(strings.TrimSpace(strings.Split(al, ",")[0]))
		if strings.HasPrefix(first, "fr") {
			return i18n.FR, true
		}
		return i18n.EN, true
	}
	return s.deps.Lang, true
}

// answerLang is lang, falling back to the server's language when ?lang= is
// unknown (for error messages).
func (s *server) answerLang(r *http.Request) i18n.Lang {
	if l, ok := s.lang(r); ok {
		return l
	}
	return s.deps.Lang
}

// writeJSON answers v with status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"error":"internal error"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}

// fail answers an ErrorBody: what went wrong and what to do ("" for nothing).
func (s *server) fail(w http.ResponseWriter, status int, what, hint string) {
	writeJSON(w, status, ErrorBody{Error: what, Hint: hint})
}

// internal answers 500 without the cause: stored errors may name files.
func (s *server) internal(w http.ResponseWriter, r *http.Request) {
	s.fail(w, http.StatusInternalServerError, i18n.T(s.answerLang(r), "api.internal"), i18n.T(s.answerLang(r), "api.internal_hint"))
}

// index serves the page. A ?token= present must be the right one: the page
// reads it from its URL once, then keeps it.
func (s *server) index(w http.ResponseWriter, r *http.Request) {
	if q := r.URL.Query(); q.Has("token") && !s.validToken(q.Get("token")) {
		s.fail(w, http.StatusUnauthorized, i18n.T(s.answerLang(r), "api.unauthorized"), i18n.T(s.answerLang(r), "api.unauthorized_hint"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if s.deps.Web != nil {
		if b, err := fs.ReadFile(s.deps.Web, "index.html"); err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(b)
			return
		}
	}
	lang := s.answerLang(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html>\n<html lang=\"%s\">\n<head><meta charset=\"utf-8\"><title>Michel</title></head>\n<body><p>%s</p></body>\n</html>\n",
		lang, html.EscapeString(i18n.T(lang, "api.no_ui")))
}

// static serves a file of the front, never a folder listing. These files
// hold no data, so they need no token.
func (s *server) static(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	if s.deps.Web == nil || name == "" || strings.HasSuffix(name, "/") || !fs.ValidPath(name) {
		http.NotFound(w, r)
		return
	}
	st, err := fs.Stat(s.deps.Web, name)
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(name, ".webmanifest") {
		// Go's mime table does not know this extension.
		w.Header().Set("Content-Type", "application/manifest+json")
	}
	http.ServeFileFS(w, r, s.deps.Web, name)
}
