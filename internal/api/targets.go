package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/collect"
	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/servererr"
	"github.com/kvarot/michel/internal/serverlog"
	"github.com/kvarot/michel/internal/serverrules"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/target"
	"github.com/kvarot/michel/internal/vulnmatch"
)

// Servers are the collaborators of the server routes.
type Servers struct {
	// Check is the check service of the servers: the registry, SSH through
	// the gateway (and the SSH agent the policy names), the collection and
	// the judging. A zero Repo makes the routes that reach a server answer
	// 503.
	Check servercheck.CheckDeps
	// Home is the user's folder, where discovery reads .ssh/config; "" reads
	// no SSH configuration (the PhpStorm files of the projects are still
	// read).
	Home string
}

// targetActor is the audit actor of the server changes made on the page.
const targetActor = decisionAuthor

// maxTargetHistory is how many checks the detail of a server lists.
const maxTargetHistory = 20

// checkBound bounds one check started from the page.
const checkBound = 15 * time.Minute

func (s *server) targetRoutes() {
	m := s.mux
	m.HandleFunc("GET /api/v1/targets", s.targetList)
	m.HandleFunc("POST /api/v1/targets", s.targetAdd)
	m.HandleFunc("POST /api/v1/targets/discover", s.targetDiscover)
	m.HandleFunc("GET /api/v1/targets/{id}", s.targetGet)
	m.HandleFunc("PATCH /api/v1/targets/{id}", s.targetPatch)
	m.HandleFunc("DELETE /api/v1/targets/{id}", s.targetDelete)
	m.HandleFunc("GET /api/v1/targets/{id}/hostkey", s.targetHostKey)
	m.HandleFunc("POST /api/v1/targets/{id}/hostkey", s.targetHostKeyConfirm)
	m.HandleFunc("POST /api/v1/targets/{id}/check", s.targetCheck)
	m.HandleFunc("GET /api/v1/targets/{id}/inventory", s.targetInventory)
	m.HandleFunc("POST /api/v1/targets/{id}/fix/{finding}", s.targetFix)
	m.HandleFunc("POST /api/v1/targets/{id}/agent-fix/{finding}", s.targetAgentFix)
	m.HandleFunc("GET /api/v1/targets/{id}/ai-consent", s.targetConsent)
	m.HandleFunc("POST /api/v1/targets/{id}/ai-consent", s.targetConsentGive)
	m.HandleFunc("DELETE /api/v1/targets/{id}/ai-consent", s.targetConsentRevoke)
	s.logRoutes()
}

// ---- views -----------------------------------------------------------------

// TargetRef names a server.
type TargetRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// TargetState is where a server stands, in one sentence. Code is one of
// inactive, checking, key_unconfirmed, check_failed, never_checked,
// findings, unread, clean.
type TargetState struct {
	Code string `json:"code"`
	Text string `json:"text"`
}

// TargetFindingView is an open or past finding of a server.
type TargetFindingView struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Rule       string   `json:"rule"`
	Package    string   `json:"package"`
	Installed  string   `json:"installed_version"`
	Fixed      []string `json:"fixed_versions"`
	SAPI       string   `json:"sapi,omitempty"`
	Location   string   `json:"location,omitempty"`
	Ecosystem  string   `json:"ecosystem"`
	Severity   string   `json:"severity"`
	Title      string   `json:"title"`
	Explain    string   `json:"explain,omitempty"`
	Status     string   `json:"status"`
	Mitigation bool     `json:"mitigation"`
	KEV        bool     `json:"kev"`
	// Urgent: the finding would send an urgent alert (servercheck.Urgent).
	Urgent    bool   `json:"urgent"`
	FirstSeen string `json:"first_seen_at"`
	LastSeen  string `json:"last_seen_at"`
}

// TargetUnseenView is something the last check could not read, and why.
type TargetUnseenView struct {
	What   string `json:"what"`
	Reason string `json:"reason"`
}

// TargetLinkView is a project that lives on the server.
type TargetLinkView struct {
	Project   string `json:"project"`
	RemoteDir string `json:"remote_dir"`
}

// TargetCheckView is one check of the history: the counts it ended with.
type TargetCheckView struct {
	At      string `json:"at"`
	New     int    `json:"new"`
	Still   int    `json:"still"`
	Gone    int    `json:"gone"`
	Unseen  int    `json:"unseen"`
	Unjudge int    `json:"unjudged"`
}

// TargetLastCheck is what the last check started since Michel runs ended
// with: its failure, in clear, when it failed.
type TargetLastCheck struct {
	At    string `json:"at"`
	OK    bool   `json:"ok"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
	Hint  string `json:"hint,omitempty"`
}

// TargetView is a server: its settings, where it stands, and (in the detail)
// its findings, what the last check could not read, its projects, its check
// history and the size of the backups Michel keeps for it.
type TargetView struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Host           string      `json:"host"`
	Port           int         `json:"port"`
	User           string      `json:"user"`
	Alias          string      `json:"alias"`
	Kind           string      `json:"kind"`
	Env            string      `json:"env"`
	Classification string      `json:"classification"`
	FixLevel       int         `json:"fix_level"`
	CheckInterval  string      `json:"check_interval"`
	Preprod        *TargetRef  `json:"preprod"`
	Executor       string      `json:"executor"`
	Sudo           string      `json:"sudo"`
	SiteURL        string      `json:"site_url"`
	AutoConfig     bool        `json:"auto_config"`
	Active         bool        `json:"active"`
	HostKey        string      `json:"host_key"`
	HostKeyPinned  bool        `json:"host_key_pinned"`
	LastCheckAt    string      `json:"last_check_at"`
	CreatedAt      string      `json:"created_at"`
	State          TargetState `json:"state"`
	Open           int         `json:"open_findings"`
	// CriticalOpen and UrgentOpen count the open findings of critical
	// severity, and the urgent ones (servercheck.Urgent: prod and KEV,
	// critical or unreadable PHP version).
	CriticalOpen int              `json:"critical_open"`
	UrgentOpen   int              `json:"urgent_open"`
	Checking     bool             `json:"checking"`
	LastCheck    *TargetLastCheck `json:"last_check"`
	// LogNew counts the errors of the logs not seen yet (new or back);
	// LogDeviations names the log privacy settings away from the recommended
	// choice (the badge); LogNoChannel says that a log is read but no
	// channel can tell anyone.
	LogNew        int      `json:"log_new"`
	LogDeviations []string `json:"log_deviations"`
	LogNoChannel  bool     `json:"log_no_channel"`

	// The detail only.
	Findings    []TargetFindingView `json:"findings,omitempty"`
	Unseen      []TargetUnseenView  `json:"unseen,omitempty"`
	Projects    []TargetLinkView    `json:"projects,omitempty"` // also in the list
	History     []TargetCheckView   `json:"history,omitempty"`
	BackupBytes *int64              `json:"backup_bytes,omitempty"`
	BackupFiles *int                `json:"backup_files,omitempty"`
	AIConsent   *bool               `json:"ai_consent,omitempty"`
	// SourceToEnable is the catalog key of the distribution database Michel
	// needs to judge the system packages it saw ("" when none is missing).
	SourceToEnable string `json:"source_to_enable,omitempty"`
}

// CandidateView is a server found on this computer, not yet added: the same
// fields POST /targets takes.
type CandidateView struct {
	Alias    string           `json:"alias"`
	Host     string           `json:"host"`
	Port     int              `json:"port"`
	User     string           `json:"user"`
	From     []string         `json:"from"`
	Projects []TargetLinkView `json:"projects"`
	Known    bool             `json:"known"`
}

// HostKeyView is GET /targets/{id}/hostkey: the fingerprint the server
// shows, to confirm. Pinned is the fingerprint Michel already trusts ("" for
// none) and Matches whether it is this one.
type HostKeyView struct {
	Fingerprint string `json:"fingerprint"`
	KeyType     string `json:"key_type"`
	Pinned      string `json:"pinned"`
	Matches     bool   `json:"matches"`
}

// TargetBody is the body of POST /targets (a server added by hand, or from a
// candidate: its fields) and, with pointers, of PATCH /targets/{id}.
type TargetBody struct {
	Name           string           `json:"name"`
	Alias          string           `json:"alias"`
	Host           string           `json:"host"`
	Port           int              `json:"port"`
	User           string           `json:"user"`
	Kind           string           `json:"kind"`
	Env            string           `json:"env"`
	Classification string           `json:"classification"`
	FixLevel       *int             `json:"fix_level"`
	CheckInterval  string           `json:"check_interval"`
	Preprod        string           `json:"preprod"`
	Executor       string           `json:"executor"`
	Sudo           string           `json:"sudo"`
	SiteURL        string           `json:"site_url"`
	AutoConfig     bool             `json:"auto_config"`
	Links          []TargetLinkBody `json:"links"`
}

// TargetLinkBody ties a project (its name) to the folder it lives in on the
// server.
type TargetLinkBody struct {
	Project   string `json:"project"`
	RemoteDir string `json:"remote_dir"`
}

// TargetPatch is the body of PATCH /targets/{id}: the fields to change.
type TargetPatch struct {
	Alias          *string `json:"alias"`
	Host           *string `json:"host"`
	Port           *int    `json:"port"`
	User           *string `json:"user"`
	Kind           *string `json:"kind"`
	Env            *string `json:"env"`
	Classification *string `json:"classification"`
	FixLevel       *int    `json:"fix_level"`
	CheckInterval  *string `json:"check_interval"`
	Preprod        *string `json:"preprod"`
	Executor       *string `json:"executor"`
	Sudo           *string `json:"sudo"`
	SiteURL        *string `json:"site_url"`
	AutoConfig     *bool   `json:"auto_config"`
	Active         *bool   `json:"active"`
}

// HostKeyConfirm is the body of POST /targets/{id}/hostkey.
type HostKeyConfirm struct {
	Fingerprint string `json:"fingerprint"`
	// Replace must be true to replace a fingerprint already confirmed with
	// another one: a changed key is never accepted by the usual confirmation.
	Replace bool `json:"replace"`
}

// ---- text of the server, shown without the workstation -----------------------

var (
	// driveRe is a path with a drive letter, after anything that cannot end a
	// word (so "www:/home" is not one).
	driveRe = regexp.MustCompile(`(^|[^A-Za-z0-9._+-])[A-Za-z]:[\\/][^\s"']*`)
	// uncRe is a share path, fileRe a file address.
	uncRe  = regexp.MustCompile(`\\\\[^\s\\]+\\[^\s"']*`)
	fileRe = regexp.MustCompile(`(?i)file:/+[^\s"']*`)
)

// localPaths replaces the paths of a Windows computer (a drive, a share) and
// the file addresses in s: what a server's text never holds, and what must not
// leave if it does.
func localPaths(s string) string {
	s = driveRe.ReplaceAllString(s, "${1}<path>")
	s = uncRe.ReplaceAllString(s, "<path>")
	return fileRe.ReplaceAllString(s, "<path>")
}

// tilde writes the home folder of the server's own SSH user as ~: the user's
// name is the user's own business, and a path under /home/<user>/ reads the
// same with ~/. Other users' folders stay as they are.
func tilde(user, s string) string {
	home := "/home/" + user
	if user == "" || !strings.Contains(s, home) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], home) && (i == 0 || strings.IndexByte(" \t\"'=:,;([", s[i-1]) >= 0) {
			if j := i + len(home); j == len(s) || strings.IndexByte("/ \t\"',;)]", s[j]) >= 0 {
				b.WriteByte('~')
				i = j
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// srvText makes a text read on a server safe to answer: control characters
// removed, a Windows path replaced, the SSH user's home written as ~.
func srvText(user, s string) string {
	return tilde(user, localPaths(scan.SanitizeText(s)))
}

func srvTexts(user string, in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, srvText(user, s))
	}
	return out
}

// ---- running checks ----------------------------------------------------------

// checkTracker follows the checks started from the page: one at a time per
// server, and how the last one ended.
type checkTracker struct {
	mu   sync.Mutex
	runs map[string]*checkRun
}

type checkRun struct {
	running bool
	at      time.Time
	code    string
	ok      bool
}

func (c *checkTracker) begin(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.runs == nil {
		c.runs = map[string]*checkRun{}
	}
	if r := c.runs[id]; r != nil && r.running {
		return false
	}
	c.runs[id] = &checkRun{running: true}
	return true
}

func (c *checkTracker) end(id string, at time.Time, code string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runs[id] = &checkRun{at: at, code: code, ok: code == ""}
}

func (c *checkTracker) get(id string) (checkRun, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.runs[id]
	if r == nil {
		return checkRun{}, false
	}
	return *r, true
}

// ---- errors -------------------------------------------------------------------

// targetFailure maps an error of the registry, of SSH or of a check to its
// HTTP status and catalog key. The key's sentence is all that is answered:
// the errors themselves can hold a socket path, a user or an address.
func targetFailure(err error) (status int, key string) {
	key = servererr.Key(err)
	if key == "" {
		return 0, ""
	}
	if st, ok := targetStatus[key]; ok {
		return st, key
	}
	return http.StatusBadRequest, key
}

// targetStatus is the HTTP status of the keys that are not a plain 400.
var targetStatus = map[string]int{
	"api.target.not_found":       http.StatusNotFound,
	"api.target.duplicate":       http.StatusConflict,
	"api.target.inactive":        http.StatusConflict,
	"api.target.no_agent":        http.StatusServiceUnavailable,
	"api.target.no_key_accepted": http.StatusBadGateway,
	"api.target.hostkey_unknown": http.StatusConflict,
	"api.target.hostkey_changed": http.StatusConflict,
	"api.target.denied":          http.StatusForbidden,
	"api.target.timeout":         http.StatusGatewayTimeout,
}

// failedBody answers a coded refusal: the sentence in lang and its key.
func (s *server) failedBody(w http.ResponseWriter, status int, lang i18n.Lang, key, hint string) {
	body := FixErrorBody{Error: i18n.T(lang, key), Code: key}
	if hint != "" && i18n.Has(hint) {
		body.Hint = i18n.T(lang, hint)
	}
	writeJSON(w, status, body)
}

// targetRefused answers an error of a server route. reach is true for the
// routes that connect to the server: any other failure then reads "Michel
// could not reach the server" (502), else it is an internal error.
func (s *server) targetRefused(w http.ResponseWriter, r *http.Request, lang i18n.Lang, err error, reach bool) {
	if status, key := targetFailure(err); key != "" {
		s.failedBody(w, status, lang, key, key+"_hint")
		return
	}
	if reach {
		s.failedBody(w, http.StatusBadGateway, lang, servererr.Unreachable, servererr.Unreachable+"_hint")
		return
	}
	s.internal(w, r)
}

// codeOfCheck is the catalog key a failed check is remembered by ("" when
// it succeeded).
func codeOfCheck(err error) string {
	if err == nil {
		return ""
	}
	if key := servererr.Key(err); key != "" {
		return key
	}
	return servererr.CheckFailed
}

// ---- helpers --------------------------------------------------------------------

func (s *server) targets() *target.Repo { return target.NewRepo(s.deps.Store) }

// targetOf reads the server of the route's {id} (its id or its name); it
// answers 404 itself.
func (s *server) targetOf(w http.ResponseWriter, r *http.Request, lang i18n.Lang) (target.Target, bool) {
	t, err := s.targets().Get(r.Context(), r.PathValue("id"))
	if err != nil {
		s.targetRefused(w, r, lang, err, false)
		return target.Target{}, false
	}
	return t, true
}

// reachable says whether the routes that connect to a server can work here
// (michel serve gave them the check service); it answers 503 itself.
func (s *server) reachable(w http.ResponseWriter, lang i18n.Lang) bool {
	if s.deps.Servers.Check.Repo == nil || s.deps.Servers.Check.SSH.Gateway == nil {
		s.fail(w, http.StatusServiceUnavailable, i18n.T(lang, "api.target.unavailable"), "")
		return false
	}
	return true
}

func (s *server) targetAudit(ctx context.Context, action, id, result string, ev map[string]any) error {
	_, err := s.deps.Audit.Record(ctx, audit.Event{Actor: targetActor, Action: action, Target: id, Result: result, Evidence: ev})
	return err
}

// resolveLinks turns the project names of a body into links; false (400
// answered) for an unknown project or a folder that is not an absolute path.
func (s *server) resolveLinks(w http.ResponseWriter, r *http.Request, lang i18n.Lang, in []TargetLinkBody) ([]target.Link, bool) {
	var out []target.Link
	seen := map[string]bool{}
	for _, l := range in {
		p, err := project.NewRepo(s.deps.Store).Get(r.Context(), strings.TrimSpace(l.Project))
		if errors.Is(err, project.ErrNotFound) {
			s.fail(w, http.StatusBadRequest, i18n.T(lang, "api.project_not_found"), "")
			return nil, false
		}
		if err != nil {
			s.internal(w, r)
			return nil, false
		}
		if target.ValidateRemoteDir(l.RemoteDir) != nil {
			s.failedBody(w, http.StatusBadRequest, lang, "api.target.bad_remote_dir", "api.target.bad_remote_dir_hint")
			return nil, false
		}
		if seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		out = append(out, target.Link{ProjectID: p.ID, RemoteDir: l.RemoteDir})
	}
	return out, true
}

// changeRules writes the network rules to add, then removes those to remove
// (one edit each, in the policy file), reloads the policy and hands it to the
// gateway. It returns the rules to add that were not in force yet, so a
// caller can take them back. Adding a server is the user's opt-in; removing
// it takes the opt-in back.
func (s *server) changeRules(add, remove []policy.AllowRule) (added, removed []policy.AllowRule, err error) {
	if s.deps.PolicyPath == "" || s.deps.Reload == nil {
		return nil, nil, nil
	}
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	ctx := context.Background()
	repo := s.targets()
	// What is in force is read from the file itself: a rule the user wrote
	// since Michel started counts as theirs.
	present := s.currentPolicy().Sovereignty.Network.Allow
	if p, err := s.deps.Reload(); err == nil {
		present = p.Sovereignty.Network.Allow
	}
	added = target.NewRules(present, add)
	// Only the rules Michel wrote are taken back: a rule the user wrote by
	// hand stays.
	if removed, err = repo.OwnedOnly(ctx, remove); err != nil {
		return nil, nil, err
	}
	if len(add) > 0 {
		if _, err := policy.AddAllowRules(s.deps.PolicyPath, add...); err != nil {
			return nil, nil, err
		}
		if err := repo.RecordRules(ctx, added); err != nil {
			return added, nil, err
		}
	}
	if len(removed) > 0 {
		if _, err := policy.RemoveAllowRules(s.deps.PolicyPath, removed...); err != nil {
			return added, nil, err
		}
		if err := repo.ForgetRules(ctx, removed); err != nil {
			return added, removed, err
		}
	}
	p, err := s.reload()
	if err != nil {
		return added, removed, err
	}
	if g := s.deps.Sources.Gateway; g != nil {
		g.SetRules(p.Sovereignty.Network.Allow)
	}
	return added, removed, nil
}

// otherTargets are the servers other than id.
func (s *server) otherTargets(ctx context.Context, id string) ([]target.Target, error) {
	all, err := s.targets().List(ctx)
	if err != nil {
		return nil, err
	}
	out := all[:0:0]
	for _, t := range all {
		if t.ID != id {
			out = append(out, t)
		}
	}
	return out, nil
}

var ruleKeys = sync.OnceValue(func() map[string]string {
	out := map[string]string{}
	set, err := serverrules.Rules()
	if err != nil {
		return out
	}
	for _, r := range set.Config {
		out[r.ID] = r.Key
	}
	for _, a := range set.Upstream {
		out[a.ID] = a.Key
		for _, al := range a.Aliases {
			out[al] = a.Key
		}
	}
	for _, r := range set.Listen {
		if r.Key != "" {
			out[r.Rule] = r.Key
		}
	}
	return out
})

func targetFindingView(lang i18n.Lang, user string, f scan.Finding) TargetFindingView {
	sev, _ := scan.EffectiveSeverity(f)
	v := TargetFindingView{ID: f.ID, Kind: f.Kind, Ecosystem: f.Ecosystem, Rule: srvText(user, f.OSVID), Package: srvText(user, f.Package),
		Installed: srvText(user, f.InstalledVersion), Fixed: srvTexts(user, f.FixedVersions), SAPI: srvText(user, f.SAPI),
		Location: srvText(user, f.Location), Severity: severityOf(sev), Title: srvText(user, f.Summary), Status: f.Status,
		Mitigation: f.Mitigation, KEV: f.KEV, FirstSeen: f.FirstSeenAt, LastSeen: f.LastSeenAt}
	if f.Kind == scan.KindServerPackage {
		v.Title = i18n.T(lang, "api.target.package_title", v.Package, v.Installed, v.Rule)
		if len(v.Fixed) > 0 {
			v.Title = i18n.T(lang, "api.target.package_title_fixed", v.Package, v.Installed, v.Rule, v.Fixed[0])
		}
	}
	if key := ruleKeys()[f.OSVID]; key != "" && i18n.Has(key+".title") {
		v.Title = i18n.T(lang, key+".title")
		if i18n.Has(key + ".explain") {
			v.Explain = i18n.T(lang, key+".explain")
		}
	}
	return v
}

// openStatus tells whether a finding still counts for the state of the
// server: not gone, not decided.
func openStatus(status string) bool { return status == scan.StatusNew || status == scan.StatusPending }

// targetView builds the view of t; detail adds the findings, what could not
// be read, the projects, the history and the backups.
func (s *server) targetView(ctx context.Context, t target.Target, lang i18n.Lang, detail bool) (TargetView, error) {
	repo := s.targets()
	v := TargetView{ID: t.ID, Name: srvText("", t.Name), Host: srvText("", t.Host), Port: t.Port, User: srvText("", t.User), Alias: srvText("", t.Alias),
		Kind: string(t.Kind), Env: string(t.Env), Classification: string(t.Classification), FixLevel: t.FixLevel,
		CheckInterval: target.IntervalText(t.CheckInterval), Executor: string(t.Executor), Sudo: string(t.Sudo),
		SiteURL: srvText("", t.SiteURL), AutoConfig: t.AutoConfig, Active: t.Active, HostKey: t.HostKey, HostKeyPinned: t.HostKey != "",
		LastCheckAt: stamp(t.LastCheckAt), CreatedAt: stamp(t.CreatedAt)}
	if t.PreprodID != "" {
		if p, err := repo.Get(ctx, t.PreprodID); err == nil {
			v.Preprod = &TargetRef{ID: p.ID, Name: srvText("", p.Name)}
		}
	}
	findings, err := scan.NewRepo(s.deps.Store).ListServerFindings(ctx, t.ID)
	if err != nil {
		return TargetView{}, err
	}
	for _, f := range findings {
		urgent := servercheck.Urgent(t, f)
		if openStatus(f.Status) {
			v.Open++
			if sev, _ := scan.EffectiveSeverity(f); sev == "critical" {
				v.CriticalOpen++
			}
			if urgent {
				v.UrgentOpen++
			}
		}
		if detail && f.Status != scan.StatusGone {
			fv := targetFindingView(lang, t.User, f)
			fv.Urgent = urgent
			v.Findings = append(v.Findings, fv)
		}
	}
	unread := 0
	var inv target.Inventory
	var haveInv bool
	if detail || !t.LastCheckAt.IsZero() {
		if inv, haveInv, err = repo.LatestInventory(ctx, t.ID); err != nil {
			return TargetView{}, err
		}
		if haveInv {
			unread = len(inv.Unseen)
		}
	}
	run, tracked := s.checks.get(t.ID)
	v.Checking = tracked && run.running
	if tracked && !run.running {
		lc := &TargetLastCheck{At: stamp(run.at), OK: run.ok}
		if !run.ok {
			lc.Code, lc.Error = run.code, i18n.T(lang, run.code)
			if i18n.Has(run.code + "_hint") {
				lc.Hint = i18n.T(lang, run.code+"_hint")
			}
		}
		v.LastCheck = lc
	}
	v.State = s.targetState(lang, t, v, run, tracked, unread)
	// The projects that live on the server, in the list too: a project's card
	// links to its servers.
	links, err := repo.Links(ctx, t.ID)
	if err != nil {
		return TargetView{}, err
	}
	for _, l := range links {
		p, err := project.NewRepo(s.deps.Store).Get(ctx, l.ProjectID)
		if err != nil {
			continue
		}
		v.Projects = append(v.Projects, TargetLinkView{Project: p.Name, RemoteDir: srvText(t.User, l.RemoteDir)})
	}
	// The log fields, in the list too: the badges and the count of new errors.
	if err := s.logSummary(ctx, t, &v); err != nil {
		return TargetView{}, err
	}
	if !detail {
		return v, nil
	}
	if haveInv {
		for _, u := range inv.Unseen {
			v.Unseen = append(v.Unseen, TargetUnseenView{What: srvText(t.User, u.What), Reason: reasonText(lang, t.User, u.Reason)})
		}
		if v.SourceToEnable, err = s.sourceToEnable(ctx, inv); err != nil {
			return TargetView{}, err
		}
	}
	if v.History, err = s.targetHistory(ctx, t.ID); err != nil {
		return TargetView{}, err
	}
	n, files, err := fix.NewRepo(s.deps.Store).BackupSize(ctx, t.ID)
	if err != nil {
		return TargetView{}, err
	}
	if files > 0 {
		v.BackupBytes, v.BackupFiles = &n, &files
	}
	if d, ok := s.fixDepsQuiet(lang); ok {
		if c, err := fix.ServerConsent(ctx, d, t.ID); err == nil {
			v.AIConsent = &c
		}
	}
	return v, nil
}

// sourceToEnable is the distribution database the packages of inv need and
// that is not turned on ("" when there is none to turn on, or no package
// manager answered), as the check judges it.
func (s *server) sourceToEnable(ctx context.Context, inv target.Inventory) (string, error) {
	eco, ok := vulnmatch.Ecosystem(inv.OS)
	if !ok || len(inv.Packages) == 0 {
		return "", nil
	}
	enabled, err := osvdb.Enabled(ctx, source.NewRepo(s.deps.Store), nil)
	if err != nil {
		return "", err
	}
	base, _, _ := strings.Cut(eco, ":")
	if slices.Contains(enabled, base) {
		return "", nil
	}
	return vulnmatch.CatalogKey(eco), nil
}

// reasonText is the reason a read failed: the catalog sentence when the
// stored reason is a key, else the text.
func reasonText(lang i18n.Lang, user, reason string) string {
	if i18n.Has(reason) {
		return i18n.T(lang, reason)
	}
	return srvText(user, reason)
}

func (s *server) targetState(lang i18n.Lang, t target.Target, v TargetView, run checkRun, tracked bool, unread int) TargetState {
	st := func(code string, args ...any) TargetState {
		return TargetState{Code: code, Text: i18n.T(lang, "api.target.state."+code, args...)}
	}
	switch {
	case !t.Active:
		return st("inactive")
	case v.Checking:
		return st("checking")
	case tracked && !run.ok:
		return TargetState{Code: "check_failed", Text: i18n.T(lang, "api.target.state.check_failed", i18n.T(lang, run.code))}
	case t.LastCheckAt.IsZero() && t.HostKey == "":
		return st("key_unconfirmed")
	case t.LastCheckAt.IsZero():
		return st("never_checked")
	case v.Open > 0:
		return TargetState{Code: "findings", Text: i18n.N(lang, "api.target.state.findings", v.Open)}
	case unread > 0:
		return TargetState{Code: "unread", Text: i18n.N(lang, "api.target.state.unread", unread)}
	}
	return st("clean")
}

// targetHistory lists the last checks from the audit log: the counts of
// each, nothing else.
func (s *server) targetHistory(ctx context.Context, id string) ([]TargetCheckView, error) {
	rows, err := s.deps.Store.DB().QueryContext(ctx, `SELECT ts, evidence FROM audit_event WHERE action = 'target.check' AND target = ? ORDER BY rowid DESC LIMIT ?`, id, maxTargetHistory)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TargetCheckView{}
	for rows.Next() {
		var at, ev string
		if err := rows.Scan(&at, &ev); err != nil {
			return nil, err
		}
		var m struct {
			New      int `json:"new"`
			Still    int `json:"still"`
			Gone     int `json:"gone"`
			Unseen   int `json:"unseen"`
			Unjudged int `json:"unjudged"`
		}
		_ = json.Unmarshal([]byte(ev), &m)
		out = append(out, TargetCheckView{At: at, New: m.New, Still: m.Still, Gone: m.Gone, Unseen: m.Unseen, Unjudge: m.Unjudged})
	}
	return out, rows.Err()
}

// fixDepsQuiet is fixDeps without the 503.
func (s *server) fixDepsQuiet(lang i18n.Lang) (fix.Deps, bool) {
	if s.deps.Fix == nil {
		return fix.Deps{}, false
	}
	d := *s.deps.Fix
	d.Policy = s.currentPolicy()
	d.LivePolicy = s.currentPolicy
	d.Lang = lang
	d.Actor = fixActor
	if s.deps.Reload != nil {
		d.Reload = s.reload
	}
	return d, true
}

// ---- routes -----------------------------------------------------------------------

func (s *server) targetList(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	list, err := s.targets().List(r.Context())
	if err != nil {
		s.internal(w, r)
		return
	}
	out := []TargetView{}
	for _, t := range list {
		v, err := s.targetView(r.Context(), t, lang, false)
		if err != nil {
			s.internal(w, r)
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) targetGet(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	t, ok := s.targetOf(w, r, lang)
	if !ok {
		return
	}
	v, err := s.targetView(r.Context(), t, lang, true)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *server) targetDiscover(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	projects, err := project.NewRepo(s.deps.Store).List(ctx)
	if err != nil {
		s.internal(w, r)
		return
	}
	active := projects[:0:0]
	names := map[string]string{}
	for _, p := range projects {
		if p.Active {
			active = append(active, p)
			names[p.ID] = p.Name
		}
	}
	existing, err := s.targets().List(ctx)
	if err != nil {
		s.internal(w, r)
		return
	}
	cands, err := target.Discover(ctx, s.deps.Servers.Home, active, existing)
	if err != nil {
		s.failedBody(w, http.StatusUnprocessableEntity, lang, "api.target.discover_failed", "api.target.discover_failed_hint")
		return
	}
	out := []CandidateView{}
	for _, c := range cands {
		v := CandidateView{Alias: srvText("", c.Alias), Host: srvText("", c.Host), Port: c.Port, User: srvText("", c.User),
			From: srvTexts("", c.From), Projects: []TargetLinkView{}, Known: c.Known}
		if v.Port == 0 {
			v.Port = 22
		}
		for _, l := range c.Projects {
			if name := names[l.ProjectID]; name != "" {
				v.Projects = append(v.Projects, TargetLinkView{Project: name, RemoteDir: srvText("", l.RemoteDir)})
			}
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) targetAdd(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var b TargetBody
	if !s.readJSON(w, r, &b) {
		return
	}
	ctx := r.Context()
	t := target.Target{Name: strings.TrimSpace(b.Name), Alias: strings.TrimSpace(b.Alias), Host: strings.TrimSpace(b.Host), Port: b.Port,
		User: strings.TrimSpace(b.User), Kind: target.Kind(b.Kind), Env: target.Env(b.Env), Classification: policy.Classification(b.Classification),
		Executor: target.Executor(b.Executor), Sudo: target.SudoMode(b.Sudo), SiteURL: strings.TrimSpace(b.SiteURL), AutoConfig: b.AutoConfig,
		FixLevel: 1}
	if t.Name == "" {
		t.Name = t.Alias
	}
	if t.Name == "" {
		t.Name = t.Host
	}
	if t.Kind == "" {
		t.Kind = target.KindVPS
	}
	if b.FixLevel != nil {
		t.FixLevel = *b.FixLevel
	}
	if err := target.Check(t); err != nil {
		s.targetRefused(w, r, lang, err, false)
		return
	}
	var err error
	if t.CheckInterval, err = target.ParseInterval(b.CheckInterval); err != nil {
		s.targetRefused(w, r, lang, err, false)
		return
	}
	if t.PreprodID, err = s.targets().ResolvePreprod(ctx, t, b.Preprod); err != nil {
		s.targetRefused(w, r, lang, err, false)
		return
	}
	links, ok := s.resolveLinks(w, r, lang, b.Links)
	if !ok {
		return
	}
	added, err := s.targets().Add(ctx, t)
	if err != nil {
		s.targetRefused(w, r, lang, err, false)
		return
	}
	for _, l := range links {
		l.TargetID = added.ID
		if err := s.targets().Link(ctx, l); err != nil {
			_ = s.targets().Remove(ctx, added.ID)
			s.internal(w, r)
			return
		}
	}
	fresh, _, err := s.changeRules(target.AllowRules(added), nil)
	n := len(fresh)
	if err != nil {
		_ = s.targets().Remove(ctx, added.ID)
		s.failedBody(w, http.StatusInternalServerError, lang, "api.target.allow_failed", "api.target.allow_failed_hint")
		return
	}
	if err := s.targetAudit(ctx, "target.add", added.ID, "ok", map[string]any{"name": added.Name, "kind": string(added.Kind), "env": string(added.Env),
		"fix_level": added.FixLevel, "links": len(links), "rules_written": n}); err != nil {
		s.internal(w, r)
		return
	}
	v, err := s.targetView(ctx, added, lang, true)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (s *server) targetPatch(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var p TargetPatch
	if !s.readJSON(w, r, &p) {
		return
	}
	t, ok := s.targetOf(w, r, lang)
	if !ok {
		return
	}
	ctx := r.Context()
	old := t
	var changed []string
	set := func(name string, do func()) {
		do()
		changed = append(changed, name)
	}
	str := func(v *string, name string, dst *string) {
		if v != nil {
			set(name, func() { *dst = strings.TrimSpace(*v) })
		}
	}
	str(p.Alias, "alias", &t.Alias)
	str(p.Host, "host", &t.Host)
	str(p.User, "user", &t.User)
	str(p.SiteURL, "site_url", &t.SiteURL)
	if p.Port != nil {
		set("port", func() { t.Port = *p.Port })
	}
	if p.Kind != nil {
		set("kind", func() { t.Kind = target.Kind(*p.Kind) })
	}
	if p.Env != nil {
		set("env", func() { t.Env = target.Env(*p.Env) })
	}
	if p.Classification != nil {
		set("classification", func() { t.Classification = policy.Classification(*p.Classification) })
	}
	if p.FixLevel != nil {
		set("fix_level", func() { t.FixLevel = *p.FixLevel })
	}
	if p.Executor != nil {
		set("executor", func() { t.Executor = target.Executor(*p.Executor) })
	}
	if p.Sudo != nil {
		set("sudo", func() { t.Sudo = target.SudoMode(*p.Sudo) })
	}
	if p.AutoConfig != nil {
		set("auto_config", func() { t.AutoConfig = *p.AutoConfig })
	}
	if p.Active != nil {
		set("active", func() { t.Active = *p.Active })
	}
	var err error
	if p.CheckInterval != nil {
		if t.CheckInterval, err = target.ParseInterval(*p.CheckInterval); err != nil {
			s.targetRefused(w, r, lang, err, false)
			return
		}
		changed = append(changed, "check_interval")
	}
	if err := target.Check(t); err != nil {
		s.targetRefused(w, r, lang, err, false)
		return
	}
	if err := s.targets().CheckEnv(ctx, t); err != nil {
		s.targetRefused(w, r, lang, err, false)
		return
	}
	if p.Preprod != nil {
		if t.PreprodID, err = s.targets().ResolvePreprod(ctx, t, *p.Preprod); err != nil {
			s.targetRefused(w, r, lang, err, false)
			return
		}
		changed = append(changed, "preprod")
	}
	// A server that moved is not the one whose fingerprint was confirmed:
	// Update clears the pin with the address.
	portOf := func(p int) int {
		if p == 0 {
			return 22
		}
		return p
	}
	moved := t.Host != old.Host || portOf(t.Port) != portOf(old.Port)
	// The new rules go in first, so a refusal of the policy file changes
	// nothing; they come out again when the update fails.
	var fresh []policy.AllowRule
	if t.Host != old.Host || t.SiteURL != old.SiteURL {
		if fresh, _, err = s.changeRules(target.AllowRules(t), nil); err != nil {
			s.failedBody(w, http.StatusInternalServerError, lang, "api.target.allow_failed", "api.target.allow_failed_hint")
			return
		}
	}
	if err := s.targets().Update(ctx, t); err != nil {
		if len(fresh) > 0 {
			_, _, _ = s.changeRules(nil, fresh)
		}
		s.targetRefused(w, r, lang, err, false)
		return
	}
	// What the old address and site needed, and no other server uses, goes.
	released := 0
	if t.Host != old.Host || t.SiteURL != old.SiteURL {
		if others, err := s.otherTargets(ctx, t.ID); err == nil {
			gone := target.ReleasedRules(old, append(others, t))
			if _, done, err := s.changeRules(nil, gone); err == nil {
				released = len(done)
			}
		}
	}
	rules := len(fresh)
	if err := s.targetAudit(ctx, "target.update", t.ID, "ok", map[string]any{"name": t.Name, "changed": changed, "rules_written": rules,
		"rules_removed": released, "host_key_reset": moved && old.HostKey != ""}); err != nil {
		s.internal(w, r)
		return
	}
	got, err := s.targets().Get(ctx, t.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	v, err := s.targetView(ctx, got, lang, true)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// targetDelete takes the server out of Michel: nothing is done on the server.
// A fix that is running on it keeps it there until it ends.
func (s *server) targetDelete(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	t, ok := s.targetOf(w, r, lang)
	if !ok {
		return
	}
	ctx := r.Context()
	// No check of this server runs (the scheduler's, the page's) while it is
	// removed, and no fix is on it.
	unlock, free := servercheck.TryLock(t.ID)
	if !free {
		s.failedBody(w, http.StatusConflict, lang, "api.target.busy", "api.target.busy_hint")
		return
	}
	defer unlock()
	// Nor does a read of its logs, which would write rows back.
	logUnlock, logFree := serverlog.TryLock(t.ID)
	if !logFree {
		s.logRefused(w, http.StatusConflict, lang, "api.logs.busy")
		return
	}
	defer logUnlock()
	block, err := fix.NewRepo(s.deps.Store).TargetBlock(ctx, t.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	switch block {
	case "":
	case fix.BlockUnknown:
		s.failedBody(w, http.StatusConflict, lang, "api.target.busy_unknown", "api.target.busy_unknown_hint")
		return
	case fix.BlockApproved:
		s.failedBody(w, http.StatusConflict, lang, "api.target.busy_approved", "api.target.busy_approved_hint")
		return
	default:
		s.failedBody(w, http.StatusConflict, lang, "api.target.busy", "api.target.busy_hint")
		return
	}
	others, err := s.otherTargets(ctx, t.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	dependents := 0
	for _, o := range others {
		if o.PreprodID == t.ID {
			dependents++
		}
	}
	// What Michel read in its logs goes first: errors, text, sources, settings. If
	// that fails the server stays, and removing it can be tried again (once it is
	// gone, nothing could erase the logs). The page leaving does not interrupt it.
	dctx, cancel := s.detached(r)
	defer cancel()
	erased, forgetErr := serverlog.ForgetTargetAudited(dctx, s.serverLogs(), s.deps.Audit, targetActor, t.ID)
	if !erased {
		s.failedBody(w, http.StatusInternalServerError, lang, "api.target.logs_failed", "api.target.logs_failed_hint")
		return
	}
	if err := s.targets().Remove(dctx, t.ID); err != nil {
		s.targetRefused(w, r, lang, err, false)
		return
	}
	// The opt-in goes with the server, except for what another still uses.
	released := target.ReleasedRules(t, others)
	removed, rulesFailed := 0, false
	if len(released) > 0 {
		_, gone, err := s.changeRules(nil, released)
		removed, rulesFailed = len(gone), err != nil
	}
	if err := s.targetAudit(ctx, "target.remove", t.ID, "ok", map[string]any{"name": t.Name, "rules_removed": removed, "rules_error": rulesFailed,
		"preprod_cleared": dependents, "logs_error": forgetErr != nil}); err != nil {
		s.internal(w, r)
		return
	}
	if rulesFailed {
		// The server is gone; its network rules could not be taken back.
		writeJSON(w, http.StatusOK, map[string]bool{"removed": true, "rules_not_removed": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"removed": true})
}

// readFingerprint connects to the server (no sign-in) and reads the host key
// it shows.
func (s *server) readFingerprint(r *http.Request, t target.Target) (fp, typ string, err error) {
	ctx, cancel := s.detached(r)
	defer cancel()
	return sshx.FingerprintKey(ctx, s.deps.Servers.Check.SSH, t)
}

func (s *server) targetHostKey(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok || !s.reachable(w, lang) {
		return
	}
	t, ok := s.targetOf(w, r, lang)
	if !ok {
		return
	}
	extend(w)
	fp, typ, err := s.readFingerprint(r, t)
	if err != nil {
		s.targetRefused(w, r, lang, err, true)
		return
	}
	writeJSON(w, http.StatusOK, HostKeyView{Fingerprint: fp, KeyType: typ, Pinned: t.HostKey, Matches: t.HostKey == fp})
}

// targetHostKeyConfirm pins the fingerprint the user read, but only when the
// server shows it still: Michel reads it again, so a fingerprint typed wrong
// (or a server that changed meanwhile) pins nothing (409).
func (s *server) targetHostKeyConfirm(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok || !s.reachable(w, lang) {
		return
	}
	var b HostKeyConfirm
	if !s.readJSON(w, r, &b) {
		return
	}
	t, ok := s.targetOf(w, r, lang)
	if !ok {
		return
	}
	ctx := r.Context()
	b.Fingerprint = strings.TrimSpace(b.Fingerprint)
	if b.Fingerprint == "" {
		s.failedBody(w, http.StatusBadRequest, lang, "api.target.need_fingerprint", "api.target.need_fingerprint_hint")
		return
	}
	extend(w)
	fp, _, err := s.readFingerprint(r, t)
	if err != nil {
		s.targetRefused(w, r, lang, err, true)
		return
	}
	if fp != b.Fingerprint {
		_ = s.targetAudit(ctx, "target.hostkey", t.ID, "refused", map[string]any{"name": t.Name, "reason": "fingerprint mismatch"})
		s.failedBody(w, http.StatusConflict, lang, "api.target.hostkey_mismatch", "api.target.hostkey_mismatch_hint")
		return
	}
	if t.HostKey != "" && t.HostKey != fp && !b.Replace {
		_ = s.targetAudit(ctx, "target.hostkey", t.ID, "refused", map[string]any{"name": t.Name, "reason": "key changed, replace not asked"})
		s.failedBody(w, http.StatusConflict, lang, "api.target.hostkey_changed", "api.target.hostkey_changed_hint")
		return
	}
	if err := s.targets().SetHostKey(ctx, t.ID, fp); err != nil {
		s.targetRefused(w, r, lang, err, false)
		return
	}
	if err := s.targetAudit(ctx, "target.hostkey", t.ID, "ok", map[string]any{"name": t.Name, "fingerprint": fp, "replaced": t.HostKey != "" && t.HostKey != fp}); err != nil {
		s.internal(w, r)
		return
	}
	got, err := s.targets().Get(ctx, t.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	v, err := s.targetView(ctx, got, lang, true)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// targetCheck starts a check in the background and answers 202 at once; the
// server's detail tells how it ended.
func (s *server) targetCheck(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok || !s.reachable(w, lang) {
		return
	}
	t, ok := s.targetOf(w, r, lang)
	if !ok {
		return
	}
	if !t.Active {
		s.targetRefused(w, r, lang, servercheck.ErrInactive, false)
		return
	}
	if !s.checks.begin(t.ID) {
		s.failedBody(w, http.StatusConflict, lang, "api.target.check_running", "")
		return
	}
	cd := s.deps.Servers.Check
	started := s.goBackground(func(ctx context.Context) {
		ctx, cancel := context.WithTimeout(ctx, checkBound)
		defer cancel()
		_, err := servercheck.Check(ctx, cd, t.ID)
		s.checks.end(t.ID, s.deps.Now(), codeOfCheck(err))
	})
	if !started {
		s.checks.end(t.ID, s.deps.Now(), "api.target.unavailable")
		s.fail(w, http.StatusServiceUnavailable, i18n.T(lang, "api.target.unavailable"), "")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"started": true})
}

// ---- the inventory --------------------------------------------------------------------

// InventoryView is what the last check read on a server: no secret value
// (a directive marked secret has none), and the SSH user's home written ~.
type InventoryView struct {
	TargetID   string               `json:"target_id"`
	CheckedAt  string               `json:"checked_at"`
	OS         InventoryOS          `json:"os"`
	PHP        []InventoryPHP       `json:"php"`
	Web        []InventoryWeb       `json:"web_servers"`
	Packages   []InventoryPackage   `json:"packages"`
	Directives []InventoryDirective `json:"directives"`
	Files      []InventoryFile      `json:"files"`
	Unseen     []TargetUnseenView   `json:"unseen"`
	Site       InventorySite        `json:"site"`
}

type InventoryOS struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
	Pretty    string `json:"pretty"`
	Kernel    string `json:"kernel"`
}

type InventoryPHP struct {
	SAPI         string   `json:"sapi"`
	Binary       string   `json:"binary"`
	Version      string   `json:"version"`
	FromPackage  string   `json:"from_package"`
	Modules      []string `json:"modules"`
	LoadedIni    string   `json:"loaded_ini"`
	ScannedDir   string   `json:"scanned_dir"`
	ScannedFiles []string `json:"scanned_files"`
	PoolFiles    []string `json:"pool_files"`
}

type InventoryWeb struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type InventoryPackage struct {
	Name    string `json:"name"`
	Source  string `json:"source"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

// InventoryDirective is a setting read in a file. A secret one has no value:
// Secret says so and Value is empty.
type InventoryDirective struct {
	SAPI   string `json:"sapi"`
	Binary string `json:"binary"`
	Name   string `json:"name"`
	Value  string `json:"value"`
	Secret bool   `json:"secret"`
	// ValueText stands for the value of a secret one: "[masked]".
	ValueText string `json:"value_text,omitempty"`
	File      string `json:"file"`
	Line      int    `json:"line"`
}

type InventoryFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

type InventorySite struct {
	Server    string `json:"server"`
	PoweredBy string `json:"powered_by"`
}

func inventoryView(lang i18n.Lang, user string, inv target.Inventory) InventoryView {
	x := func(s string) string { return srvText(user, s) }
	v := InventoryView{TargetID: inv.TargetID, CheckedAt: stamp(inv.At),
		OS:  InventoryOS{ID: x(inv.OS.ID), VersionID: x(inv.OS.VersionID), Pretty: x(inv.OS.Pretty), Kernel: x(inv.OS.Kernel)},
		PHP: []InventoryPHP{}, Web: []InventoryWeb{}, Packages: []InventoryPackage{}, Directives: []InventoryDirective{},
		Files: []InventoryFile{}, Unseen: []TargetUnseenView{}, Site: InventorySite{Server: x(inv.Site.Server), PoweredBy: x(inv.Site.PoweredBy)}}
	for _, p := range inv.PHP {
		v.PHP = append(v.PHP, InventoryPHP{SAPI: x(p.SAPI), Binary: x(p.Binary), Version: x(p.Version), FromPackage: x(p.FromPackage),
			Modules: srvTexts(user, p.Modules), LoadedIni: x(p.LoadedIni), ScannedDir: x(p.ScannedDir),
			ScannedFiles: srvTexts(user, p.ScannedFiles), PoolFiles: srvTexts(user, p.PoolFiles)})
	}
	for _, w := range inv.Web {
		v.Web = append(v.Web, InventoryWeb{Name: x(w.Name), Version: x(w.Version)})
	}
	for _, p := range inv.Packages {
		v.Packages = append(v.Packages, InventoryPackage{Name: x(p.Name), Source: x(p.Source), Version: x(p.Version), Arch: x(p.Arch)})
	}
	for _, d := range inv.Directives {
		dv := InventoryDirective{SAPI: x(d.SAPI), Binary: x(d.Binary), Name: x(d.Name), Secret: d.Secret, File: x(d.File), Line: d.Line}
		if d.Secret {
			dv.ValueText = i18n.T(lang, collect.SecretValueKey)
		} else {
			dv.Value = x(d.Value)
		}
		v.Directives = append(v.Directives, dv)
	}
	for _, f := range inv.Files {
		v.Files = append(v.Files, InventoryFile{Path: x(f.Path), SHA256: f.SHA256, Size: f.Size})
	}
	for _, u := range inv.Unseen {
		v.Unseen = append(v.Unseen, TargetUnseenView{What: x(u.What), Reason: reasonText(lang, user, u.Reason)})
	}
	return v
}

func (s *server) targetInventory(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	t, ok := s.targetOf(w, r, lang)
	if !ok {
		return
	}
	inv, found, err := s.targets().LatestInventory(r.Context(), t.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	if !found {
		s.failedBody(w, http.StatusNotFound, lang, "api.target.no_inventory", "api.target.no_inventory_hint")
		return
	}
	writeJSON(w, http.StatusOK, inventoryView(lang, t.User, inv))
}
