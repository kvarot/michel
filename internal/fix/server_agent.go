package fix

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/agent"
	"github.com/kvarot/michel/internal/egress/allowproxy"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/serverrules"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

// The agent of a server fix (spec § 8.2). The agent never reaches the
// server: it reads the masked inventory of the attempt's server and proposes
// typed actions with propose_server_fix. Michel validates them against the
// inventory (serverfix.Validate), renders the scripts itself and stores the
// proposal, which then goes through the same approval and run as Michel's
// own fixes. A health server never goes to an agent.

// ServerActionInput is one action the agent proposes: the fields of its
// tool, and nothing else. Michel fills every other field of the action
// (the line, the key, the binary, the manager) from the inventory.
type ServerActionInput struct {
	Op        string `json:"op"`
	Path      string `json:"path,omitempty"`
	Directive string `json:"directive,omitempty"`
	Value     string `json:"value,omitempty"`
	Service   string `json:"service,omitempty"`
	Package   string `json:"package,omitempty"`
	Version   string `json:"version,omitempty"`
	SAPI      string `json:"sapi,omitempty"`
}

// ServerProposeInput is what the agent gives to propose_server_fix. It
// lives here so that the fix service and the MCP server do not import each
// other.
type ServerProposeInput struct {
	Summary    string              `json:"summary"`
	Actions    []ServerActionInput `json:"actions"`
	Mitigation bool                `json:"mitigation,omitempty"`
}

// Bounds of a server proposal.
const (
	// MaxServerActions is the longest list of actions of one proposal.
	MaxServerActions = 16
	// maxServerSummary bounds the agent's summary (characters).
	maxServerSummary = 4000
	// maxInventoryPackages bounds the packages listed to the agent.
	maxInventoryPackages = 4000
	// MaxAgentSimulations caps the package simulations (each one an SSH
	// session) an agent's proposals may cause for one attempt.
	MaxAgentSimulations = 3
)

// ErrAgentActionRefused is matched by a ServerRefusal: Michel refused an
// action of the agent; nothing was prepared.
var ErrAgentActionRefused = errors.New("Michel refused an action of the agent")

// ServerRefusal is the answer to a proposal Michel refused: Key names the
// reason (catalog key fix.server.agent_refused.*), Error is the plain
// English sentence the agent reads. It never quotes the proposal, the
// inventory or a path of the workstation.
type ServerRefusal struct {
	Key string
}

func (r *ServerRefusal) Error() string {
	return "Michel refused an action: " + i18n.T(i18n.EN, r.Key) + " Nothing was prepared; correct the actions and call propose_server_fix again."
}

// Is makes a ServerRefusal match ErrAgentActionRefused.
func (r *ServerRefusal) Is(target error) bool { return target == ErrAgentActionRefused }

// refusalOf maps a validation error to its reason.
func refusalOf(err error) *ServerRefusal {
	var rm serverfix.ErrWouldRemove
	for _, k := range []struct {
		err error
		key string
	}{
		{serverfix.ErrLinkedFile, "link"},
		{serverfix.ErrPathNotAllowed, "path"},
		{serverfix.ErrBadValue, "value"},
		{serverfix.ErrUnknownDirective, "directive"},
		{serverfix.ErrUnknownService, "service"},
		{serverfix.ErrUnknownPackage, "package"},
		{serverfix.ErrMajorUpgrade, "major"},
		{serverfix.ErrDowngrade, "downgrade"},
		{serverfix.ErrAmbiguous, "ambiguous"},
		{serverfix.ErrUntestableBinary, "untestable"},
		{errUnreachable, "unreachable"},
		{errSimulationLimit, "simulation_limit"},
		{ErrSimulationRefused, "simulation"},
		{serverfix.ErrSimulation, "simulation"},
	} {
		if errors.Is(err, k.err) {
			return &ServerRefusal{Key: "fix.server.agent_refused." + k.key}
		}
	}
	if errors.As(err, &rm) {
		return &ServerRefusal{Key: "fix.server.agent_refused.simulation"}
	}
	return &ServerRefusal{Key: "fix.server.agent_refused.malformed"}
}

var (
	// errUnreachable: Michel could not connect to the server.
	errUnreachable = errors.New("Michel cannot reach the server")
	// errSimulationLimit: the attempt used its package simulations.
	errSimulationLimit = errors.New("too many package simulations for this attempt")
)

// simulation counts one package simulation of attempt id and tells whether
// it is within MaxAgentSimulations.
func (s *Sessions) simulation(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sims[id] >= MaxAgentSimulations {
		return false
	}
	s.sims[id]++
	return true
}

// agentOrigin tells whether an attempt's origin is the agent's.
func agentOrigin(origin string) bool { return origin == OriginAgent || origin == OriginAgentAuto }

// serverAgentDir is the agent's working folder for a server attempt,
// <data>/worktrees/<server>/<attempt>, where the agent driver accepts a
// session: an empty folder (the agent has no file tool and no file of the
// server). Sweep removes what a stopped process left.
func serverAgentDir(dataDir, targetID, attemptID string) string {
	return filepath.Join(dataDir, "worktrees", targetID, attemptID)
}

// StartServerAgent starts Claude Code to help with a fix of a server
// finding, on the user's request. It refuses a health server
// (ErrHealthForbidden: kind hds or classified health, consent or not), a
// server set to report only (ErrReportOnly), a gone finding, a strict_local
// policy (ErrStrictLocal), a server without AI consent
// (ErrConsentRequired), a busy server (ErrBusy) and an unusable Claude Code.
// When the server has a preprod, the agent works on the preprod's finding
// and inventory (whose consent is then needed); the production fix is
// built from the production's inventory once the preprod one is proven.
// The agent gets an empty working folder, the masked inventory and the
// MCP tools of a server attempt; the attempt is returned in state
// preparing and its session goes on in the background.
func StartServerAgent(ctx context.Context, d Deps, findingID string) (Attempt, error) {
	return d.startServerAgent(ctx, findingID, OriginAgent)
}

func (d Deps) startServerAgent(ctx context.Context, findingID, origin string) (Attempt, error) {
	f, t, err := d.serverFinding(ctx, findingID)
	if err != nil {
		return Attempt{}, err
	}
	if healthTarget(t) {
		return Attempt{}, ErrHealthForbidden
	}
	if t.FixLevel == 0 {
		return Attempt{}, ErrReportOnly
	}
	if f.Status == scan.StatusGone {
		return Attempt{}, ErrFindingGone
	}
	if d.Policy.Sovereignty.Mode == policy.ModeStrictLocal {
		return Attempt{}, ErrStrictLocal
	}
	on, of, w := t, f, ServerWork{TargetID: t.ID}
	if t.PreprodID != "" {
		pt, err := d.Targets.Get(ctx, t.PreprodID)
		if err != nil {
			return Attempt{}, fmt.Errorf("cannot read the preprod server: %w", err)
		}
		if healthTarget(pt) {
			return Attempt{}, ErrHealthForbidden
		}
		if pt.FixLevel == 0 {
			return Attempt{}, ErrReportOnly
		}
		pf, ok, err := d.sameOn(ctx, pt, f)
		if err != nil {
			return Attempt{}, err
		}
		if !ok {
			return Attempt{}, ErrPreprodMissing
		}
		on, of, w = pt, pf, ServerWork{TargetID: pt.ID, ProdTargetID: t.ID, ProdFindingID: f.ID}
	}
	// The consent is the one of the server whose inventory leaves.
	ok, err := d.serverConsentOK(ctx, on)
	if err != nil {
		return Attempt{}, err
	}
	if !ok {
		return Attempt{}, ErrConsentRequired
	}
	inv, ok, err := d.Targets.LatestInventory(ctx, on.ID)
	if err != nil {
		return Attempt{}, err
	}
	if !ok {
		return Attempt{}, ErrNoInventory
	}
	if busy, err := d.busy(ctx, on.ID); err != nil {
		return Attempt{}, err
	} else if busy {
		return Attempt{}, ErrBusy
	}
	if st := d.agentStatus(ctx); st.Hint != "" {
		return Attempt{}, &AgentUnavailableError{Status: st}
	}
	if d.Gateway == nil {
		return Attempt{}, errors.New("the fix service needs the egress gateway")
	}
	if d.Secrets == nil || d.DataDir == "" || !filepath.IsAbs(d.DataDir) {
		return Attempt{}, errors.New("the fix service needs the secret store and the data folder")
	}
	repo := d.repo()
	a, err := repo.CreateAttempt(ctx, Attempt{FindingID: of.ID, ProjectID: on.ID, Origin: origin, Work: Work{Server: &w}})
	if err != nil {
		return Attempt{}, err
	}
	lang := d.lang()
	fail := func(key string, cause error) (Attempt, error) {
		text := i18n.T(lang, key)
		if repo.SetState(ctx, a.ID, []State{StatePreparing}, StateFailed, text) == nil {
			_ = repo.SetCauseDetail(ctx, a.ID, auditDetail(d, cause))
		}
		got, _ := repo.GetAttempt(ctx, a.ID)
		d.cleanup(ctx, got, true)
		return got, cause
	}
	dir := serverAgentDir(d.DataDir, on.ID, a.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail("fix.cause.prepare_failed", noPath(err))
	}
	view := serverInventoryView(on, inv, of, d.DataDir)
	m := mask.New()
	if err := m.Save(d.Secrets, a.ID); err != nil {
		return fail("fix.cause.prepare_failed", err)
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fail("fix.cause.prepare_failed", err)
	}
	token := hex.EncodeToString(raw[:])
	if err := SetAttemptToken(d.Secrets, a.ID, token); err != nil {
		return fail("fix.cause.prepare_failed", err)
	}
	proxyURL, closeProxy, err := allowproxy.Listen(d.Gateway, policy.PurposeAgentClaude)
	if err != nil {
		return fail("fix.cause.prepare_failed", err)
	}
	ad := d.AgentDeps
	ad.DataDir, ad.ProxyAddr, ad.Now = d.DataDir, proxyURL, d.Now
	spec := agent.Spec{
		Dir: dir, Prompt: ServerPrompt(view, lang), MCPCommand: d.MCPCommand,
		MCPEnv:  map[string]string{EnvAttempt: a.ID, EnvToken: token},
		Timeout: d.Timeout, MaxTurns: d.maxTurns(),
		// Everything the agent needs comes from Michel's MCP tools.
		NoFileTools: true,
	}
	sess, err := d.startAgent(context.WithoutCancel(ctx), ad, spec)
	if err != nil {
		closeProxy()
		return fail("fix.cause.agent_start_failed", err)
	}
	if id := sess.ID(); id != "" {
		_ = repo.SetRun(ctx, a.ID, "", id)
	}
	if err := d.record(ctx, "server_fix.agent_start", a.ID, "ok", map[string]any{
		"attempt_id": a.ID, "target_id": on.ID, "finding_id": of.ID, "origin": origin, "classification": string(on.Classification),
		"preprod_first": w.ProdTargetID != "", "directives": len(view.Directives), "packages": len(view.Packages),
	}); err != nil {
		_ = sess.Close()
		closeProxy()
		return fail("fix.cause.prepare_failed", err)
	}
	r := &running{sess: sess, masker: m, saved: m.Len(), closeProxy: closeProxy, done: make(chan struct{})}
	d.sessions().add(a.ID, r)
	go d.run(a.ID, r)
	return repo.GetAttempt(ctx, a.ID)
}

// ProposeServer records the agent's proposal for a server attempt (state
// preparing or proposed; a new proposal supersedes the previous one). Only
// the fields of ServerActionInput are taken; Michel validates the actions
// against the server's latest inventory (serverfix.Validate), simulates a
// package upgrade, renders and fingerprints the scripts itself. A refused
// action gives a ServerRefusal (the agent reads its reason, the
// conversation tells the user) and no proposal. A proposal of the agent is
// never approved by a rule: the user alone approves it.
func ProposeServer(ctx context.Context, d Deps, attemptID string, in ServerProposeInput) (Proposal, error) {
	pl := d.sessions().proposeLock(attemptID)
	pl.Lock()
	defer pl.Unlock()
	repo := d.repo()
	lang := d.lang()
	a, err := repo.GetAttempt(ctx, attemptID)
	if err != nil {
		return Proposal{}, err
	}
	if a.Work.Server == nil {
		return Proposal{}, ErrNotServerFinding
	}
	if !agentOrigin(a.Origin) {
		return Proposal{}, fmt.Errorf("%w: this fix is Michel's own, an agent cannot propose for it", ErrBadTransition)
	}
	if a.State != StatePreparing && a.State != StateProposed {
		return Proposal{}, fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	if d.Targets == nil {
		return Proposal{}, errors.New("the fix service needs the server registry")
	}
	t, err := d.Targets.Get(ctx, a.Work.Server.TargetID)
	if err != nil {
		return Proposal{}, err
	}
	if t.ID != a.ProjectID {
		return Proposal{}, errors.New("the attempt's server does not match its record")
	}
	if healthTarget(t) {
		_ = d.record(ctx, "server_fix.propose", a.ID, "refused", map[string]any{"attempt_id": a.ID, "target_id": t.ID, "reason": "health"})
		return Proposal{}, ErrHealthForbidden
	}
	// The consent may have been withdrawn since the session started.
	if ok, err := d.serverConsentOK(ctx, t); err != nil {
		return Proposal{}, err
	} else if !ok {
		_ = d.record(ctx, "server_fix.propose", a.ID, "refused", map[string]any{"attempt_id": a.ID, "target_id": t.ID, "reason": "consent"})
		return Proposal{}, ErrConsentRequired
	}
	f, err := d.exactFinding(ctx, a.FindingID)
	if err != nil {
		return Proposal{}, err
	}
	if f.Status == scan.StatusGone {
		return Proposal{}, ErrFindingGone
	}
	inv, ok, err := d.Targets.LatestInventory(ctx, t.ID)
	if err != nil {
		return Proposal{}, err
	}
	if !ok {
		return Proposal{}, ErrNoInventory
	}
	m := mask.New()
	summary := shown(m, []string{d.DataDir}, in.Summary)
	if summary == "" {
		return Proposal{}, errors.New("the summary is empty")
	}
	if utf8.RuneCountInString(summary) > maxServerSummary {
		summary = string([]rune(summary)[:maxServerSummary]) + "…"
	}
	say := func(text string) {
		_, _ = repo.AddMessage(ctx, Message{AttemptID: a.ID, Role: RoleMichel, Text: text})
	}
	refuse := func(err error) (Proposal, error) {
		ref := refusalOf(err)
		say(i18n.T(lang, "fix.msg.server_refused", i18n.T(lang, ref.Key)))
		_ = d.record(ctx, "server_fix.propose", a.ID, "refused", map[string]any{"attempt_id": a.ID, "target_id": t.ID, "finding_id": f.ID,
			"origin": a.Origin, "reason": strings.TrimPrefix(ref.Key, "fix.server.agent_refused."), "actions": len(in.Actions)})
		return Proposal{}, ref
	}
	if len(in.Actions) == 0 || len(in.Actions) > MaxServerActions {
		return refuse(serverfix.ErrBadAction)
	}
	req := make([]serverfix.Action, 0, len(in.Actions))
	for _, x := range in.Actions {
		// The ops of the agent's tool only: Michel adds the backups, the
		// tests and the site check itself.
		switch serverfix.Op(x.Op) {
		case serverfix.OpSetDirective, serverfix.OpReload, serverfix.OpPackageUpgrade:
		default:
			return refuse(serverfix.ErrBadAction)
		}
		// Only the fields of the agent's tool: whatever else the action
		// could carry is Michel's to fill.
		req = append(req, serverfix.Action{Op: serverfix.Op(x.Op), Path: x.Path, Directive: x.Directive, Value: x.Value,
			Service: x.Service, Package: x.Package, Version: x.Version, SAPI: x.SAPI})
	}
	v, err := serverfix.Validate(serverfix.Plan{TargetID: t.ID, FindingID: f.ID, Actions: req, Mitigation: in.Mitigation}, t, inv)
	if err != nil {
		return refuse(err)
	}
	if v.NeedsSnapshot {
		// Each simulation is an SSH session the agent causes: a few per
		// attempt at most.
		if !d.sessions().simulation(a.ID) {
			return refuse(errSimulationLimit)
		}
		if err := d.simulateOnce(ctx, t, v); err != nil {
			return refuse(err)
		}
	}
	cid := newCorrectionID()
	b, err := serverfix.Render(v, t, cid)
	if err != nil {
		return refuse(err)
	}
	sf := ServerFix{TargetID: t.ID, FindingID: f.ID, CorrectionID: cid, Executor: executorFor(t, b),
		Mitigation: v.Mitigation, NeedsSnapshot: v.NeedsSnapshot, Actions: v.Actions, Requested: req}
	prop := Proposal{AttemptID: a.ID, Summary: summary, StepsServer: explainServer(lang, t, sf, b),
		Scripts: &b, Server: &sf, Hash: serverHash(b.Hash, sf)}
	if prop, err = repo.AddProposal(ctx, prop); err != nil {
		return Proposal{}, err
	}
	if a.State == StatePreparing {
		if err := repo.SetState(ctx, a.ID, []State{StatePreparing}, StateProposed, ""); err != nil {
			return Proposal{}, err
		}
	}
	say(i18n.T(lang, "fix.msg.proposed"))
	if err := d.record(ctx, "server_fix.propose", a.ID, "ok", map[string]any{
		"attempt_id": a.ID, "target_id": t.ID, "finding_id": f.ID, "proposal_id": prop.ID, "correction_id": cid, "origin": a.Origin,
		"hash": prop.Hash, "scripts_hash": b.Hash, "executor": string(sf.Executor), "run_as_root": b.RunAsRoot,
		"needs_snapshot": sf.NeedsSnapshot, "mitigation": sf.Mitigation, "superseded": a.State == StateProposed, "actions": len(req),
	}); err != nil {
		return prop, err
	}
	if d.Notify != nil {
		if waiting, err := repo.ListAttempts(ctx, "", string(StateProposed)); err == nil {
			d.Notify(ctx, len(waiting))
		}
	}
	return prop, nil
}

// exactFinding is the finding with exactly this id.
func (d Deps) exactFinding(ctx context.Context, id string) (scan.Finding, error) {
	list, err := scan.NewRepo(d.Store).FindByIDPrefix(ctx, id)
	if err != nil {
		return scan.Finding{}, err
	}
	for _, f := range list {
		if f.ID == id {
			return f, nil
		}
	}
	return scan.Finding{}, fmt.Errorf("%w: the finding of the attempt is gone", ErrNotFound)
}

// The masked inventory the agent reads (its first message and the tool
// get_server_inventory): only the attempt's server, never a value marked
// Secret (the directive is left out), never the value of a directive whose
// name or value looks like a secret, never a path of the workstation.

// ServerInventoryView is the masked inventory of one server and the finding
// of the attempt.
type ServerInventoryView struct {
	Kind              string                `json:"server_kind"`
	Env               string                `json:"server_env"`
	SiteChecked       bool                  `json:"site_checked_after_fix"`
	CheckedAt         string                `json:"checked_at"`
	Finding           ServerFindingView     `json:"finding"`
	OS                ServerOSView          `json:"os"`
	PHP               []ServerPHPView       `json:"php"`
	Web               []ServerWebView       `json:"web_servers"`
	Packages          []ServerPackageView   `json:"packages"`
	PackagesTruncated bool                  `json:"packages_truncated,omitempty"`
	Directives        []ServerDirectiveView `json:"directives"`
	FilesRead         []string              `json:"files_read"`
	NotRead           []ServerUnseenView    `json:"not_read"`
}

// ServerFindingView is the finding the fix is for.
type ServerFindingView struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Rule       string   `json:"rule_or_advisory"`
	Package    string   `json:"directive_or_package"`
	Installed  string   `json:"installed,omitempty"`
	Fixed      []string `json:"fixed_versions,omitempty"`
	SAPI       string   `json:"sapi,omitempty"`
	Location   string   `json:"location,omitempty"`
	Severity   string   `json:"severity"`
	Summary    string   `json:"summary"`
	Mitigation bool     `json:"mitigation_only,omitempty"`
}

// ServerOSView is the server's system.
type ServerOSView struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
	Pretty    string `json:"pretty,omitempty"`
	Kernel    string `json:"kernel,omitempty"`
}

// ServerPHPView is one PHP runtime.
type ServerPHPView struct {
	SAPI         string   `json:"sapi"`
	Binary       string   `json:"binary"`
	Version      string   `json:"version"`
	FromPackage  string   `json:"from_package,omitempty"`
	LoadedIni    string   `json:"loaded_ini,omitempty"`
	ScannedDir   string   `json:"scanned_dir,omitempty"`
	ScannedFiles []string `json:"scanned_files,omitempty"`
	PoolFiles    []string `json:"pool_files,omitempty"`
	Modules      []string `json:"modules,omitempty"`
}

// ServerWebView is a web server.
type ServerWebView struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ServerPackageView is an installed package.
type ServerPackageView struct {
	Name    string `json:"name"`
	Source  string `json:"source,omitempty"`
	Version string `json:"version"`
}

// ServerDirectiveView is one directive read in a file; ValueHidden says the
// value was left out because it may be a secret.
type ServerDirectiveView struct {
	SAPI        string `json:"sapi"`
	Binary      string `json:"binary,omitempty"`
	Name        string `json:"name"`
	Value       string `json:"value"`
	ValueHidden bool   `json:"value_hidden,omitempty"`
	File        string `json:"file"`
	Line        int    `json:"line"`
}

// ServerUnseenView is something the check could not read.
type ServerUnseenView struct {
	What   string `json:"what"`
	Reason string `json:"reason"`
}

var (
	// serverPathRe is a POSIX path of the server: no backslash, no drive,
	// no quote, no space.
	serverPathRe = regexp.MustCompile(`^/[A-Za-z0-9._@+,:~/-]{0,510}$`)
	// directiveNameRe is a directive name as the collection stores it.
	directiveNameRe = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]{1,128}$`)
	// secretNameRe are names whose value is never shown.
	secretNameRe = regexp.MustCompile(`(?i)(pass|pw|secret|token|key|auth|cred|salt|dsn|cookie_?val|^env\[)`)
	// secretValueRe are values that carry a credential.
	secretValueRe = regexp.MustCompile(`(?i)(auth|pass|passwd|password|pwd|secret|token|key|credentials?)\s*[=:]|://[^/\s]*:[^/\s]*@`)
	// drivePathRe is a path of a Windows workstation.
	drivePathRe = regexp.MustCompile(`(^|[\s"'=;,(])[A-Za-z]:[\\/]`)
)

// ruleDirectives are the directives of Michel's rules: their values are
// settings, never secrets, and the agent needs them.
func ruleDirectives() map[string]bool {
	out := map[string]bool{}
	if set, err := serverrules.Rules(); err == nil {
		for _, r := range set.Config {
			out[r.Directive] = true
		}
	}
	return out
}

// viewText makes a text of the server safe to show: one line, no control
// or invisible character, at most n characters; "" when it holds a hidden
// folder (the workstation's), a Windows path, a masked secret or a
// credential.
func viewText(v string, n int, hide []string) string {
	v = strings.Map(func(r rune) rune {
		switch {
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r >= 0x200B && r <= 0x200D, r == 0xFEFF:
			return -1
		}
		return r
	}, scan.SanitizeText(v))
	v = strings.Join(strings.Fields(v), " ")
	if utf8.RuneCountInString(v) > n {
		v = string([]rune(v)[:n])
	}
	if v == "" || hidden(v, hide) || strings.Contains(v, `\`) || drivePathRe.MatchString(v) ||
		mask.HasToken(mask.New().Mask(v)) || secretValueRe.MatchString(v) {
		return ""
	}
	return v
}

func hidden(v string, hide []string) bool {
	for _, h := range hide {
		if h == "" {
			continue
		}
		if strings.Contains(v, h) || strings.Contains(v, filepath.ToSlash(h)) {
			return true
		}
	}
	return false
}

// viewPath keeps a POSIX path of the server, else "".
func viewPath(p string, hide []string) string {
	if !serverPathRe.MatchString(p) || hidden(p, hide) {
		return ""
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return ""
		}
	}
	return p
}

func viewPaths(ps []string, hide []string) []string {
	var out []string
	for _, p := range ps {
		if v := viewPath(p, hide); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// serverInventoryView is the masked view of inv for finding f on t. hide
// are the workstation's folders (the data folder): a value holding one is
// left out.
func serverInventoryView(t target.Target, inv target.Inventory, f scan.Finding, hide ...string) ServerInventoryView {
	sev, _ := scan.EffectiveSeverity(f)
	loc := viewPath(f.Location, hide)
	v := ServerInventoryView{
		Kind: string(t.Kind), Env: string(t.Env), SiteChecked: t.SiteURL != "",
		Finding: ServerFindingView{ID: viewText(f.ID, 64, hide), Kind: viewText(f.Kind, 32, hide), Rule: viewText(f.OSVID, 64, hide),
			Package: viewText(f.Package, 128, hide), Installed: viewText(f.InstalledVersion, 64, hide), SAPI: viewText(f.SAPI, 16, hide),
			Location: loc, Severity: viewText(sev, 16, hide), Summary: viewText(f.Summary, 300, hide), Mitigation: f.Mitigation},
		OS: ServerOSView{ID: viewText(inv.OS.ID, 32, hide), VersionID: viewText(inv.OS.VersionID, 32, hide),
			Pretty: viewText(inv.OS.Pretty, 100, hide), Kernel: viewText(inv.OS.Kernel, 100, hide)},
		PHP: []ServerPHPView{}, Web: []ServerWebView{}, Packages: []ServerPackageView{}, Directives: []ServerDirectiveView{},
		FilesRead: []string{}, NotRead: []ServerUnseenView{},
	}
	if !inv.At.IsZero() {
		v.CheckedAt = inv.At.UTC().Format(time.RFC3339)
	}
	for _, x := range f.FixedVersions {
		if s := viewText(x, 64, hide); s != "" {
			v.Finding.Fixed = append(v.Finding.Fixed, s)
		}
	}
	for _, rt := range inv.PHP {
		p := ServerPHPView{SAPI: viewText(rt.SAPI, 16, hide), Binary: viewPath(rt.Binary, hide), Version: viewText(rt.Version, 64, hide),
			FromPackage: viewText(rt.FromPackage, 128, hide), LoadedIni: viewPath(rt.LoadedIni, hide), ScannedDir: viewPath(rt.ScannedDir, hide),
			ScannedFiles: viewPaths(rt.ScannedFiles, hide), PoolFiles: viewPaths(rt.PoolFiles, hide)}
		for _, mod := range rt.Modules {
			if s := viewText(mod, 64, hide); s != "" {
				p.Modules = append(p.Modules, s)
			}
		}
		v.PHP = append(v.PHP, p)
	}
	for _, w := range inv.Web {
		v.Web = append(v.Web, ServerWebView{Name: viewText(w.Name, 64, hide), Version: viewText(w.Version, 64, hide)})
	}
	for _, p := range inv.Packages {
		if len(v.Packages) == maxInventoryPackages {
			v.PackagesTruncated = true
			break
		}
		name := viewText(p.Name, 128, hide)
		if name == "" {
			continue
		}
		v.Packages = append(v.Packages, ServerPackageView{Name: name, Source: viewText(p.Source, 128, hide), Version: viewText(p.Version, 64, hide)})
	}
	rules := ruleDirectives()
	for _, x := range inv.Directives {
		if x.Secret || !directiveNameRe.MatchString(x.Name) {
			continue
		}
		file := viewPath(x.File, hide)
		if file == "" {
			continue
		}
		dv := ServerDirectiveView{SAPI: viewText(x.SAPI, 16, hide), Binary: viewPath(x.Binary, hide), Name: x.Name, File: file, Line: x.Line}
		switch {
		case !rules[x.Name] && secretNameRe.MatchString(x.Name):
			dv.ValueHidden = true
		default:
			dv.Value = viewText(x.Value, 512, hide)
			dv.ValueHidden = dv.Value == "" && strings.TrimSpace(x.Value) != ""
		}
		v.Directives = append(v.Directives, dv)
	}
	for _, fs := range inv.Files {
		if p := viewPath(fs.Path, hide); p != "" {
			v.FilesRead = append(v.FilesRead, p)
		}
	}
	for _, u := range inv.Unseen {
		v.NotRead = append(v.NotRead, ServerUnseenView{What: viewText(u.What, 200, hide), Reason: viewText(u.Reason, 100, hide)})
	}
	return v
}

// ServerInventoryOf is the masked inventory of the server of attempt
// attemptID, and its finding: the server of that attempt only. It refuses
// an attempt that is not a server one (ErrNotServerFinding), a health
// server (ErrHealthForbidden) and a server never checked (ErrNoInventory).
// hide are the workstation's folders to leave out.
func ServerInventoryOf(ctx context.Context, st *store.Store, attemptID string, hide ...string) (ServerInventoryView, error) {
	a, err := NewRepo(st).GetAttempt(ctx, attemptID)
	if err != nil {
		return ServerInventoryView{}, err
	}
	if a.Work.Server == nil || a.Work.Server.TargetID != a.ProjectID {
		return ServerInventoryView{}, ErrNotServerFinding
	}
	repo := target.NewRepo(st)
	t, err := repo.Get(ctx, a.Work.Server.TargetID)
	if err != nil {
		return ServerInventoryView{}, err
	}
	if healthTarget(t) {
		return ServerInventoryView{}, ErrHealthForbidden
	}
	if _, _, ok, err := NewRepo(st).Consent(ctx, serverConsentKey(t.ID)); err != nil {
		return ServerInventoryView{}, err
	} else if !ok {
		return ServerInventoryView{}, ErrConsentRequired
	}
	inv, ok, err := repo.LatestInventory(ctx, t.ID)
	if err != nil {
		return ServerInventoryView{}, err
	}
	if !ok {
		return ServerInventoryView{}, ErrNoInventory
	}
	f, err := Deps{Store: st}.exactFinding(ctx, a.FindingID)
	if err != nil {
		return ServerInventoryView{}, err
	}
	return serverInventoryView(t, inv, f, hide...), nil
}
