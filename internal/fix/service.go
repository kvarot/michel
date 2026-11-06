package fix

import (
	"context"
	"time"

	"github.com/kvarot/michel/internal/agent"
	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
	"github.com/kvarot/michel/internal/workcopy"
)

// Session is a running agent, as the service drives it: *agent.Session, or
// a fake in the tests.
type Session interface {
	Events() <-chan agent.Event
	ID() string
	Send(text string) error
	Close() error
}

// ActorAuto is the actor of an approval made by a level 3 rule.
const ActorAuto = "auto"

// MessageRetention is how long the conversations are kept.
const MessageRetention = 30 * 24 * time.Hour

// MaxAutoPerDay is the number of attempts Michel starts alone per project
// and per day (fix level 2).
const MaxAutoPerDay = 3

// Deps are the collaborators of the fix service. Store, Secrets, Gateway,
// Policy and DataDir are always needed; Agent, AgentDeps, AgentStatus and
// MCPCommand only where attempts are started (michel serve); Notify where
// proposals are recorded (michel serve and michel mcp).
type Deps struct {
	// Repo is the fix tables; nil means NewRepo(Store) with Now.
	Repo    *Repo
	Store   *store.Store
	Audit   *audit.Logger
	Secrets secret.Store
	// Gateway is the egress gateway the allow proxies of the attempt use
	// (purposes agent.claude and fix.install).
	Gateway *egress.Gateway
	// Policy is the policy in force; PolicyPath the file GiveConsent edits;
	// Reload rereads it (the gateway learns the rules). After GiveConsent
	// the caller refreshes its own copy of the policy through Reload.
	Policy     policy.Policy
	PolicyPath string
	Reload     func() (policy.Policy, error)
	// LivePolicy, when set, is the policy in force as the process sees it
	// now (michel serve: the one a consent given on the page reloads). The
	// worker reads it at each pass instead of keeping Policy.
	LivePolicy func() policy.Policy
	// DataDir is Michel's data folder; OSVRoot the offline databases of the
	// re-scan (empty: the policy's db.osv_path).
	DataDir string
	OSVRoot string
	Lang    i18n.Lang
	// Agent starts Claude Code for a spec with the agent deps of the
	// attempt (proxy and data folder filled in). Nil means agent.Start.
	Agent func(ctx context.Context, ad agent.Deps, s agent.Spec) (Session, error)
	// AgentDeps are the fixed parts of the agent driver (Binary, Home,
	// Exec for Detect); DataDir, ProxyAddr and Now are set per attempt.
	AgentDeps agent.Deps
	// AgentStatus tells whether Claude Code can be used. Nil means
	// agent.Detect with AgentDeps.
	AgentStatus func(ctx context.Context) agent.Status
	// MCPCommand starts michel mcp (the executable and its arguments); it is
	// the only MCP server of the agent.
	MCPCommand []string
	// Work are the collaborators of the work copy; its ProxyAddr is replaced
	// by the install proxy of each proposal.
	Work workcopy.Deps
	// Rescan reports whether the finding is absent from the copy at root.
	// Nil means scan.ScanDir offline with the project's exclusions.
	Rescan func(ctx context.Context, root string, f scan.Finding, p project.Project) (absent bool, err error)
	// Notify is called when a proposal waits for the user, with the number
	// of proposals waiting over every project. Nil sends nothing.
	Notify func(ctx context.Context, waiting int)
	// NotifyHeld is called when a start Michel made alone stopped on a key and
	// waits for a person's answer. Nil sends nothing.
	NotifyHeld func(ctx context.Context, n int)
	Now        func() time.Time
	// Actor is the audit actor of the calls (cli, web, serve).
	Actor string
	// Sessions holds the running agents of this process; nil means a
	// package-wide registry.
	Sessions *Sessions
	// Timeout and MaxTurns bound a session (0: agent.DefaultTimeout,
	// DefaultMaxTurns). WorkerInterval is the pause between two looks at the
	// queue (0: 30 s). PollInterval is how often a running session's state
	// is read (0: 1 s).
	Timeout time.Duration
	// TestsBound bounds a run of the tests a person asked for (RunTests):
	// 0 is DefaultTestsTimeout.
	TestsBound     time.Duration
	MaxTurns       int
	WorkerInterval time.Duration
	PollInterval   time.Duration

	// Server fixes (StartServer, Apply and AppliedByMe of a server finding).
	//
	// Targets is the server registry; SSH the client's services (every
	// connection goes through the egress gateway and the strict host key
	// check). CheckServer checks a server again (servercheck.Check in
	// michel serve). SiteCheck makes the GET of check_site from the
	// workstation (purpose target.http): nil means "no site check
	// possible", a fix with a check_site is then not proven. Alert tells
	// the user (servercheck.AlertInput kinds rolled_back, rollback_failed,
	// undo_now); nil tells no one. OnStep, when set, is told each step of a
	// run as it is known.
	Targets     *target.Repo
	SSH         sshx.Deps
	CheckServer func(ctx context.Context, targetID string) (servercheck.CheckResult, error)
	SiteCheck   func(ctx context.Context, url string) error
	Alert       func(ctx context.Context, in servercheck.AlertInput)
	OnStep      func(attemptID string, s StepResult)
	// ConfigApplyTimeout and PackageApplyTimeout bound a fix script's run
	// (0: DefaultConfigApplyTimeout, DefaultPackageApplyTimeout). They
	// replace the per-command cap of the collection for the scripts only.
	ConfigApplyTimeout  time.Duration
	PackageApplyTimeout time.Duration
	RecordTimeout       time.Duration
	// SiteCheckTimeout bounds one site check (0: DefaultSiteCheckTimeout),
	// CheckTimeout one recollection (0: DefaultCheckTimeout).
	SiteCheckTimeout time.Duration
	CheckTimeout     time.Duration
	// AllowLocalRemote lets a project attach to a remote on this disk: tests and
	// the trial build only (R28, R33). No variable, option or setting opens it.
	AllowLocalRemote bool
	// BackupKeyWait is how long a process waits for the backup key another
	// one is writing before it takes the key for lost (0: 10 s).
	BackupKeyWait time.Duration
}

// DefaultMaxTurns caps the agentic turns of a session when Deps.MaxTurns
// is 0 (spec § 7.1), on top of the session timeout.
const DefaultMaxTurns = 50

func (d Deps) maxTurns() int {
	if d.MaxTurns > 0 {
		return d.MaxTurns
	}
	return DefaultMaxTurns
}

// timeout is the longest a session runs.
func (d Deps) timeout() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return agent.DefaultTimeout
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

func (d Deps) repo() *Repo {
	if d.Repo != nil {
		return d.Repo
	}
	r := NewRepo(d.Store)
	if d.Now != nil {
		r.Now = d.Now
	}
	return r
}

func (d Deps) lang() i18n.Lang {
	if d.Lang.Valid() {
		return d.Lang
	}
	return i18n.EN
}

func (d Deps) actor() string {
	if d.Actor != "" {
		return d.Actor
	}
	return "michel"
}

func (d Deps) work() workcopy.Deps {
	w := d.Work
	w.AllowLocalRemote = d.AllowLocalRemote
	if w.DataDir == "" {
		w.DataDir = d.DataDir
	}
	if w.Now == nil {
		w.Now = d.Now
	}
	return w
}

var defaultSessions = NewSessions()

func (d Deps) sessions() *Sessions {
	if d.Sessions != nil {
		return d.Sessions
	}
	return defaultSessions
}

func (d Deps) pollInterval() time.Duration {
	if d.PollInterval > 0 {
		return d.PollInterval
	}
	return time.Second
}

func (d Deps) osvRoot() string {
	if d.OSVRoot != "" {
		return d.OSVRoot
	}
	return d.Policy.DB.OSVPath
}

// record writes an audit event; a nil logger records nothing.
func (d Deps) record(ctx context.Context, action, target, result string, ev map[string]any) error {
	if d.Audit == nil {
		return nil
	}
	_, err := d.Audit.Record(ctx, audit.Event{Actor: d.actor(), Action: action, Target: target, Result: result, Evidence: ev})
	return err
}
