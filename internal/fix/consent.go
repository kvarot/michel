package fix

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/target"
)

// AgentHosts are the hosts Claude Code 2.1.314 needs behind Michel's allow
// proxy (purpose agent.claude): the API, and platform.claude.com, where a
// subscription login refreshes its OAuth token (/v1/oauth/token). The other
// hosts of the binary (docs on code.claude.com, downloads, telemetry,
// error reports, claude.ai MCP connectors) are turned off by the launch
// environment or useless to a fix; the proxy refuses and records them.
var AgentHosts = []string{"api.anthropic.com", "platform.claude.com"}

// InstallHosts are the package registries the work copy installs from
// (purpose fix.install): Packagist and the GitHub archives Composer
// downloads, and the npm registry.
var InstallHosts = []string{"repo.packagist.org", "packagist.org", "api.github.com", "codeload.github.com", "registry.npmjs.org"}

// ConsentText is one line of the consent screen. What is its catalog key;
// Host is its argument when it names a destination (then Purpose is the
// allow rule's purpose), "" for a plain sentence.
type ConsentText struct {
	What    string `json:"what"`
	Host    string `json:"host,omitempty"`
	Purpose string `json:"purpose,omitempty"`
}

// hostMatches is the policy's host match: exact, or "*.suffix".
func hostMatches(rule, host string) bool {
	rule, host = strings.ToLower(rule), strings.ToLower(host)
	if strings.HasPrefix(rule, "*.") {
		return strings.HasSuffix(host, rule[1:])
	}
	return rule == host
}

func allowed(rules []policy.AllowRule, host, purpose string) bool {
	for _, r := range rules {
		if hostMatches(r.Host, host) && r.Purpose == purpose {
			return true
		}
	}
	return false
}

// missingRules are the allow rules the fix agent needs and pol lacks.
func missingRules(pol policy.Policy) []policy.AllowRule {
	var out []policy.AllowRule
	for _, h := range AgentHosts {
		if !allowed(pol.Sovereignty.Network.Allow, h, policy.PurposeAgentClaude) {
			out = append(out, policy.AllowRule{Host: h, Purpose: policy.PurposeAgentClaude})
		}
	}
	for _, h := range InstallHosts {
		if !allowed(pol.Sovereignty.Network.Allow, h, policy.PurposeFixInstall) {
			out = append(out, policy.AllowRule{Host: h, Purpose: policy.PurposeFixInstall})
		}
	}
	return out
}

// ConsentNeeded lists what the user must accept before an agent works on p
// under pol: what leaves the computer, what runs on it (controller ruling
// 30), the project's classification when it is sensitive, each host that
// has no allow rule yet, and the policy switch of external providers.
// consented says whether the project already gave its consent (the
// fix_consent row, Repo.Consent): a project that did not always gets the
// sentences, with host lines only for the rules still missing. It is empty
// for a consented project under a policy that allows everything.
func ConsentNeeded(p project.Project, pol policy.Policy, consented bool) []ConsentText {
	rules := missingRules(pol)
	if consented && len(rules) == 0 && pol.Sovereignty.AI.ExternalProvidersEnabled {
		return nil
	}
	out := []ConsentText{{What: "fix.consent.what_leaves"}, {What: "fix.consent.runs_code"}}
	if p.Classification == policy.ClassSensitive || p.Classification == policy.ClassHealth {
		out = append(out, ConsentText{What: "fix.consent.sensitive"})
	}
	for _, r := range rules {
		what := "fix.consent.install"
		if r.Purpose == policy.PurposeAgentClaude {
			what = "fix.consent.agent"
		}
		out = append(out, ConsentText{What: what, Host: r.Host, Purpose: r.Purpose})
	}
	if !pol.Sovereignty.AI.ExternalProvidersEnabled {
		out = append(out, ConsentText{What: "fix.consent.external_providers"})
	}
	return out
}

// serverConsentKey is the key of a server's consent record in fix_consent:
// a prefix keeps it apart from the projects' records.
func serverConsentKey(targetID string) string { return "server:" + targetID }

// healthTarget tells whether a server holds health data: kind hds, or
// classified health. Its findings never go to an external AI.
func healthTarget(t target.Target) bool {
	return t.Kind == target.KindHDS || t.Classification == policy.ClassHealth
}

// missingAgentRules are the allow rules an agent on a server needs and pol
// lacks: the agent's hosts only (Michel installs nothing for a server fix).
func missingAgentRules(pol policy.Policy) []policy.AllowRule {
	var out []policy.AllowRule
	for _, h := range AgentHosts {
		if !allowed(pol.Sovereignty.Network.Allow, h, policy.PurposeAgentClaude) {
			out = append(out, policy.AllowRule{Host: h, Purpose: policy.PurposeAgentClaude})
		}
	}
	return out
}

// ServerConsentNeeded lists what the user must accept before an agent
// helps with a fix of server t: what leaves the computer (the masked
// versions and settings of this server), that the agent never connects to
// it, the server's classification when it is sensitive, each agent host
// without an allow rule and the switch of external providers. A health
// server gets the one line that says it never goes to an AI. It is empty
// for a consented server under a policy that allows everything.
func ServerConsentNeeded(t target.Target, pol policy.Policy, consented bool) []ConsentText {
	if healthTarget(t) {
		return []ConsentText{{What: "fix.consent.server_health"}}
	}
	rules := missingAgentRules(pol)
	if consented && len(rules) == 0 && pol.Sovereignty.AI.ExternalProvidersEnabled {
		return nil
	}
	out := []ConsentText{{What: "fix.consent.server_what_leaves"}, {What: "fix.consent.server_no_access"}}
	if t.Classification == policy.ClassSensitive {
		out = append(out, ConsentText{What: "fix.consent.server_sensitive"})
	}
	for _, r := range rules {
		out = append(out, ConsentText{What: "fix.consent.agent", Host: r.Host, Purpose: r.Purpose})
	}
	if !pol.Sovereignty.AI.ExternalProvidersEnabled {
		out = append(out, ConsentText{What: "fix.consent.external_providers"})
	}
	return out
}

// serverConsentOK reports whether an agent may help with a fix of t now:
// not a health server, a consent record for t, every agent rule in force
// and external providers on.
func (d Deps) serverConsentOK(ctx context.Context, t target.Target) (bool, error) {
	if healthTarget(t) || len(missingAgentRules(d.Policy)) > 0 || !d.Policy.Sovereignty.AI.ExternalProvidersEnabled {
		return false, nil
	}
	_, _, ok, err := d.repo().Consent(ctx, serverConsentKey(t.ID))
	return ok, err
}

// ServerConsent reports whether server targetID gave its AI consent (the
// page shows ServerConsentNeeded with it).
func ServerConsent(ctx context.Context, d Deps, targetID string) (bool, error) {
	_, _, ok, err := d.repo().Consent(ctx, serverConsentKey(targetID))
	return ok, err
}

// ServerConsentAt is ServerConsent with the date the consent was given
// (zero when it was not).
func ServerConsentAt(ctx context.Context, d Deps, targetID string) (time.Time, bool, error) {
	at, _, ok, err := d.repo().Consent(ctx, serverConsentKey(targetID))
	return at, ok, err
}

// RevokeServerConsent forgets the AI consent of server targetID and
// records ai.consent_revoked. The agents this process runs on that server
// are stopped; any other one can no longer read the inventory nor propose
// (both check the consent at each call), and no agent starts without a new
// consent. The policy's allow rules stay: other consents may use them.
func RevokeServerConsent(ctx context.Context, d Deps, targetID string) error {
	if err := d.repo().DeleteConsent(ctx, serverConsentKey(targetID)); err != nil {
		return err
	}
	stopped := 0
	if list, err := d.repo().ListAttempts(ctx, targetID, string(StatePreparing)); err == nil {
		for _, a := range list {
			if a.Work.Server != nil && agentOrigin(a.Origin) {
				if _, ok := d.sessions().get(a.ID); ok {
					d.sessions().Close(a.ID)
					stopped++
				}
			}
		}
	}
	return d.record(ctx, "ai.consent_revoked", targetID, "ok", map[string]any{
		"target_id": targetID, "kind": "server", "sessions_stopped": stopped, "author": d.actor(),
	})
}

// leavingTarget is the server whose inventory an agent would read for a
// fix of t: its preprod when it has one (the fix is tried there first).
func (d Deps) leavingTarget(ctx context.Context, t target.Target) (target.Target, error) {
	if t.PreprodID == "" {
		return t, nil
	}
	return d.Targets.Get(ctx, t.PreprodID)
}

// GiveServerConsent records the AI consent of one server: it refuses a
// health server (ErrHealthForbidden) and a strict_local policy
// (ErrStrictLocal), writes the missing allow rules of AgentHosts, turns
// ai.external_providers_enabled on when needed, reloads the policy, stores
// the consent of this server only and records ai.consent.
func GiveServerConsent(ctx context.Context, d Deps, targetID string) error {
	return GiveServerConsentWith(ctx, d, targetID, ConsentOptions{})
}

// GiveServerConsentWith is GiveServerConsent with the user's choices (the
// switch to standard mode on the user's click, as for a project).
func GiveServerConsentWith(ctx context.Context, d Deps, targetID string, opts ConsentOptions) error {
	if d.Targets == nil {
		return errors.New("the fix service needs the server registry")
	}
	t, err := d.Targets.Get(ctx, targetID)
	if err != nil {
		return err
	}
	if healthTarget(t) {
		return ErrHealthForbidden
	}
	if d.Policy.Sovereignty.Mode == policy.ModeStrictLocal {
		if !opts.SwitchToStandard {
			return ErrStrictLocal
		}
		if err := d.switchToStandard(ctx, project.Project{ID: t.ID, Name: t.Name}); err != nil {
			return err
		}
	}
	rules := missingAgentRules(d.Policy)
	enable := !d.Policy.Sovereignty.AI.ExternalProvidersEnabled
	if len(rules) > 0 || enable {
		if d.PolicyPath == "" {
			return errors.New("cannot write the consent: the policy file path is unknown")
		}
		if len(rules) > 0 {
			if _, err := policy.AddAllowRules(d.PolicyPath, rules...); err != nil {
				return err
			}
		}
		if enable {
			if _, err := policy.SetExternalProviders(d.PolicyPath, true); err != nil {
				return err
			}
		}
		if err := d.reload(); err != nil {
			return fmt.Errorf("the consent was written but the policy cannot be reloaded: %w", err)
		}
	}
	hosts := append([]string{}, AgentHosts...)
	if err := d.repo().SetConsent(ctx, serverConsentKey(t.ID), hosts); err != nil {
		return err
	}
	if d.Audit != nil {
		if _, err := d.Audit.Record(ctx, audit.Event{
			Actor: d.actor(), Action: "ai.consent", Target: t.ID, Result: "ok",
			Evidence: map[string]any{
				"target_id": t.ID, "kind": "server", "classification": string(t.Classification), "hosts": hosts,
				"purposes": []string{policy.PurposeAgentClaude}, "rules_written": len(rules),
				"external_providers_written": enable, "author": d.actor(),
			},
		}); err != nil {
			return fmt.Errorf("the consent is recorded, but the audit log could not record it: %w", err)
		}
	}
	return nil
}

// consentOK reports whether p may go to the agent now: a consent record,
// every rule in force and external providers on.
func (d Deps) consentOK(ctx context.Context, p project.Project) (bool, error) {
	if len(missingRules(d.Policy)) > 0 || !d.Policy.Sovereignty.AI.ExternalProvidersEnabled {
		return false, nil
	}
	_, _, ok, err := d.repo().Consent(ctx, p.ID)
	return ok, err
}

// GiveConsent records the AI consent of the project: it refuses a health
// project (ErrHealthForbidden) and a strict_local policy (ErrStrictLocal,
// the mode is the user's to change), writes the missing allow rules for
// AgentHosts and InstallHosts in the policy file, turns
// ai.external_providers_enabled on when needed, reloads the policy so the
// gateway learns the rules, stores the consent and records ai.consent with
// the hosts and the classification.
func GiveConsent(ctx context.Context, d Deps, projectID string) error {
	return GiveConsentWith(ctx, d, projectID, ConsentOptions{})
}

// ConsentOptions are the choices the user made on the consent screen.
type ConsentOptions struct {
	// SwitchToStandard is the user's explicit click on « Autoriser les IA
	// externes (mode standard) » (controller ruling 41): under strict_local
	// the policy goes to standard with external providers on, then the
	// consent is given. Without it, strict_local is refused and never
	// changed.
	SwitchToStandard bool
}

// GiveConsentWith is GiveConsent with the user's choices. Under
// strict_local and with SwitchToStandard, it first writes
// sovereignty.mode: standard and ai.external_providers_enabled: true in one
// edit of the policy file (with its .bak), records policy.mode and reloads
// the policy; a health project is refused before anything is written.
func GiveConsentWith(ctx context.Context, d Deps, projectID string, opts ConsentOptions) error {
	p, err := project.NewRepo(d.Store).Get(ctx, projectID)
	if err != nil {
		return err
	}
	if p.Classification == policy.ClassHealth {
		return ErrHealthForbidden
	}
	if d.Policy.Sovereignty.Mode == policy.ModeStrictLocal {
		if !opts.SwitchToStandard {
			return ErrStrictLocal
		}
		if err := d.switchToStandard(ctx, p); err != nil {
			return err
		}
	}
	rules := missingRules(d.Policy)
	enable := !d.Policy.Sovereignty.AI.ExternalProvidersEnabled
	if len(rules) > 0 || enable {
		if d.PolicyPath == "" {
			return errors.New("cannot write the consent: the policy file path is unknown")
		}
		if len(rules) > 0 {
			if _, err := policy.AddAllowRules(d.PolicyPath, rules...); err != nil {
				return err
			}
		}
		if enable {
			if _, err := policy.SetExternalProviders(d.PolicyPath, true); err != nil {
				return err
			}
		}
		if err := d.reload(); err != nil {
			return fmt.Errorf("the consent was written but the policy cannot be reloaded: %w", err)
		}
	}
	hosts := append(append([]string{}, AgentHosts...), InstallHosts...)
	if err := d.repo().SetConsent(ctx, p.ID, hosts); err != nil {
		return err
	}
	if d.Audit != nil {
		if _, err := d.Audit.Record(ctx, audit.Event{
			Actor: d.actor(), Action: "ai.consent", Target: p.Name, Result: "ok",
			Evidence: map[string]any{
				"project_id": p.ID, "classification": string(p.Classification), "hosts": hosts,
				"purposes":      []string{policy.PurposeAgentClaude, policy.PurposeFixInstall},
				"rules_written": len(rules), "external_providers_written": enable, "author": d.actor(),
			},
		}); err != nil {
			return fmt.Errorf("the consent is recorded, but the audit log could not record it: %w", err)
		}
	}
	return nil
}

// switchToStandard moves the policy from strict_local to standard with
// external providers on, on the user's click, audits it as policy.mode and
// reloads the policy.
func (d *Deps) switchToStandard(ctx context.Context, p project.Project) error {
	if d.PolicyPath == "" {
		return errors.New("cannot change the policy mode: the policy file path is unknown")
	}
	if _, err := policy.SetMode(d.PolicyPath, policy.ModeStandard, true); err != nil {
		return err
	}
	if d.Audit != nil {
		if _, err := d.Audit.Record(ctx, audit.Event{
			Actor: d.actor(), Action: "policy.mode", Target: p.Name, Result: "ok",
			Evidence: map[string]any{
				"from": string(policy.ModeStrictLocal), "to": string(policy.ModeStandard), "external_providers_enabled": true,
				"project_id": p.ID, "author": d.actor(),
			},
		}); err != nil {
			return fmt.Errorf("the policy mode changed, but the audit log could not record it: %w", err)
		}
	}
	if d.Reload == nil {
		d.Policy.Sovereignty.Mode = policy.ModeStandard
		d.Policy.Sovereignty.AI.ExternalProvidersEnabled = true
		return nil
	}
	if err := d.reload(); err != nil {
		return fmt.Errorf("the policy mode changed but the policy cannot be reloaded: %w", err)
	}
	return nil
}

// reload rereads the policy and hands its rules to the gateway.
func (d *Deps) reload() error {
	if d.Reload == nil {
		return nil
	}
	p, err := d.Reload()
	if err != nil {
		return err
	}
	d.Policy = p
	if d.Gateway != nil {
		d.Gateway.SetRules(p.Sovereignty.Network.Allow)
	}
	return nil
}

// ConsentState is the AI consent screen of a project: what to accept, whether
// the project consented (and when), whether an agent may work on it now, and
// the refusal when no consent can be given.
type ConsentState struct {
	Lines     []ConsentText
	Consented bool
	GivenAt   time.Time
	// Ready: consent given and every rule in force; never true with a Refusal.
	Ready bool
	// Refusal is ErrHealthForbidden (a health project), ErrStrictLocal (a
	// strict_local policy) or nil. A health project wins over strict_local.
	Refusal error
}

// ConsentStatus computes the consent state of p under pol; the CLI and the
// page both show it.
func ConsentStatus(ctx context.Context, d Deps, p project.Project, pol policy.Policy) (ConsentState, error) {
	at, _, consented, err := d.repo().Consent(ctx, p.ID)
	if err != nil {
		return ConsentState{}, err
	}
	lines := ConsentNeeded(p, pol, consented)
	st := ConsentState{Lines: lines, Consented: consented, Ready: consented && len(lines) == 0}
	if consented {
		st.GivenAt = at
	}
	switch {
	case p.Classification == policy.ClassHealth:
		st.Ready, st.Refusal = false, ErrHealthForbidden
	case pol.Sovereignty.Mode == policy.ModeStrictLocal:
		st.Ready, st.Refusal = false, ErrStrictLocal
	}
	return st, nil
}
