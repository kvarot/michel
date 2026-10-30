package fix

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
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
	p, err := project.NewRepo(d.Store).Get(ctx, projectID)
	if err != nil {
		return err
	}
	if p.Classification == policy.ClassHealth {
		return ErrHealthForbidden
	}
	if d.Policy.Sovereignty.Mode == policy.ModeStrictLocal {
		return ErrStrictLocal
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
