package source

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
)

// ConsentText is one destination the user is asked to accept. What is the
// i18n key of the sentence (source.consent.*) that the caller renders with
// Host as its only argument.
type ConsentText struct {
	Key, Host, Purpose string
	What               string
}

// Deps are what Enable and Disable need: the registry, the audit log, the
// gateway in force (it learns the new rules), the policy file to edit and a
// function that reloads and validates it.
type Deps struct {
	Repo       *Repo
	Audit      *audit.Logger
	Gateway    *egress.Gateway
	PolicyPath string
	Reload     func() (policy.Policy, error)
	Now        func() time.Time
	// Actor is recorded as the author of the consent (cli, api).
	Actor string
}

// consentWhat picks the sentence that says what Michel does with the host.
func consentWhat(e Entry) string {
	switch {
	case e.Purpose == policy.PurposeDiscover:
		return "source.consent.discover"
	case e.Purpose == policy.PurposeRepo:
		return "source.consent.repo"
	case e.Kind == KindEnrichment && e.Config.Bool("on_demand"):
		return "source.consent.enrichment_on_demand"
	case e.Kind == KindEnrichment:
		return "source.consent.enrichment"
	case e.Kind == KindOSV:
		return "source.consent.osv"
	default:
		return "source.consent.feed"
	}
}

// ConsentNeeded lists the hosts of e that have no allow rule for its purpose
// yet. It is empty when every host is already allowed (or e has none).
func ConsentNeeded(e Entry, allowed func(host, purpose string) bool) []ConsentText {
	var out []ConsentText
	for _, h := range e.Hosts {
		if !allowed(h, e.Purpose) {
			out = append(out, ConsentText{Key: e.Key, Host: h, Purpose: e.Purpose, What: consentWhat(e)})
		}
	}
	return out
}

// SharedWith lists the other enabled entries that use one of the host and
// purpose pairs of e, sorted by key.
func SharedWith(ctx context.Context, r *Repo, e Entry) ([]string, error) {
	if len(e.Hosts) == 0 {
		return nil, nil
	}
	all, err := r.List(ctx, "", true)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, o := range all {
		if o.Key == e.Key || !o.Enabled || o.Purpose != e.Purpose {
			continue
		}
		for _, h := range o.Hosts {
			if slices.Contains(e.Hosts, h) {
				out = append(out, o.Key)
				break
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

func (d Deps) allowed(host, purpose string) bool {
	ok, _ := d.Gateway.Allowed(host, purpose)
	return ok
}

// reload rereads the policy and hands its rules to the gateway.
func (d Deps) reload() error {
	if d.Reload == nil {
		return nil
	}
	p, err := d.Reload()
	if err != nil {
		return err
	}
	d.Gateway.SetRules(p.Sovereignty.Network.Allow)
	return nil
}

// Enable turns the entry on. When some host has no allow rule and consent is
// false, it changes nothing and returns ErrConsentRequired with the texts to
// show. With consent, it writes the missing rules into the policy file (in
// one edit: all of them or none),
// reloads the policy (the gateway learns the rules), records source.consent
// and turns the entry on. A host already allowed (by another entry) asks
// nothing, but the consent is still recorded. It returns the texts of the
// rules it wrote.
func Enable(ctx context.Context, d Deps, key string, consent bool) (Entry, []ConsentText, error) {
	e, err := d.Repo.Get(ctx, key)
	if err != nil {
		return Entry{}, nil, err
	}
	need := ConsentNeeded(e, d.allowed)
	if len(need) > 0 && !consent {
		return e, need, ErrConsentRequired
	}
	if len(need) > 0 {
		if d.PolicyPath == "" {
			return e, need, errors.New("cannot write the network rule: the policy file path is unknown")
		}
		// One edit for every rule: a failure leaves the file as it was.
		rules := make([]policy.AllowRule, 0, len(need))
		for _, c := range need {
			rules = append(rules, policy.AllowRule{Host: c.Host, Purpose: c.Purpose})
		}
		if _, err := policy.AddAllowRules(d.PolicyPath, rules...); err != nil {
			return e, need, err
		}
		if err := d.reload(); err != nil {
			return e, need, fmt.Errorf("the network rule was written but the policy cannot be reloaded: %w", err)
		}
	}
	if len(e.Hosts) > 0 {
		if _, err := d.Audit.Record(ctx, audit.Event{
			Actor: d.Actor, Action: "source.consent", Target: e.Key, Result: "ok",
			Evidence: map[string]any{
				"key": e.Key, "hosts": e.Hosts, "purpose": e.Purpose, "author": d.Actor, "rules_written": len(need),
			},
		}); err != nil {
			return e, need, fmt.Errorf("cannot record the consent in the audit log: %w", err)
		}
	}
	if err := d.Repo.SetEnabled(ctx, key, true); err != nil {
		return e, need, err
	}
	if e.Hidden {
		if err := d.Repo.SetHidden(ctx, key, false); err != nil {
			return e, need, err
		}
	}
	if _, err := d.Audit.Record(ctx, audit.Event{
		Actor: d.Actor, Action: "source.enable", Target: e.Key, Result: "ok",
		Evidence: map[string]any{"key": e.Key, "kind": string(e.Kind)},
	}); err != nil {
		return e, need, fmt.Errorf("source %s is enabled, but the audit log could not record it: %w", key, err)
	}
	e, err = d.Repo.Get(ctx, key)
	return e, need, err
}

// Disable turns the entry off. With forget it also removes its allow rules
// from the policy file, unless another enabled entry needs one of them
// (ErrRuleShared names it, and nothing changes).
func Disable(ctx context.Context, d Deps, key string, forget bool) error {
	e, err := d.Repo.Get(ctx, key)
	if err != nil {
		return err
	}
	if forget && len(e.Hosts) > 0 {
		shared, err := SharedWith(ctx, d.Repo, e)
		if err != nil {
			return err
		}
		if len(shared) > 0 {
			return ErrRuleShared{Key: shared[0]}
		}
	}
	if err := d.Repo.SetEnabled(ctx, key, false); err != nil {
		return err
	}
	removed := 0
	if forget && len(e.Hosts) > 0 {
		if d.PolicyPath == "" {
			return errors.New("cannot remove the network rule: the policy file path is unknown")
		}
		for _, h := range e.Hosts {
			ok, err := policy.RemoveAllowRule(d.PolicyPath, policy.AllowRule{Host: h, Purpose: e.Purpose})
			if err != nil {
				return err
			}
			if ok {
				removed++
			}
		}
		if err := d.reload(); err != nil {
			return fmt.Errorf("the network rule was removed but the policy cannot be reloaded: %w", err)
		}
	}
	if _, err := d.Audit.Record(ctx, audit.Event{
		Actor: d.Actor, Action: "source.disable", Target: e.Key, Result: "ok",
		Evidence: map[string]any{"key": e.Key, "forget": forget, "rules_removed": removed},
	}); err != nil {
		return fmt.Errorf("source %s is disabled, but the audit log could not record it: %w", key, err)
	}
	return nil
}
