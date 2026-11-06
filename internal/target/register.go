package target

import (
	"context"
	"strings"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
)

// Deps are the collaborators of the server operations the page and the
// command line share: the registry, the audit, and the way the network rules
// of the servers reach the policy file and the gateway.
type Deps struct {
	Repo  *Repo
	Audit *audit.Logger
	// Actor is who asks, as the audit names it.
	Actor string
	// PolicyPath is the policy file that receives the network rules; Reload
	// reads it again, validates it and puts it in force in this process. With
	// either missing, the rules are left alone.
	PolicyPath string
	Reload     func() (policy.Policy, error)
	// Current is the policy in force: its rules count when the file cannot
	// be read before a change. Nil counts none.
	Current func() policy.Policy
	// Gateway learns the rules of the reloaded policy; nil skips it.
	Gateway *egress.Gateway
}

// RulesError is network rules that could not be written for a server being
// added: the server was taken out again.
type RulesError struct{ Err error }

func (e *RulesError) Error() string { return "cannot write the network rules: " + e.Err.Error() }
func (e *RulesError) Unwrap() error { return e.Err }

// LinkError is a link to a project that could not be stored for a server
// being added: the server was taken out again.
type LinkError struct{ Err error }

func (e *LinkError) Error() string { return "cannot link the server: " + e.Err.Error() }
func (e *LinkError) Unwrap() error { return e.Err }

// AuditError is the audit event of an operation that was done but whose
// trace could not be written.
type AuditError struct{ Err error }

func (e *AuditError) Error() string { return "the audit log could not be written: " + e.Err.Error() }
func (e *AuditError) Unwrap() error { return e.Err }

// ChangeRules writes the network rules to add, then removes those to remove
// (one edit each, in the policy file), reloads the policy and hands it to the
// gateway. Adding a server is the user's opt-in; removing it takes the opt-in
// back. It returns the rules to add that were not in force yet, so a caller
// can take them back, and the rules it removed.
//
// What is in force is read from the file itself, as it is now: a rule the
// user wrote by hand, before or since this process started, stays theirs and
// is never taken back. Only the rules Michel wrote are removed. A process
// that edits the policy file from several goroutines serializes the calls
// itself.
func ChangeRules(ctx context.Context, d Deps, add, remove []policy.AllowRule) (added, removed []policy.AllowRule, err error) {
	if d.PolicyPath == "" || d.Reload == nil {
		return nil, nil, nil
	}
	var present []policy.AllowRule
	if d.Current != nil {
		present = d.Current().Sovereignty.Network.Allow
	}
	if p, _, err := policy.Load(d.PolicyPath, ""); err == nil && policy.Validate(p) == nil {
		present = p.Sovereignty.Network.Allow
	}
	added = NewRules(present, add)
	if removed, err = d.Repo.OwnedOnly(ctx, remove); err != nil {
		return nil, nil, err
	}
	if len(add) > 0 {
		if _, err := policy.AddAllowRules(d.PolicyPath, add...); err != nil {
			return nil, nil, err
		}
		if err := d.Repo.RecordRules(ctx, added); err != nil {
			return added, nil, err
		}
	}
	if len(removed) > 0 {
		if _, err := policy.RemoveAllowRules(d.PolicyPath, removed...); err != nil {
			return added, nil, err
		}
		if err := d.Repo.ForgetRules(ctx, removed); err != nil {
			return added, removed, err
		}
	}
	p, err := d.Reload()
	if err != nil {
		return added, removed, err
	}
	if d.Gateway != nil {
		d.Gateway.SetRules(p.Sovereignty.Network.Allow)
	}
	return added, removed, nil
}

// RegisterRequest is what is asked to add a server. The text fields are
// trimmed; FixLevel nil is level 1, CheckInterval "" the default interval,
// Preprod a server's id or name ("" for none). Links are the projects the
// server serves, already resolved by the caller.
type RegisterRequest struct {
	Name, Alias, Host, User string
	Port                    int
	Kind                    Kind
	Env                     Env
	Classification          policy.Classification
	Executor                Executor
	Sudo                    SudoMode
	SiteURL                 string
	AutoConfig              bool
	FixLevel                *int
	CheckInterval           string
	Preprod                 string
	Links                   []Link
}

// Register adds a server, the one way the page and michel target add share.
// The name is the alias, else the host, when none is given; the kind is vps.
// The checks come in one order: the fields (Check), the interval, the
// preprod, then the registry. The links and the network rules the server
// needs follow; when either cannot be stored the server is taken out again
// (LinkError, RulesError). The audit event target.add closes it; a refusal
// is returned as the registry's error, unaudited.
func Register(ctx context.Context, d Deps, req RegisterRequest) (Target, error) {
	t := Target{Name: strings.TrimSpace(req.Name), Alias: strings.TrimSpace(req.Alias), Host: strings.TrimSpace(req.Host), Port: req.Port,
		User: strings.TrimSpace(req.User), Kind: req.Kind, Env: req.Env, Classification: req.Classification,
		Executor: req.Executor, Sudo: req.Sudo, SiteURL: strings.TrimSpace(req.SiteURL), AutoConfig: req.AutoConfig, FixLevel: 1}
	if t.Name == "" {
		t.Name = t.Alias
	}
	if t.Name == "" {
		t.Name = t.Host
	}
	if t.Kind == "" {
		t.Kind = KindVPS
	}
	if req.FixLevel != nil {
		t.FixLevel = *req.FixLevel
	}
	if err := Check(t); err != nil {
		return Target{}, err
	}
	var err error
	if t.CheckInterval, err = ParseInterval(req.CheckInterval); err != nil {
		return Target{}, err
	}
	if t.PreprodID, err = d.Repo.ResolvePreprod(ctx, t, req.Preprod); err != nil {
		return Target{}, err
	}
	added, err := d.Repo.Add(ctx, t)
	if err != nil {
		return Target{}, err
	}
	for _, l := range req.Links {
		l.TargetID = added.ID
		if err := d.Repo.Link(ctx, l); err != nil {
			_ = d.Repo.Remove(ctx, added.ID)
			return Target{}, &LinkError{Err: err}
		}
	}
	fresh, _, err := ChangeRules(ctx, d, AllowRules(added), nil)
	if err != nil {
		_ = d.Repo.Remove(ctx, added.ID)
		return Target{}, &RulesError{Err: err}
	}
	if _, err := d.Audit.Record(ctx, audit.Event{Actor: d.Actor, Action: "target.add", Target: added.ID, Result: "ok",
		Evidence: map[string]any{"name": added.Name, "kind": string(added.Kind), "env": string(added.Env),
			"fix_level": added.FixLevel, "links": len(req.Links), "rules_written": len(fresh)}}); err != nil {
		// The server stays, as before: its rules are in the policy file.
		return added, &AuditError{Err: err}
	}
	return added, nil
}
