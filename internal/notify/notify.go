// Package notify sends the digest on the channels of the policy's notify
// section: email (SMTP over TLS), signed webhook, native desktop toast and, for
// urgent server alerts only, SMS.
//
// Network channels reach the network only through the egress gateway, under
// the purposes notify.email and notify.webhook. A channel receives only what
// the digest holds (projects, counters, packages, versions, advisory ids,
// dates, the page link): never code, paths, commands or secrets. Errors stay
// in English and never hold a message body, a response body, a URL path or a
// secret value.
package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/secret"
)

// Notifier sends a digest, or a fixed test message, on one channel.
type Notifier interface {
	Name() string
	Type() string
	Send(ctx context.Context, d digest.Digest) error
	Test(ctx context.Context) error
}

// Scoped is implemented by a notifier restricted to some projects.
type Scoped interface{ Projects() []string }

// Runner executes a closed-list subprocess (toast). The default runs it;
// tests capture it.
type Runner interface {
	Run(ctx context.Context, name string, args []string, stdin []byte) error
}

// Deps holds what the channels need.
type Deps struct {
	Gateway *egress.Gateway
	Secrets secret.Store
	Version string
	// Runner runs the toast subprocess; nil runs it for real.
	Runner Runner
	// Now dates the messages; nil means time.Now.
	Now func() time.Time
	// TLSConfig replaces the email TLS settings (tests trust their own
	// certificate with it); nil verifies the server name against the
	// system roots, TLS 1.2 or later.
	TLSConfig *tls.Config
	// Lang is the language of the test message.
	Lang i18n.Lang
	// SMSCounter counts the SMS of the day and SMSPerDay caps them (Build
	// fills SMSPerDay from the policy when it is 0). Without a counter no
	// alert goes out by SMS.
	SMSCounter SMSCounter
	SMSPerDay  int
}

func (d Deps) now() time.Time {
	if d.Now == nil {
		return time.Now().UTC()
	}
	return d.Now().UTC()
}

// ErrSecretMissing is matched (errors.Is) by a SecretMissingError.
var ErrSecretMissing = errors.New("secret is not set")

// SecretMissingError says which secret a channel needs.
type SecretMissingError struct{ Name string }

func (e *SecretMissingError) Error() string {
	return fmt.Sprintf("secret %q is not set: run michel secret set %s", e.Name, e.Name)
}

// Is makes errors.Is(err, ErrSecretMissing) true.
func (e *SecretMissingError) Is(target error) bool { return target == ErrSecretMissing }

// DeniedError is an egress refusal, with the allow rule that would lift it.
type DeniedError struct {
	Host, Purpose string
	Err           error
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("%v: add under sovereignty.network.allow: {host: %s, purpose: %s}", e.Err, e.Host, e.Purpose)
}

func (e *DeniedError) Unwrap() error { return e.Err }

// denied wraps err in a DeniedError when the gateway refused the connection.
func denied(err error, host, purpose string) error {
	if errors.Is(err, egress.ErrEgressDenied) {
		return &DeniedError{Host: host, Purpose: purpose, Err: err}
	}
	return err
}

// readSecret returns the value of the named secret.
func readSecret(s secret.Store, name string) ([]byte, error) {
	if s == nil {
		return nil, &SecretMissingError{Name: name}
	}
	v, err := s.Get(name)
	if errors.Is(err, secret.ErrNotFound) {
		return nil, &SecretMissingError{Name: name}
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read secret %s: %w", name, err)
	}
	return v, nil
}

// base is what every channel shares.
type base struct {
	cfg  policy.ChannelConfig
	deps Deps
}

func (b *base) Name() string       { return b.cfg.Name }
func (b *base) Type() string       { return b.cfg.Type }
func (b *base) Projects() []string { return b.cfg.Projects }

// measured is implemented by the built-in channels: the size of what they
// sent (for the audit) and the host and purpose they contact.
type measured interface {
	send(ctx context.Context, d digest.Digest) (int, error)
	test(ctx context.Context) (int, error)
	Target() (host, purpose string)
}

// New returns the notifier of one channel, enabled or not. The channel's
// fields are checked as in the policy (policy.ChannelTarget).
func New(c policy.ChannelConfig, deps Deps) (Notifier, error) {
	if _, _, err := policy.ChannelTarget(c); err != nil {
		return nil, fmt.Errorf("notify channel %q: %w", c.Name, err)
	}
	b := base{cfg: c, deps: deps}
	switch c.Type {
	case policy.ChannelEmail:
		return &email{base: b}, nil
	case policy.ChannelWebhook:
		return &webhook{base: b}, nil
	case policy.ChannelSMS:
		return &sms{base: b}, nil
	default: // policy.ChannelToast
		return newToast(b), nil
	}
}

// Build returns one Notifier per enabled channel; an unknown type is a
// configuration error.
func Build(cfg policy.NotifyConfig, deps Deps) ([]Notifier, error) {
	out := []Notifier{}
	if deps.SMSPerDay == 0 {
		deps.SMSPerDay = cfg.EffectiveSMSPerDay()
	}
	for _, c := range cfg.Channels {
		if !c.IsEnabled() {
			continue
		}
		n, err := New(c, deps)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

// Results of a channel.
const (
	ResultOK      = "ok"
	ResultError   = "error"
	ResultSkipped = "skipped"
)

// Delivery is what happened on one channel, with what the audit records:
// the host contacted ("local" for a toast) and the size of the body sent.
// It never holds the body.
type Delivery struct {
	digest.ChannelResult
	Host    string
	Purpose string
	Bytes   int
	// Err is the error behind ResultError (not stored).
	Err error
}

// Target returns the host and egress purpose of n ("", "" when unknown).
func Target(n Notifier) (host, purpose string) {
	if m, ok := n.(measured); ok {
		return m.Target()
	}
	return "", ""
}

func deliver(n Notifier, host, purpose string, size int, err error) Delivery {
	dl := Delivery{ChannelResult: digest.ChannelResult{Name: n.Name(), Type: n.Type(), Result: ResultOK}, Host: host, Purpose: purpose, Bytes: size}
	if err != nil {
		dl.Result, dl.Error, dl.Err = ResultError, err.Error(), err
	}
	return dl
}

// Deliver sends d to every notifier (a scoped notifier gets d restricted to
// its projects, and is skipped when none is left), never stops at the first
// failure, and returns one delivery per notifier, in order. Channels get the
// channel-safe copy of d (digest.ForChannel: no call-site example).
func Deliver(ctx context.Context, ns []Notifier, d digest.Digest) []Delivery {
	d = digest.ForChannel(d)
	out := make([]Delivery, 0, len(ns))
	for _, n := range ns {
		host, purpose := Target(n)
		if n.Type() == policy.ChannelSMS {
			// The digest never goes by SMS.
			out = append(out, Delivery{ChannelResult: digest.ChannelResult{Name: n.Name(), Type: n.Type(), Result: ResultSkipped},
				Host: host, Purpose: purpose})
			continue
		}
		dn := d
		if s, ok := n.(Scoped); ok && len(s.Projects()) > 0 {
			dn = digest.Filter(d, s.Projects())
			if len(dn.Projects) == 0 {
				out = append(out, Delivery{ChannelResult: digest.ChannelResult{Name: n.Name(), Type: n.Type(), Result: ResultSkipped},
					Host: host, Purpose: purpose})
				continue
			}
		}
		var size int
		var err error
		if m, ok := n.(measured); ok {
			size, err = m.send(ctx, dn)
		} else {
			err = n.Send(ctx, dn)
		}
		out = append(out, deliver(n, host, purpose, size, err))
	}
	return out
}

// SendAll sends d to every notifier (filtered by Projects), never stops at
// the first failure, and returns one result per channel.
func SendAll(ctx context.Context, ns []Notifier, d digest.Digest) []digest.ChannelResult {
	out := []digest.ChannelResult{}
	for _, dl := range Deliver(ctx, ns, d) {
		out = append(out, dl.ChannelResult)
	}
	return out
}

// TestOne sends the fixed test message on n.
func TestOne(ctx context.Context, n Notifier) Delivery {
	host, purpose := Target(n)
	if m, ok := n.(measured); ok {
		size, err := m.test(ctx)
		return deliver(n, host, purpose, size, err)
	}
	return deliver(n, host, purpose, 0, n.Test(ctx))
}

// testMessage returns the fixed test title and body in lang.
func testMessage(lang i18n.Lang) (title, body string) {
	return i18n.T(lang, "notify.test.subject", digest.DefaultAssistant), i18n.T(lang, "notify.test.body")
}
