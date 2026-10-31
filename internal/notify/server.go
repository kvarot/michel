package notify

import (
	"context"
	"errors"
	"time"

	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/servercheck"
)

// serverMessage is the text of a server alert: the server's name and, for a
// new finding, how many grave ones. Never a version, a path, a setting or an
// advisory: the page tells the rest.
func serverMessage(lang i18n.Lang, in servercheck.AlertInput, pageURL string) (title, body string) {
	if !lang.Valid() {
		lang = i18n.EN
	}
	name := scan.SanitizeText(in.Target.Name)
	title = i18n.T(lang, "notify.server.title", digest.DefaultAssistant)
	switch in.Kind {
	case servercheck.AlertRollbackFailed:
		body = i18n.T(lang, "notify.server.rollback_failed", name)
	case servercheck.AlertRolledBack:
		body = i18n.T(lang, "notify.server.rolled_back", name)
	case servercheck.AlertAppliedAuto:
		body = i18n.T(lang, "notify.server.applied_auto", name)
	default:
		n := len(in.New)
		if n == 0 {
			n = 1
		}
		body = i18n.N(lang, "notify.server.new", n, name)
	}
	if pageURL != "" {
		body += "\n" + pageURL
	}
	return title, body
}

// smsWanted tells whether an alert goes by SMS: it is urgent, or a fix could
// not be undone.
func smsWanted(in servercheck.AlertInput) bool {
	return in.Urgent || in.Kind == servercheck.AlertRollbackFailed
}

// SendServerAlert tells every channel about a server: a short text with the
// server's name and the page link, nothing else. An SMS channel only sends
// when the alert is urgent (or a fix failed to roll back), the channel has
// urgent set, and fewer than the daily cap of SMS went out. It never stops at
// the first failure. now dates the SMS count.
func SendServerAlert(ctx context.Context, ns []Notifier, in servercheck.AlertInput, pageURL string, now time.Time) []Delivery {
	out := make([]Delivery, 0, len(ns))
	for _, n := range ns {
		host, purpose := Target(n)
		skipped := func(reason string) Delivery {
			return Delivery{ChannelResult: digest.ChannelResult{Name: n.Name(), Type: n.Type(), Result: ResultSkipped, Error: reason},
				Host: host, Purpose: purpose}
		}
		lang := i18n.EN
		if b, ok := n.(interface{ lang() i18n.Lang }); ok {
			lang = b.lang()
		}
		title, body := serverMessage(lang, in, pageURL)
		if s, ok := n.(*sms); ok {
			if !smsWanted(in) || !s.cfg.Urgent {
				out = append(out, skipped(""))
				continue
			}
			dl := s.alert(ctx, body, now)
			dl.Host, dl.Purpose = host, purpose
			out = append(out, dl)
			continue
		}
		m, ok := n.(messenger)
		if !ok {
			out = append(out, skipped(""))
			continue
		}
		size, err := m.message(ctx, title, body)
		out = append(out, deliver(n, host, purpose, size, err))
	}
	return out
}

// alert sends text by SMS if the day's count allows it.
func (s *sms) alert(ctx context.Context, text string, now time.Time) Delivery {
	d := Delivery{ChannelResult: digest.ChannelResult{Name: s.Name(), Type: s.Type()}}
	if s.deps.SMSCounter == nil {
		d.Result, d.Error, d.Err = ResultError, "notify: no sms counter, nothing sent", errors.New("notify: no sms counter")
		return d
	}
	max := s.deps.SMSPerDay
	if max <= 0 {
		max = policy.DefaultSMSPerDay
	}
	ok, err := s.deps.SMSCounter.Take(ctx, now, max)
	if err != nil {
		d.Result, d.Error, d.Err = ResultError, err.Error(), err
		return d
	}
	if !ok {
		d.Result, d.Error = ResultSkipped, "daily sms cap reached"
		return d
	}
	size, err := s.message(ctx, text, "")
	if err != nil {
		_ = s.deps.SMSCounter.Release(ctx, now)
		d.Result, d.Error, d.Err, d.Bytes = ResultError, err.Error(), err, size
		return d
	}
	d.Result, d.Bytes = ResultOK, size
	return d
}
