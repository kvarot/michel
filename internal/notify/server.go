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

// maxNameRunes bounds the server name in an alert, so an SMS stays short.
const maxNameRunes = 40

// serverMessage is the text of a server alert: the server's name and, for a
// new finding, how many grave ones. Never a version, a path, a setting or an
// advisory: the page tells the rest.
func serverMessage(lang i18n.Lang, in servercheck.AlertInput, pageURL string) (title, body string) {
	if !lang.Valid() {
		lang = i18n.EN
	}
	name := scan.SanitizeText(in.Target.Name)
	if r := []rune(name); len(r) > maxNameRunes {
		name = string(r[:maxNameRunes-1]) + "…"
	}
	title = i18n.T(lang, "notify.server.title", digest.DefaultAssistant)
	switch in.Kind {
	case servercheck.AlertRollbackFailed:
		body = i18n.T(lang, "notify.server.rollback_failed", name)
	case servercheck.AlertRolledBack:
		body = i18n.T(lang, "notify.server.rolled_back", name)
	case servercheck.AlertAppliedAuto:
		body = i18n.T(lang, "notify.server.applied_auto", name)
	case servercheck.AlertUndoNow:
		body = i18n.T(lang, "notify.server.undo_now", name)
	case servercheck.AlertRestoreSnapshot:
		body = i18n.T(lang, "notify.server.restore_snapshot", name)
	case servercheck.AlertAutoNotRun:
		body = i18n.T(lang, "notify.server.auto_not_run", name)
	case servercheck.AlertUnknownState:
		body = i18n.T(lang, "notify.server.unknown_state", name)
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
		if sc, ok := n.(Scoped); ok && len(sc.Projects()) > 0 {
			// A channel limited to some projects (a client's) must not hear
			// about the servers, as the digest does not show them.
			out = append(out, Delivery{ChannelResult: digest.ChannelResult{Name: n.Name(), Type: n.Type(), Result: ResultSkipped},
				Host: host, Purpose: purpose})
			continue
		}
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
