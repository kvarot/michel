package notify

import (
	"context"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/serverlog"
	"github.com/kvarot/michel/internal/target"
)

const (
	// maxLogItems bounds the errors listed in one message; the rest is counted.
	maxLogItems = 5
	// maxLogTextRunes bounds the cleaned text of one error in a message.
	maxLogTextRunes = 200
)

// shortName is the name of a server as an alert shows it: clean and short.
func shortName(t target.Target) string {
	name := scan.SanitizeText(t.Name)
	if r := []rune(name); len(r) > maxNameRunes {
		name = string(r[:maxNameRunes-1]) + "…"
	}
	return name
}

// logItemLine is one error of an alert: its type, where, how many times and
// why it is told. The text comes after it, only when the item holds one (the
// server settings decide that upstream). The source of a log is never shown:
// an id means nothing to a reader and a path is not for a channel.
func logItemLine(lang i18n.Lang, it serverlog.AlertItem, kind serverlog.AlertKind) string {
	label := scan.SanitizeText(it.Type)
	if loc := scan.SanitizeText(it.Location); loc != "" {
		if label != "" {
			label += ", "
		}
		label += loc
	}
	if label == "" {
		label = i18n.T(lang, "notify.log.unnamed")
	}
	line := label
	if it.Count > 0 {
		line = i18n.N(lang, "notify.log.times", int(it.Count), label)
	}
	if it.Kind != "" {
		kind = it.Kind
	}
	line = "- " + line + " (" + i18n.T(lang, "notify.log.why."+string(kind)) + ")"
	if txt := scan.SanitizeText(it.Text); txt != "" {
		if r := []rune(txt); len(r) > maxLogTextRunes {
			txt = string(r[:maxLogTextRunes-1]) + "…"
		}
		line += "\n  " + txt
	}
	return line
}

// logReason is the plain sentence for the cause of a failed read: a key of
// serverlog.Reason*, never what the server printed.
func logReason(lang i18n.Lang, reason string) string {
	switch reason {
	case serverlog.ReasonNoAgent, serverlog.ReasonNoKeyAccepted, serverlog.ReasonHostKeyUnknown, serverlog.ReasonHostKeyChanged,
		serverlog.ReasonDenied, serverlog.ReasonTimeout, serverlog.ReasonOutputCut, serverlog.ReasonInactive, serverlog.ReasonBusy:
		return i18n.T(lang, "notify.log.reason."+reason)
	}
	return i18n.T(lang, "notify.log.reason."+serverlog.ReasonError)
}

// logMessage is the text of a server log alert. By default: the type, the
// place and the count of each error, the name of the server and the page link;
// the cleaned text only when an item holds it. Never a host, a user, a path or
// the id of a source.
func logMessage(lang i18n.Lang, in serverlog.AlertInput, pageURL string) (title, body string) {
	if !lang.Valid() {
		lang = i18n.EN
	}
	name := shortName(in.Target)
	title = i18n.T(lang, "notify.log.title", digest.DefaultAssistant)
	switch in.Kind {
	case serverlog.AlertNotReading:
		names := make([]string, 0, len(in.Items))
		for _, it := range in.Items {
			if n := scan.SanitizeText(it.Type); n != "" {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			names = []string{name}
		}
		body = i18n.N(lang, "notify.log.not_reading", len(names), strings.Join(names, ", ")) + "\n" + logReason(lang, in.Reason)
	case serverlog.AlertCapReached:
		body = i18n.T(lang, "notify.log.cap_reached", name)
	case serverlog.AlertVolume:
		n := len(in.Items)
		if n == 0 {
			n = 1
		}
		body = i18n.N(lang, "notify.log.volume", n, name)
	default:
		n := len(in.Items)
		lines := []string{i18n.N(lang, "notify.log.errors", n, name)}
		for i, it := range in.Items {
			if i == maxLogItems {
				lines = append(lines, i18n.N(lang, "notify.log.more", n-maxLogItems))
				break
			}
			lines = append(lines, logItemLine(lang, it, in.Kind))
		}
		body = strings.Join(lines, "\n")
	}
	if pageURL != "" {
		body += "\n" + pageURL
	}
	return title, body
}

// serverLog is a server log alert on the webhook: its own marker and its kind,
// so a consumer never takes it for another message.
func (w *webhook) serverLog(ctx context.Context, kind, title, body string) (int, error) {
	return w.marked(ctx, map[string]any{"michel_server_log_alert": 1, "kind": kind}, title, body)
}

// SendLogAlert tells every channel about the errors of a server's logs. By
// default a message holds the type, place and count of each error, the
// server's name and the page link, and the cleaned text only if the items hold
// it. An SMS channel only sends when smsAllowed (the server's own setting, off
// by default), the channel has urgent set, and fewer than the daily cap of SMS
// went out. A channel limited to some projects is skipped. It never stops at
// the first failure. now dates the SMS count.
func SendLogAlert(ctx context.Context, ns []Notifier, in serverlog.AlertInput, smsAllowed bool, pageURL string, now time.Time) []Delivery {
	out := make([]Delivery, 0, len(ns))
	for _, n := range ns {
		host, purpose := Target(n)
		skipped := func() Delivery {
			return Delivery{ChannelResult: digest.ChannelResult{Name: n.Name(), Type: n.Type(), Result: ResultSkipped}, Host: host, Purpose: purpose}
		}
		if sc, ok := n.(Scoped); ok && len(sc.Projects()) > 0 {
			// A channel limited to some projects (a client's) must not hear
			// about the servers, as the digest does not show them.
			out = append(out, skipped())
			continue
		}
		lang := i18n.EN
		if b, ok := n.(interface{ lang() i18n.Lang }); ok {
			lang = b.lang()
		}
		title, body := logMessage(lang, in, pageURL)
		if s, ok := n.(*sms); ok {
			if !smsAllowed || !s.cfg.Urgent {
				out = append(out, skipped())
				continue
			}
			dl := s.alert(ctx, body, now)
			dl.Host, dl.Purpose = host, purpose
			out = append(out, dl)
			continue
		}
		if w, ok := n.(*webhook); ok {
			size, err := w.serverLog(ctx, string(in.Kind), title, body)
			out = append(out, deliver(n, host, purpose, size, err))
			continue
		}
		m, ok := n.(messenger)
		if !ok {
			out = append(out, skipped())
			continue
		}
		size, err := m.message(ctx, title, body)
		out = append(out, deliver(n, host, purpose, size, err))
	}
	return out
}
