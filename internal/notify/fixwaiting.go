package notify

import (
	"context"
	"encoding/json"
	"html"

	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
)

// messenger is a channel that can carry a short fixed message besides the
// digest.
type messenger interface {
	message(ctx context.Context, title, body string) (int, error)
}

func (e *email) message(ctx context.Context, title, body string) (int, error) {
	page := "<!DOCTYPE html>\n<html><body><p>" + html.EscapeString(body) + "</p></body></html>\n"
	return e.deliver(ctx, title, body+"\n", page)
}

func (w *webhook) message(ctx context.Context, title, body string) (int, error) {
	return w.marked(ctx, map[string]any{"michel_fix_waiting": 1}, title, body)
}

// serverAlert is a server alert on the webhook: its own marker and its
// kind, so a consumer never takes it for the "a fix waits" message.
func (w *webhook) serverAlert(ctx context.Context, kind, title, body string) (int, error) {
	return w.marked(ctx, map[string]any{"michel_server_alert": 1, "kind": kind}, title, body)
}

// marked posts a short message; the generic format carries the fields of
// marker besides the title and the text.
func (w *webhook) marked(ctx context.Context, marker map[string]any, title, body string) (int, error) {
	var raw []byte
	var err error
	switch w.cfg.Format {
	case policy.FormatSlack, policy.FormatDiscord:
		raw, err = chatBody(w.cfg.Format, title+"\n"+body)
	default:
		doc := map[string]any{"title": title, "text": body}
		for k, v := range marker {
			doc[k] = v
		}
		raw, err = json.Marshal(doc)
	}
	if err != nil {
		return 0, err
	}
	return w.post(ctx, raw)
}

func (t *toast) message(ctx context.Context, title, body string) (int, error) {
	return t.show(ctx, title, body)
}

// fixWaitingMessage is the text of SendFixWaiting: how many fixes wait and
// the page link, nothing else.
func fixWaitingMessage(lang i18n.Lang, n int, pageURL string) (title, body string) {
	if !lang.Valid() {
		lang = i18n.EN
	}
	title = i18n.T(lang, "notify.fix_waiting.title", digest.DefaultAssistant)
	body = i18n.N(lang, "notify.fix_waiting.body", n)
	if pageURL != "" {
		body += "\n" + pageURL
	}
	return title, body
}

// fixHeldMessage is the text of SendFixHeld: how many fixes stopped before the
// agent started, and the page link, nothing else.
func fixHeldMessage(lang i18n.Lang, n int, pageURL string) (title, body string) {
	if !lang.Valid() {
		lang = i18n.EN
	}
	title = i18n.T(lang, "notify.fix_held.title", digest.DefaultAssistant)
	body = i18n.N(lang, "notify.fix_held.body", n)
	if pageURL != "" {
		body += "\n" + pageURL
	}
	return title, body
}

// SendFixWaiting tells every channel that n fix proposals wait for the
// user's decision, with the page link: a short text without any detail (no
// project, package, diff or path). It never stops at the first failure.
func SendFixWaiting(ctx context.Context, ns []Notifier, n int, pageURL string) []Delivery {
	return sendFixMessage(ctx, ns, func(lang i18n.Lang) (string, string) { return fixWaitingMessage(lang, n, pageURL) })
}

// SendFixHeld tells every channel that n fixes stopped on a possible key in the
// code and wait for an answer: no proposal exists yet, so it is not
// SendFixWaiting's text. No detail either, and no key.
func SendFixHeld(ctx context.Context, ns []Notifier, n int, pageURL string) []Delivery {
	return sendFixMessage(ctx, ns, func(lang i18n.Lang) (string, string) { return fixHeldMessage(lang, n, pageURL) })
}

func sendFixMessage(ctx context.Context, ns []Notifier, text func(i18n.Lang) (title, body string)) []Delivery {
	out := make([]Delivery, 0, len(ns))
	for _, nf := range ns {
		host, purpose := Target(nf)
		m, ok := nf.(messenger)
		if !ok {
			out = append(out, Delivery{ChannelResult: digest.ChannelResult{Name: nf.Name(), Type: nf.Type(), Result: ResultSkipped}, Host: host, Purpose: purpose})
			continue
		}
		lang := i18n.EN
		if b, ok := nf.(interface{ lang() i18n.Lang }); ok {
			lang = b.lang()
		}
		title, body := text(lang)
		size, err := m.message(ctx, title, body)
		out = append(out, deliver(nf, host, purpose, size, err))
	}
	return out
}

func (b *base) lang() i18n.Lang { return b.deps.Lang }
