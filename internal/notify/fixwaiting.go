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
	var raw []byte
	var err error
	switch w.cfg.Format {
	case policy.FormatSlack, policy.FormatDiscord:
		raw, err = chatBody(w.cfg.Format, title+"\n"+body)
	default:
		raw, err = json.Marshal(map[string]any{"michel_fix_waiting": 1, "title": title, "text": body})
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

// SendFixWaiting tells every channel that n fix proposals wait for the
// user's decision, with the page link: a short text without any detail (no
// project, package, diff or path). It never stops at the first failure.
func SendFixWaiting(ctx context.Context, ns []Notifier, n int, pageURL string) []Delivery {
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
		title, body := fixWaitingMessage(lang, n, pageURL)
		size, err := m.message(ctx, title, body)
		out = append(out, deliver(nf, host, purpose, size, err))
	}
	return out
}

func (b *base) lang() i18n.Lang { return b.deps.Lang }
