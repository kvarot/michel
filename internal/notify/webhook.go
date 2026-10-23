package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/policy"
)

// webhookTimeout bounds one webhook request.
const webhookTimeout = 20 * time.Second

// discordMax is the longest Discord content, in characters (Discord accepts
// 2,000).
const discordMax = 1900

// webhook POSTs the digest as JSON, signed with HMAC-SHA256 when the channel
// names a secret.
type webhook struct{ base }

func (w *webhook) host() string {
	u, err := url.Parse(w.cfg.URL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func (w *webhook) Target() (string, string) { return w.host(), policy.PurposeWebhook }

func (w *webhook) Send(ctx context.Context, d digest.Digest) error {
	_, err := w.send(ctx, d)
	return err
}

func (w *webhook) Test(ctx context.Context) error {
	_, err := w.test(ctx)
	return err
}

func (w *webhook) send(ctx context.Context, d digest.Digest) (int, error) {
	var body []byte
	var err error
	switch w.cfg.Format {
	case policy.FormatSlack, policy.FormatDiscord:
		text, rerr := digest.RenderText(d)
		if rerr != nil {
			return 0, rerr
		}
		body, err = chatBody(w.cfg.Format, text)
	default:
		body, err = digest.RenderJSON(d)
	}
	if err != nil {
		return 0, err
	}
	return w.post(ctx, body)
}

func (w *webhook) test(ctx context.Context) (int, error) {
	title, text := testMessage(w.deps.Lang)
	var body []byte
	var err error
	switch w.cfg.Format {
	case policy.FormatSlack, policy.FormatDiscord:
		body, err = chatBody(w.cfg.Format, title+"\n"+text)
	default:
		body, err = json.Marshal(map[string]any{"michel_test": 1, "title": title, "text": text})
	}
	if err != nil {
		return 0, err
	}
	return w.post(ctx, body)
}

// chatBody is the Slack ({"text"}) or Discord ({"content"}, cut) body.
func chatBody(format, text string) ([]byte, error) {
	if format == policy.FormatSlack {
		return json.Marshal(map[string]string{"text": text})
	}
	if utf8.RuneCountInString(text) > discordMax {
		text = string([]rune(text)[:discordMax-1]) + "…"
	}
	return json.Marshal(map[string]string{"content": text})
}

// post sends body and returns its size. Neither the URL path nor the
// response body ever reaches the error.
func (w *webhook) post(ctx context.Context, body []byte) (int, error) {
	host := w.host()
	var key []byte
	if w.cfg.Secret != "" {
		k, err := readSecret(w.deps.Secrets, w.cfg.Secret)
		if err != nil {
			return 0, err
		}
		key = k
		defer clear(key)
	}
	if w.deps.Gateway == nil {
		return 0, errors.New("notify: no egress gateway")
	}
	ctx, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("notify: the webhook url of %s is invalid", host)
	}
	ts := w.deps.now().Format(time.RFC3339)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "michel/"+w.deps.Version)
	req.Header.Set("X-Michel-Timestamp", ts)
	if key != nil {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(ts + "."))
		mac.Write(body)
		req.Header.Set("X-Michel-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	client := w.deps.Gateway.Client(policy.PurposeWebhook)
	// A redirect would carry the digest to another address: never follow.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err // drop the URL, its path may hold a token
		}
		return 0, denied(fmt.Errorf("notify: webhook to %s failed: %w", host, err), host, policy.PurposeWebhook)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return len(body), fmt.Errorf("notify: webhook %s answered HTTP %d", host, resp.StatusCode)
	}
	return len(body), nil
}
