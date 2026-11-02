package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/policy"
)

// sms sends a short text on the SMS channel. It carries no digest: it is only
// used for urgent server alerts (SendServerAlert) and for the test message.
// The Free Mobile login and key never reach a log, the audit or an error.
type sms struct{ base }

func (s *sms) endpoint() string {
	if s.cfg.URL == "" && s.cfg.Provider == policy.SMSFreeMobile {
		return policy.FreeMobileURL
	}
	return s.cfg.URL
}

func (s *sms) Target() (string, string) { return hostOf(s.endpoint()), policy.PurposeNotifySMS }

// Send does nothing: the digest never goes by SMS.
func (s *sms) Send(context.Context, digest.Digest) error { return nil }

func (s *sms) send(context.Context, digest.Digest) (int, error) { return 0, nil }

func (s *sms) Test(ctx context.Context) error {
	_, err := s.test(ctx)
	return err
}

func (s *sms) test(ctx context.Context) (int, error) {
	title, body := testMessage(s.deps.Lang)
	return s.message(ctx, title, body)
}

// message sends title and body as one text.
func (s *sms) message(ctx context.Context, title, body string) (int, error) {
	text := title
	if body != "" {
		text += "\n" + body
	}
	if s.cfg.Provider == policy.SMSFreeMobile {
		return s.freeMobile(ctx, text)
	}
	raw, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return 0, err
	}
	return signedPost(ctx, s.deps, s.cfg.URL, policy.PurposeNotifySMS, s.cfg.Secret, "sms", raw)
}

// freeMobile calls the Free Mobile API: GET with the login, the key and the
// text in the query. The URL holds the key, so no error ever shows it.
func (s *sms) freeMobile(ctx context.Context, text string) (int, error) {
	endpoint := s.endpoint()
	host := hostOf(endpoint)
	key, err := readSecret(s.deps.Secrets, s.cfg.Secret)
	if err != nil {
		return 0, err
	}
	defer clear(key)
	if s.deps.Gateway == nil {
		return 0, errors.New("notify: no egress gateway")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return 0, fmt.Errorf("notify: the sms url of %s is invalid", host)
	}
	q := url.Values{}
	q.Set("user", s.cfg.User)
	q.Set("pass", string(key))
	q.Set("msg", text)
	u.RawQuery = q.Encode()
	ctx, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, fmt.Errorf("notify: the sms url of %s is invalid", host)
	}
	req.Header.Set("User-Agent", "michel/"+s.deps.Version)
	client := s.deps.Gateway.Client(policy.PurposeNotifySMS)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err // drop the URL: it holds the key
		}
		return 0, denied(fmt.Errorf("notify: sms to %s failed: %w", host, err), host, policy.PurposeNotifySMS)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return len(text), fmt.Errorf("notify: sms %s answered HTTP %d", host, resp.StatusCode)
	}
	return len(text), nil
}
