package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/oklog/ulid/v2"
)

// emailTimeout bounds one email, from the connection to QUIT.
const emailTimeout = 30 * time.Second

// smtpAddr is the address dialed for host and port (tests send it to their
// own server).
var smtpAddr = func(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

// email sends the digest by SMTP: STARTTLS on 587, implicit TLS on 465,
// never in clear; PLAIN authentication only once TLS is up.
type email struct{ base }

func (e *email) Target() (string, string) { return e.cfg.Host, policy.PurposeEmail }

func (e *email) Send(ctx context.Context, d digest.Digest) error {
	_, err := e.send(ctx, d)
	return err
}

func (e *email) Test(ctx context.Context) error {
	_, err := e.test(ctx)
	return err
}

func (e *email) send(ctx context.Context, d digest.Digest) (int, error) {
	text, err := digest.RenderText(d)
	if err != nil {
		return 0, err
	}
	page, err := digest.RenderHTML(d)
	if err != nil {
		return 0, err
	}
	subject := i18n.N(d.Lang, "notify.email.subject", d.NewTotal, d.Assistant, d.Until.UTC().Format(i18n.T(d.Lang, "digest.date_layout")))
	return e.deliver(ctx, subject, text, page)
}

func (e *email) test(ctx context.Context) (int, error) {
	subject, body := testMessage(e.deps.Lang)
	page := "<!DOCTYPE html>\n<html><body><p>" + html.EscapeString(body) + "</p></body></html>\n"
	return e.deliver(ctx, subject, body+"\n", page)
}

// tlsConfig returns the TLS settings for the server name host.
func (e *email) tlsConfig() *tls.Config {
	if e.deps.TLSConfig == nil {
		return &tls.Config{ServerName: e.cfg.Host, MinVersion: tls.VersionTLS12}
	}
	cfg := e.deps.TLSConfig.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = e.cfg.Host
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		cfg.MinVersion = tls.VersionTLS12
	}
	return cfg
}

// deliver builds the message and runs the SMTP session. It returns the size
// of the message.
func (e *email) deliver(ctx context.Context, subject, text, page string) (int, error) {
	c := e.cfg
	var password []byte
	if c.Username != "" {
		pw, err := readSecret(e.deps.Secrets, c.PasswordSecret)
		if err != nil {
			return 0, err
		}
		password = pw
		defer clear(password)
	}
	msg, err := buildMessage(c.From, c.To, subject, text, page, e.deps.now())
	if err != nil {
		return 0, err
	}
	if e.deps.Gateway == nil {
		return 0, errors.New("notify: no egress gateway")
	}
	ctx, cancel := context.WithTimeout(ctx, emailTimeout)
	defer cancel()
	conn, err := e.deps.Gateway.DialContext(ctx, policy.PurposeEmail, "tcp", smtpAddr(c.Host, c.Port))
	if err != nil {
		return 0, denied(err, c.Host, policy.PurposeEmail)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	// Closing the connection when the context ends unblocks any pending read.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	cfg := e.tlsConfig()
	if c.Port == 465 {
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return 0, fmt.Errorf("notify: TLS with %s failed: %w", c.Host, err)
		}
		conn = tc
	}
	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return 0, fmt.Errorf("notify: SMTP greeting from %s failed: %w", c.Host, err)
	}
	defer client.Close()
	if c.Port != 465 {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return 0, errors.New("notify: server does not offer STARTTLS")
		}
		if err := client.StartTLS(cfg); err != nil {
			return 0, fmt.Errorf("notify: STARTTLS with %s failed: %w", c.Host, err)
		}
	}
	if c.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", c.Username, string(password), c.Host)); err != nil {
			return 0, fmt.Errorf("notify: SMTP authentication on %s failed: %w", c.Host, err)
		}
	}
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return 0, fmt.Errorf("notify: from is not an email address: %w", err)
	}
	if err := client.Mail(from.Address); err != nil {
		return 0, fmt.Errorf("notify: %s refused the sender: %w", c.Host, err)
	}
	for _, to := range c.To {
		a, err := mail.ParseAddress(to)
		if err != nil {
			return 0, fmt.Errorf("notify: a recipient is not an email address: %w", err)
		}
		if err := client.Rcpt(a.Address); err != nil {
			return 0, fmt.Errorf("notify: %s refused a recipient: %w", c.Host, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return 0, fmt.Errorf("notify: %s refused the message: %w", c.Host, err)
	}
	if _, err := w.Write(msg); err != nil {
		return 0, fmt.Errorf("notify: sending the message to %s failed: %w", c.Host, err)
	}
	if err := w.Close(); err != nil {
		return 0, fmt.Errorf("notify: %s refused the message: %w", c.Host, err)
	}
	_ = client.Quit()
	return len(msg), nil
}

// buildMessage writes a multipart/alternative message (text then HTML, both
// UTF-8 quoted-printable) with CRLF line ends.
func buildMessage(from string, to []string, subject, text, page string, now time.Time) ([]byte, error) {
	for _, h := range append([]string{from, subject}, to...) {
		if strings.ContainsAny(h, "\r\n") {
			return nil, errors.New("notify: a mail header holds a line break")
		}
	}
	var rnd [12]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	boundary := "michel-" + hex.EncodeToString(rnd[:])
	var b bytes.Buffer
	header := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	header("From", from)
	header("To", strings.Join(to, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", subject))
	header("Date", now.Format(time.RFC1123Z))
	header("Message-ID", "<"+ulid.Make().String()+"@michel.local>")
	header("MIME-Version", "1.0")
	header("Content-Type", "multipart/alternative; boundary="+boundary)
	b.WriteString("\r\n")
	for _, part := range []struct{ kind, body string }{{"text/plain", text}, {"text/html", page}} {
		b.WriteString("--" + boundary + "\r\n")
		header("Content-Type", part.kind+"; charset=utf-8")
		header("Content-Transfer-Encoding", "quoted-printable")
		b.WriteString("\r\n")
		qp := quotedprintable.NewWriter(&b)
		if _, err := qp.Write([]byte(part.body)); err != nil {
			return nil, err
		}
		if err := qp.Close(); err != nil {
			return nil, err
		}
		b.WriteString("\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return b.Bytes(), nil
}
