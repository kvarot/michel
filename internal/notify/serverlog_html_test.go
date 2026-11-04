package notify

import (
	"bytes"
	"context"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/serverlog"
)

// The HTML part of a message with several lines keeps them apart.
func TestLogAlertMailHTMLKeepsTheLines(t *testing.T) {
	srvTLS, cliTLS := testCert(t)
	srv := startSMTP(t, srvTLS, false, false)
	withSMTPAddr(t, srv.addr())
	n, err := New(emailChannel(587), Deps{Gateway: gateway(nil, policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeEmail}),
		Secrets: memSecrets{"smtp-perso": "pw-123"}, Version: "1.2.3", TLSConfig: cliTLS, Lang: i18n.EN,
		Now: func() time.Time { return time.Date(2026, 10, 23, 6, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	in := serverlog.AlertInput{Target: logServer(), Kind: serverlog.AlertNew, Items: []serverlog.AlertItem{
		{Kind: serverlog.AlertNew, Level: serverlog.LevelError, Type: "PDOException", Location: "Invoice.php:42", Count: 3},
		{Kind: serverlog.AlertNew, Level: serverlog.LevelError, Type: "TypeError", Location: "Cart.php:7", Count: 1},
	}}
	for _, d := range SendLogAlert(context.Background(), []Notifier{n}, in, false, logPage, alertNow) {
		if d.Result != ResultOK {
			t.Fatalf("%+v", d)
		}
	}
	m, err := mail.ReadMessage(strings.NewReader(srv.snapshot().data))
	if err != nil {
		t.Fatal(err)
	}
	_, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	var page string
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		if strings.HasPrefix(p.Header.Get("Content-Type"), "text/html") {
			raw, _ := io.ReadAll(quotedprintable.NewReader(p))
			page = string(raw)
		}
	}
	page = strings.ReplaceAll(page, "\r\n", "\n")
	if !strings.Contains(page, "in the logs<br>\n- PDOException, Invoice.php:42, 3 times (new)<br>\n- TypeError, Cart.php:7, 1 time (new)<br>\n") {
		t.Errorf("html part: %q", bytes.TrimSpace([]byte(page)))
	}
}
