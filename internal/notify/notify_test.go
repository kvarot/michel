package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/digest"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/secret"
)

// memSecrets is an in-memory secret.Store.
type memSecrets map[string]string

func (m memSecrets) Set(name string, value []byte) error { m[name] = string(value); return nil }
func (m memSecrets) Get(name string) ([]byte, error) {
	v, ok := m[name]
	if !ok {
		return nil, secret.ErrNotFound
	}
	return []byte(v), nil
}
func (m memSecrets) Delete(name string) error { delete(m, name); return nil }
func (m memSecrets) List() ([]string, error) {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out, nil
}

// sinkFunc records gateway attempts.
type attemptSink struct {
	mu   sync.Mutex
	list []egress.Attempt
}

func (s *attemptSink) Record(a egress.Attempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = append(s.list, a)
	return nil
}

func gateway(sink egress.Sink, rules ...policy.AllowRule) *egress.Gateway {
	p := policy.Defaults()
	p.Sovereignty.Network.Allow = rules
	return egress.New(p, sink)
}

// sample is a small digest of two projects.
func sample() digest.Digest {
	d := digest.Digest{SchemaVersion: digest.SchemaVersion, Lang: i18n.EN, Assistant: "Michel",
		Since: time.Date(2026, 10, 22, 6, 0, 0, 0, time.UTC), Until: time.Date(2026, 10, 23, 6, 0, 0, 0, time.UTC),
		PageURL: "http://127.0.0.1:7331/", Projects: []digest.ProjectDigest{
			{Name: "demo", New: []digest.Package{{Name: "acme/lib", Ecosystem: "Packagist", Installed: "1.0.0", Target: "1.0.1",
				WorstSeverity: "critical", OSVIDs: []string{"ACME-2026-0001"}, FindingIDs: []string{"f1"}, What: "acme/lib lets an attacker in."}},
				Open: map[string]int{"critical": 1}, Decided: map[string]int{}, Total: 1, Attention: 1, LastScanStatus: "ok"},
			{Name: "project-a", New: []digest.Package{{Name: "vuln-pkg", Ecosystem: "npm", Installed: "2.0.0", Target: "2.0.1",
				WorstSeverity: "low", OSVIDs: []string{"ACME-2026-0003"}, FindingIDs: []string{"f2"}}},
				Open: map[string]int{"low": 1}, Decided: map[string]int{}, Total: 1, LastScanStatus: "ok"},
		}}
	return digest.Filter(d, []string{"demo", "project-a"})
}

// withSMTPAddr sends every SMTP dial to addr for the test's duration.
func withSMTPAddr(t *testing.T, addr string) {
	t.Helper()
	old := smtpAddr
	smtpAddr = func(string, int) string { return addr }
	t.Cleanup(func() { smtpAddr = old })
}

func emailChannel(port int) policy.ChannelConfig {
	return policy.ChannelConfig{Name: "mail-perso", Type: "email", Host: "127.0.0.1", Port: port, From: "michel@example.org",
		To: []string{"me@example.org", "Other <other@example.org>"}, Username: "me", PasswordSecret: "smtp-perso"}
}

func TestEmailSendsMultipartOverStartTLS(t *testing.T) {
	srvTLS, cliTLS := testCert(t)
	srv := startSMTP(t, srvTLS, false, false)
	withSMTPAddr(t, srv.addr())
	n, err := New(emailChannel(587), Deps{Gateway: gateway(nil, policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeEmail}),
		Secrets: memSecrets{"smtp-perso": "pw-123"}, Version: "1.2.3", TLSConfig: cliTLS, Lang: i18n.FR,
		Now: func() time.Time { return time.Date(2026, 10, 23, 6, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	d := sample()
	d.Lang = i18n.FR
	d = digest.Filter(d, []string{"demo", "project-a"})
	if err := n.Send(context.Background(), d); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := srv.snapshot()
	cmds := strings.Join(got.commands, " ")
	if !strings.HasPrefix(cmds, "EHLO STARTTLS EHLO AUTH MAIL RCPT RCPT DATA") || !strings.Contains(cmds, "QUIT") {
		t.Errorf("commands = %s", cmds)
	}
	if got.auth != "\x00me\x00pw-123" || !got.authTLS {
		t.Errorf("auth = %q over TLS %v", got.auth, got.authTLS)
	}
	if got.from != "michel@example.org" || strings.Join(got.rcpts, ",") != "me@example.org,other@example.org" {
		t.Errorf("from %q rcpts %v", got.from, got.rcpts)
	}
	msg := got.data
	for _, want := range []string{"From: michel@example.org\r\n", "To: me@example.org, Other <other@example.org>\r\n", "MIME-Version: 1.0\r\n",
		"Content-Type: multipart/alternative; boundary=", "Content-Type: text/plain; charset=utf-8", "Content-Type: text/html; charset=utf-8",
		"Content-Transfer-Encoding: quoted-printable", "Message-ID: <", "@michel.local>\r\n", "Date: Fri, 23 Oct 2026 06:00:00 +0000\r\n"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
	if strings.Index(msg, "text/plain") > strings.Index(msg, "text/html") {
		t.Error("the text part must come before the HTML part")
	}
	var subject string
	for _, l := range strings.Split(msg, "\r\n") {
		if s, ok := strings.CutPrefix(l, "Subject: "); ok {
			subject = s
		}
	}
	dec, err := new(mime.WordDecoder).DecodeHeader(subject)
	if err != nil || dec != "Michel · 23/10/2026 · 2 nouveautés" || !strings.HasPrefix(subject, "=?utf-8?q?") {
		t.Errorf("subject %q -> %q (%v)", subject, dec, err)
	}
	if strings.Contains(msg, "pw-123") {
		t.Error("the password is in the message")
	}

	// Test sends the fixed message, without any digest data.
	if err := n.Test(context.Background()); err != nil {
		t.Fatalf("test: %v", err)
	}
	msg = srv.snapshot().data
	if strings.Contains(msg, "acme/lib") || strings.Contains(msg, "demo") || !strings.Contains(msg, "Subject: =?utf-8?q?") {
		t.Errorf("test message:\n%s", msg)
	}
}

func TestEmailImplicitTLSAndNoStartTLSRefused(t *testing.T) {
	srvTLS, cliTLS := testCert(t)
	srv := startSMTP(t, srvTLS, true, false)
	withSMTPAddr(t, srv.addr())
	deps := Deps{Gateway: gateway(nil, policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeEmail}),
		Secrets: memSecrets{"smtp-perso": "pw"}, TLSConfig: cliTLS, Lang: i18n.EN}
	n, err := New(emailChannel(465), deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Send(context.Background(), sample()); err != nil {
		t.Fatalf("465: %v", err)
	}
	if got := srv.snapshot(); !got.authTLS || strings.Contains(strings.Join(got.commands, " "), "STARTTLS") {
		t.Errorf("465 session = %+v", got.commands)
	}

	plain := startSMTP(t, srvTLS, false, true)
	withSMTPAddr(t, plain.addr())
	n, _ = New(emailChannel(587), deps)
	err = n.Send(context.Background(), sample())
	if err == nil || !strings.Contains(err.Error(), "notify: server does not offer STARTTLS") {
		t.Fatalf("no STARTTLS: %v", err)
	}
	if got := plain.snapshot(); got.auth != "" || got.data != "" {
		t.Errorf("sent in clear: %+v", got)
	}
}

func TestEmailDeniedByPolicySaysWhichRule(t *testing.T) {
	sink := &attemptSink{}
	n, err := New(emailChannel(587), Deps{Gateway: gateway(sink), Secrets: memSecrets{"smtp-perso": "pw"}, Lang: i18n.EN})
	if err != nil {
		t.Fatal(err)
	}
	err = n.Send(context.Background(), sample())
	if !errors.Is(err, egress.ErrEgressDenied) {
		t.Fatalf("err = %v", err)
	}
	var denied *DeniedError
	if !errors.As(err, &denied) || denied.Host != "127.0.0.1" || denied.Purpose != policy.PurposeEmail {
		t.Fatalf("denied = %+v", denied)
	}
	if !strings.Contains(err.Error(), "add under sovereignty.network.allow: {host: 127.0.0.1, purpose: notify.email}") {
		t.Errorf("err = %v", err)
	}
	if len(sink.list) != 1 || sink.list[0].Allowed || sink.list[0].Purpose != policy.PurposeEmail {
		t.Errorf("attempts = %+v", sink.list)
	}
}

func TestEmailMissingSecret(t *testing.T) {
	sink := &attemptSink{}
	n, err := New(emailChannel(587), Deps{Gateway: gateway(sink, policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeEmail}),
		Secrets: memSecrets{}, Lang: i18n.EN})
	if err != nil {
		t.Fatal(err)
	}
	err = n.Send(context.Background(), sample())
	var missing *SecretMissingError
	if !errors.Is(err, ErrSecretMissing) || !errors.As(err, &missing) || missing.Name != "smtp-perso" {
		t.Fatalf("err = %v", err)
	}
	if err.Error() != `secret "smtp-perso" is not set: run michel secret set smtp-perso` {
		t.Errorf("message = %q", err.Error())
	}
	if len(sink.list) != 0 {
		t.Errorf("dialed without a password: %+v", sink.list)
	}
}

// hookServer records the last request.
type hookServer struct {
	*httptest.Server
	mu     sync.Mutex
	header http.Header
	body   []byte
	status int
	reply  string
}

func startHook(t *testing.T, status int, reply string) *hookServer {
	t.Helper()
	h := &hookServer{status: status, reply: reply}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.header, h.body = r.Header.Clone(), b
		h.mu.Unlock()
		w.WriteHeader(h.status)
		io.WriteString(w, h.reply)
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *hookServer) last() (http.Header, []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.header, h.body
}

func hookChannel(u, format, secretName string) policy.ChannelConfig {
	return policy.ChannelConfig{Name: "hook", Type: "webhook", URL: u + "/michel", Format: format, Secret: secretName}
}

func hookDeps(sink egress.Sink, secrets memSecrets) Deps {
	return Deps{Gateway: gateway(sink, policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeWebhook}), Secrets: secrets,
		Version: "1.2.3", Lang: i18n.EN, Now: func() time.Time { return time.Date(2026, 10, 23, 6, 0, 0, 0, time.UTC) }}
}

func TestWebhookGenericSignature(t *testing.T) {
	h := startHook(t, http.StatusNoContent, "")
	n, err := New(hookChannel(h.URL, "", "hook-key"), hookDeps(nil, memSecrets{"hook-key": "k3y"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	hdr, body := h.last()
	ts := hdr.Get("X-Michel-Timestamp")
	if ts != "2026-10-23T06:00:00Z" {
		t.Errorf("timestamp = %q", ts)
	}
	mac := hmac.New(sha256.New, []byte("k3y"))
	mac.Write([]byte(ts + "." + string(body)))
	if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); hdr.Get("X-Michel-Signature") != want {
		t.Errorf("signature = %q, want %q", hdr.Get("X-Michel-Signature"), want)
	}
	if hdr.Get("Content-Type") != "application/json" || hdr.Get("User-Agent") != "michel/1.2.3" {
		t.Errorf("headers = %v", hdr)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil || doc["michel_digest"] != float64(1) || doc["new_total"] != float64(2) {
		t.Errorf("body: %v\n%s", err, body)
	}
}

func TestWebhookSlackAndDiscordFormats(t *testing.T) {
	h := startHook(t, http.StatusOK, "ok")
	n, err := New(hookChannel(h.URL, "slack", ""), hookDeps(nil, memSecrets{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	hdr, body := h.last()
	var slack map[string]string
	if err := json.Unmarshal(body, &slack); err != nil || len(slack) != 1 || !strings.HasPrefix(slack["text"], "Michel found 2 new findings tonight") {
		t.Errorf("slack: %v\n%s", err, body)
	}
	if hdr.Get("X-Michel-Signature") != "" || hdr.Get("X-Michel-Timestamp") == "" {
		t.Errorf("unsigned channel headers = %v", hdr)
	}

	// A long digest is cut for Discord.
	big := sample()
	for i := 0; i < 200; i++ {
		big.Projects[1].New = append(big.Projects[1].New, digest.Package{Name: "vuln-pkg-" + strconv.Itoa(i), Ecosystem: "npm",
			Installed: "1.0.0", Target: "1.0.1", WorstSeverity: "low", OSVIDs: []string{"ACME-2026-0004"}, FindingIDs: []string{"x" + strconv.Itoa(i)}})
	}
	n, _ = New(hookChannel(h.URL, "discord", ""), hookDeps(nil, memSecrets{}))
	if err := n.Send(context.Background(), big); err != nil {
		t.Fatal(err)
	}
	_, body = h.last()
	var discord map[string]string
	if err := json.Unmarshal(body, &discord); err != nil || len(discord) != 1 || discord["content"] == "" {
		t.Fatalf("discord: %v\n%s", err, body)
	}
	if c := utf8.RuneCountInString(discord["content"]); c > 1900 {
		t.Errorf("discord content is %d runes", c)
	}
	if !strings.HasPrefix(discord["content"], "Michel found") {
		t.Errorf("discord = %q", discord["content"][:80])
	}
}

func TestWebhookNon2xxIsError(t *testing.T) {
	h := startHook(t, http.StatusInternalServerError, "leaked-response-body")
	n, err := New(hookChannel(h.URL, "", ""), hookDeps(nil, memSecrets{}))
	if err != nil {
		t.Fatal(err)
	}
	err = n.Send(context.Background(), sample())
	if err == nil || !strings.Contains(err.Error(), "500") || strings.Contains(err.Error(), "leaked-response-body") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "/michel") {
		t.Errorf("the url path is in the error: %v", err)
	}

	// A redirect is not followed: the body never goes elsewhere.
	other := startHook(t, http.StatusOK, "")
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	n, _ = New(hookChannel(redir.URL, "", ""), hookDeps(nil, memSecrets{}))
	if err := n.Send(context.Background(), sample()); err == nil || !strings.Contains(err.Error(), "307") {
		t.Errorf("redirect: %v", err)
	}
	if _, body := other.last(); body != nil {
		t.Error("the redirect was followed")
	}
}

func TestWebhookMissingSecret(t *testing.T) {
	h := startHook(t, http.StatusOK, "")
	n, _ := New(hookChannel(h.URL, "", "hook-key"), hookDeps(nil, memSecrets{}))
	if err := n.Send(context.Background(), sample()); !errors.Is(err, ErrSecretMissing) {
		t.Fatalf("err = %v", err)
	}
	if _, body := h.last(); body != nil {
		t.Error("sent unsigned")
	}
}

// captureRunner records the subprocess it is asked to run.
type captureRunner struct {
	name  string
	args  []string
	stdin []byte
	err   error
}

func (c *captureRunner) Run(_ context.Context, name string, args []string, stdin []byte) error {
	c.name, c.args, c.stdin = name, args, stdin
	return c.err
}

// decodeScript decodes a -EncodedCommand argument (UTF-16LE, base64).
func decodeScript(t *testing.T, arg string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(arg)
	if err != nil || len(raw)%2 != 0 {
		t.Fatalf("encoded command: %v", err)
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(units))
}

func TestToastWindowsScriptIsConstant(t *testing.T) {
	r := &captureRunner{}
	n, err := New(policy.ChannelConfig{Name: "bureau", Type: "toast"}, Deps{Runner: r, Lang: i18n.EN})
	if err != nil {
		t.Fatal(err)
	}
	n.(*toast).command = windowsCommand(`C:\Windows`)

	// The reference: a plain title and project.
	if err := n.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	if r.name != `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` {
		t.Errorf("name = %q", r.name)
	}
	if len(r.args) != 4 || r.args[0] != "-NoProfile" || r.args[1] != "-NonInteractive" || r.args[2] != "-EncodedCommand" {
		t.Fatalf("args = %q", r.args)
	}
	reference := r.args[3]
	script := decodeScript(t, reference)
	for _, want := range []string{"[Console]::InputEncoding = [Text.Encoding]::UTF8", "[Console]::In.ReadToEnd() | ConvertFrom-Json",
		"Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime",
		"Windows.Data.Xml.Dom.XmlDocument", `<binding template="ToastGeneric">`, "CreateTextNode([string]$in.title)", "CreateTextNode([string]$in.body)",
		`CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe').Show($toast)`} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "demo") || strings.Contains(script, "Michel found") {
		t.Errorf("text inside the script:\n%s", script)
	}

	// Hostile texts: curly quotes PowerShell takes as single quotes,
	// backticks, subexpressions, XML, line breaks, in the title and in a
	// project name. The script never changes; stdin carries them verbatim.
	for _, hostile := range []string{
		"l’appli", "‘a’ ‚b‛", "x’; Write-Output INJECTED; ‘y", "`n`$x`", "$(Write-Output INJECTED)", "<b>&amp;</b> \"q\" 'q'",
		"line1\nline2", "tab\there", "é ü 漢字 😀",
	} {
		d := sample()
		d.Projects[0].Name = hostile
		d.Title = "title " + hostile
		if err := n.Send(context.Background(), d); err != nil {
			t.Fatalf("%q: %v", hostile, err)
		}
		if len(r.args) != 4 || r.args[3] != reference {
			t.Errorf("%q changed the script:\n%s", hostile, decodeScript(t, r.args[3]))
		}
		for _, b := range r.stdin {
			if b >= 0x80 {
				t.Errorf("%q: stdin is not ASCII: %s", hostile, r.stdin)
				break
			}
		}
		var in map[string]string
		if err := json.Unmarshal(r.stdin, &in); err != nil || len(in) != 2 {
			t.Fatalf("%q: stdin %s: %v", hostile, r.stdin, err)
		}
		_, body := digest.ToastLines(d)
		if in["title"] != "title "+hostile || in["body"] != body || !strings.Contains(in["body"], hostile) {
			t.Errorf("%q: stdin = %q", hostile, in)
		}
	}

	// Other control characters, which XML refuses, become spaces.
	d := sample()
	d.Title = "a\x01b\x7fc"
	if err := n.Send(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	var in map[string]string
	if json.Unmarshal(r.stdin, &in) != nil || in["title"] != "a b c" {
		t.Errorf("control characters: %q", in)
	}
}

func TestToastLinuxUsesNotifySend(t *testing.T) {
	r := &captureRunner{}
	n, _ := New(policy.ChannelConfig{Name: "bureau", Type: "toast"}, Deps{Runner: r, Lang: i18n.EN})
	n.(*toast).command = linuxCommand(func(string) (string, error) { return "/usr/bin/notify-send", nil })
	if err := n.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	if r.name != "/usr/bin/notify-send" || len(r.args) != 3 || r.args[0] != "--" || r.args[1] != "Michel" ||
		!strings.Contains(r.args[2], "demo: 1 new, 1 to review") || r.stdin != nil {
		t.Errorf("run %q %q", r.name, r.args)
	}
	n.(*toast).command = linuxCommand(func(string) (string, error) { return "", errors.New("not found") })
	if err := n.Send(context.Background(), sample()); err == nil || err.Error() != "notify: notify-send not found" {
		t.Errorf("absent: %v", err)
	}

	n.(*toast).command = darwinCommand
	d := sample()
	d.Title = "say \"hi\" \\ bye\nnext"
	if err := n.Send(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if r.name != "/usr/bin/osascript" || len(r.args) != 2 || r.args[0] != "-e" || !strings.Contains(r.args[1], `say \"hi\" \\ bye next`) ||
		!strings.HasSuffix(r.args[1], `with title "Michel"`) {
		t.Errorf("osascript %q", r.args)
	}

	// Test shows the fixed message.
	if err := n.Test(context.Background()); err != nil || strings.Contains(r.args[1], "demo") {
		t.Errorf("test: %v %q", err, r.args)
	}
}

// fake is a Notifier that records what it received.
type fake struct {
	name     string
	projects []string
	err      error
	got      []digest.Digest
}

func (f *fake) Name() string       { return f.name }
func (f *fake) Type() string       { return "webhook" }
func (f *fake) Projects() []string { return f.projects }
func (f *fake) Send(_ context.Context, d digest.Digest) error {
	f.got = append(f.got, d)
	return f.err
}
func (f *fake) Test(context.Context) error { return f.err }

func TestSendAllContinuesAfterFailure(t *testing.T) {
	a, b, c := &fake{name: "a", err: errors.New("boom")}, &fake{name: "b"}, &fake{name: "c", err: errors.New("down")}
	res := SendAll(context.Background(), []Notifier{a, b, c}, sample())
	if len(res) != 3 || len(a.got) != 1 || len(b.got) != 1 || len(c.got) != 1 {
		t.Fatalf("res = %+v", res)
	}
	want := []digest.ChannelResult{{Name: "a", Type: "webhook", Result: "error", Error: "boom"}, {Name: "b", Type: "webhook", Result: "ok"},
		{Name: "c", Type: "webhook", Result: "error", Error: "down"}}
	for i := range want {
		if res[i] != want[i] {
			t.Errorf("res[%d] = %+v, want %+v", i, res[i], want[i])
		}
	}
	if res := SendAll(context.Background(), nil, sample()); res == nil || len(res) != 0 {
		t.Errorf("no channel: %#v", res)
	}
}

func TestSendAllFiltersProjects(t *testing.T) {
	all, only, none := &fake{name: "all"}, &fake{name: "only", projects: []string{"project-a"}}, &fake{name: "none", projects: []string{"absent"}}
	res := SendAll(context.Background(), []Notifier{all, only, none}, sample())
	if res[0].Result != "ok" || res[1].Result != "ok" || res[2].Result != "skipped" || len(none.got) != 0 {
		t.Fatalf("res = %+v", res)
	}
	if len(all.got[0].Projects) != 2 || all.got[0].NewTotal != 2 {
		t.Errorf("all = %+v", all.got[0])
	}
	g := only.got[0]
	if len(g.Projects) != 1 || g.Projects[0].Name != "project-a" || g.NewTotal != 1 || g.AttentionTotal != 0 ||
		g.Title != "Michel found 1 new finding tonight" {
		t.Errorf("only = %+v", g)
	}
}

func TestNoBodyInAudit(t *testing.T) {
	sink := &attemptSink{}
	h := startHook(t, http.StatusBadGateway, "upstream-said-something")
	d := sample()
	d.Projects[0].New[0].Name = "acme/marker-package"
	n, err := New(hookChannel(h.URL+"/secret-path", "", "hook-key"), hookDeps(sink, memSecrets{"hook-key": "k3y-value"}))
	if err != nil {
		t.Fatal(err)
	}
	dl := Deliver(context.Background(), []Notifier{n}, d)
	if len(dl) != 1 || dl[0].Result != "error" || dl[0].Host != "127.0.0.1" || dl[0].Purpose != policy.PurposeWebhook || dl[0].Bytes == 0 {
		t.Fatalf("delivery = %+v", dl)
	}
	_, body := h.last()
	if dl[0].Bytes != len(body) {
		t.Errorf("bytes = %d, body %d", dl[0].Bytes, len(body))
	}
	trace := fmt.Sprintf("%+v %+v %s", sink.list, dl[0].ChannelResult, dl[0].Err)
	for _, leak := range []string{"marker-package", "secret-path", "k3y-value", "upstream-said-something", "/michel"} {
		if strings.Contains(trace, leak) {
			t.Errorf("%q leaked: %s", leak, trace)
		}
	}
	// A toast reports "local" as its host and contacts no network.
	tn, _ := New(policy.ChannelConfig{Name: "bureau", Type: "toast"}, Deps{Runner: &captureRunner{}, Lang: i18n.EN})
	if dl := Deliver(context.Background(), []Notifier{tn}, d); dl[0].Host != "local" || dl[0].Result != "ok" {
		t.Errorf("toast = %+v", dl[0])
	}
}

func TestBuildSkipsDisabledAndRefusesUnknownType(t *testing.T) {
	off := false
	ns, err := Build(policy.NotifyConfig{Channels: []policy.ChannelConfig{{Name: "bureau", Type: "toast"},
		{Name: "off", Type: "toast", Enabled: &off}}}, Deps{Runner: &captureRunner{}})
	if err != nil || len(ns) != 1 || ns[0].Name() != "bureau" || ns[0].Type() != "toast" {
		t.Fatalf("ns = %v, %v", ns, err)
	}
	if _, err := Build(policy.NotifyConfig{Channels: []policy.ChannelConfig{{Name: "x", Type: "sms"}}}, Deps{}); err == nil {
		t.Error("unknown type accepted")
	}
}
