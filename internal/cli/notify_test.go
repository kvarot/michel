package cli

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// hookRecorder is a loopback webhook receiver.
type hookRecorder struct {
	*httptest.Server
	mu     sync.Mutex
	bodies [][]byte
	sigs   []string
	stamps []string
}

func newHookRecorder(t *testing.T) *hookRecorder {
	t.Helper()
	h := &hookRecorder{}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.bodies = append(h.bodies, b)
		h.sigs = append(h.sigs, r.Header.Get("X-Michel-Signature"))
		h.stamps = append(h.stamps, r.Header.Get("X-Michel-Timestamp"))
		h.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *hookRecorder) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.bodies)
}

// writeNotifyCfg writes a policy with a loopback webhook (signed with
// hookSecret when set) and an email channel whose password is not stored.
func writeNotifyCfg(t *testing.T, dir, hookURL, hookSecret string) {
	t.Helper()
	cfg := `sovereignty:
  network:
    default_egress: deny
    allow:
      - {host: 127.0.0.1, purpose: notify.webhook}
      - {host: smtp.example.org, purpose: notify.email}
notify:
  channels:
    - name: hook
      type: webhook
      url: ` + hookURL + `/michel
      secret: "` + hookSecret + `"
    - name: mail-perso
      type: email
      host: smtp.example.org
      port: 587
      from: michel@example.org
      to: [me@example.org]
      username: me
      password_secret: smtp-perso
      projects: [demo]
    - name: off
      type: toast
      enabled: false
`
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDigestSendContinuesAfterChannelFailure(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	h := newHookRecorder(t)
	writeNotifyCfg(t, dir, h.URL, "")
	_, out, stderr, err := run(t, dir, "--lang", "en", "digest", "--send")
	if err == nil || ExitCode(err) != 1 {
		t.Fatalf("err = %v (code %d)", err, ExitCode(err))
	}
	if !strings.HasPrefix(out, "Michel found 3 new findings since the last digest") {
		t.Errorf("the digest was not printed:\n%s", out)
	}
	if h.count() != 1 {
		t.Errorf("webhook got %d requests", h.count())
	}
	for _, want := range []string{"Sent on hook (webhook).", "Not sent on mail-perso (email)", "michel secret set smtp-perso",
		"1 channel did not get the digest"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	runs := digestRuns(t, dir)
	if len(runs) != 1 {
		t.Fatalf("runs = %+v", runs)
	}
	var channels []map[string]string
	if err := json.Unmarshal([]byte(runs[0].channels), &channels); err != nil || len(channels) != 2 ||
		channels[0]["name"] != "hook" || channels[0]["result"] != "ok" ||
		channels[1]["name"] != "mail-perso" || channels[1]["result"] != "error" || !strings.Contains(channels[1]["error"], "michel secret set smtp-perso") {
		t.Fatalf("channels = %s", runs[0].channels)
	}
	sends := auditRows(t, dir, "notify.send")
	if len(sends) != 2 {
		t.Fatalf("notify.send = %+v", sends)
	}
	ev := sends[0].evidence
	if ev["channel"] != "hook" || ev["type"] != "webhook" || ev["host"] != "127.0.0.1" || ev["result"] != "ok" || ev["run_id"] != runs[0].id ||
		ev["bytes"] == float64(0) || ev["bytes"] == nil {
		t.Errorf("notify.send hook = %v", ev)
	}
	if ev := sends[1].evidence; ev["channel"] != "mail-perso" || ev["host"] != "smtp.example.org" || ev["result"] != "error" || ev["bytes"] != float64(0) {
		t.Errorf("notify.send mail = %v", ev)
	}
	if rows := auditRows(t, dir, "digest.run"); len(rows) != 1 || lastEventID(t, dir, "digest.run") < lastEventID(t, dir, "notify.send") {
		t.Errorf("digest.run = %+v", rows)
	}

	// In French, the same what / why / what next.
	_, _, stderr, _ = run(t, dir, "--lang", "fr", "digest", "--send")
	if !strings.Contains(stderr, "michel secret set smtp-perso") || !strings.Contains(stderr, "Envoyé sur hook") {
		t.Errorf("fr stderr:\n%s", stderr)
	}
	// The second digest restricted to demo has nothing new: the email is
	// still attempted (demo is in the digest), the run is recorded.
	if runs := digestRuns(t, dir); len(runs) != 2 {
		t.Errorf("runs = %d", len(runs))
	}
}

func TestNotifyTestAndList(t *testing.T) {
	dir := t.TempDir()
	h := newHookRecorder(t)
	writeNotifyCfg(t, dir, h.URL, "")

	_, out, _, err := run(t, dir, "--lang", "en", "notify", "list")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "name") {
		t.Fatalf("list:\n%s", out)
	}
	for i, want := range [][]string{{"hook", "webhook", "true", "127.0.0.1", "all"}, {"mail-perso", "email", "true", "smtp.example.org:587", "demo"},
		{"off", "toast", "false", "local"}} {
		for _, w := range want {
			if !strings.Contains(lines[i+1], w) {
				t.Errorf("line %q lacks %q", lines[i+1], w)
			}
		}
	}
	if strings.Contains(out, "/michel") || strings.Contains(out, "smtp-perso") {
		t.Errorf("list shows a url path or a secret name:\n%s", out)
	}
	_, out, _, err = run(t, dir, "notify", "list", "--json")
	var list []map[string]any
	if err != nil || json.Unmarshal([]byte(out), &list) != nil || len(list) != 3 || list[1]["target"] != "smtp.example.org:587" || list[2]["enabled"] != false {
		t.Fatalf("json: %v\n%s", err, out)
	}

	_, out, _, err = run(t, dir, "--lang", "en", "notify", "test", "hook")
	if err != nil || !strings.Contains(out, "Michel sent a test message on hook") || h.count() != 1 {
		t.Fatalf("test hook: %v\n%s", err, out)
	}
	var doc map[string]any
	if json.Unmarshal(h.bodies[0], &doc) != nil || doc["michel_test"] != float64(1) || doc["michel_digest"] != nil {
		t.Errorf("test body = %s", h.bodies[0])
	}
	rows := auditRows(t, dir, "notify.test")
	if len(rows) != 1 || rows[0].target != "hook" || rows[0].result != "ok" || rows[0].evidence["host"] != "127.0.0.1" || rows[0].evidence["type"] != "webhook" {
		t.Errorf("notify.test = %+v", rows)
	}

	_, _, stderr, err := run(t, dir, "--lang", "en", "notify", "test", "mail-perso")
	if err == nil || ExitCode(err) != 1 || !strings.Contains(stderr, "michel secret set smtp-perso") {
		t.Errorf("test mail: %v\n%s", err, stderr)
	}
	if rows := auditRows(t, dir, "notify.test"); len(rows) != 2 || rows[1].result != "error" {
		t.Errorf("notify.test = %+v", rows)
	}

	// A disabled channel can be tested; Michel says it is disabled.
	_, _, stderr, _ = run(t, dir, "--lang", "en", "notify", "test", "off")
	if !strings.Contains(stderr, "off is disabled") {
		t.Errorf("disabled:\n%s", stderr)
	}

	if _, _, _, err := run(t, dir, "--lang", "en", "notify", "test", "absent"); err == nil || !strings.Contains(err.Error(), "michel notify list") {
		t.Errorf("unknown: %v", err)
	}

	empty := t.TempDir()
	if _, out, _, err := run(t, empty, "--lang", "en", "notify", "list"); err != nil || !strings.Contains(out, "No notification channel") {
		t.Errorf("empty list: %v\n%s", err, out)
	}
}

func TestNotifyNeverLogsSecretValue(t *testing.T) {
	const value = "hmac-k3y-value"
	dir, _ := scannedDemo(t, false)
	h := newHookRecorder(t)
	writeNotifyCfg(t, dir, h.URL, "hook-key")
	var outputs []string
	keep := func(out, stderr string, err error) {
		outputs = append(outputs, out, stderr)
		if err != nil {
			outputs = append(outputs, err.Error())
		}
	}
	out, stderr, err := runIn(t, dir, strings.NewReader(value), "secret", "set", "hook-key")
	keep(out, stderr, err)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"notify", "test", "hook"}, {"notify", "list"}, {"notify", "list", "--json"}, {"digest", "--send"},
		{"digest", "--send", "--json"}} {
		_, out, stderr, err := run(t, dir, args...)
		keep(out, stderr, err)
	}
	if h.count() != 3 {
		t.Fatalf("webhook got %d requests", h.count())
	}
	// The receiver can check every signature with the key.
	for i, b := range h.bodies {
		mac := hmac.New(sha256.New, []byte(value))
		mac.Write([]byte(h.stamps[i] + "." + string(b)))
		if h.sigs[i] != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
			t.Errorf("request %d: bad signature", i)
		}
	}
	for _, o := range outputs {
		if strings.Contains(o, value) {
			t.Fatalf("secret value in output %q", o)
		}
	}
	if a := allAuditText(t, dir); strings.Contains(a, value) {
		t.Fatalf("secret value in the audit:\n%s", a)
	}
	for _, r := range digestRuns(t, dir) {
		if strings.Contains(r.channels, value) {
			t.Fatalf("secret value in digest_run: %s", r.channels)
		}
	}
}

func TestDigestSendWithoutSecretStoreStillSendsOthers(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	h := newHookRecorder(t)
	writeNotifyCfg(t, dir, h.URL, "")
	// A file where the secrets folder should be: the store cannot be opened.
	if err := os.WriteFile(filepath.Join(dir, "secrets"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, stderr, err := run(t, dir, "--lang", "en", "digest", "--send")
	if err == nil || ExitCode(err) != 1 {
		t.Fatalf("err = %v (code %d)", err, ExitCode(err))
	}
	if h.count() != 1 || !strings.Contains(stderr, "Sent on hook (webhook).") || !strings.Contains(stderr, "secret store cannot be opened") {
		t.Errorf("hook requests %d, stderr:\n%s", h.count(), stderr)
	}
	runs := digestRuns(t, dir)
	if len(runs) != 1 || !strings.Contains(runs[0].channels, `"name":"hook","type":"webhook","result":"ok"`) ||
		!strings.Contains(runs[0].channels, `"result":"error","error":"cannot read secret smtp-perso: the secret store cannot be opened`) {
		t.Fatalf("runs = %+v", runs)
	}
}
