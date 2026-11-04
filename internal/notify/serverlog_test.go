package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/serverlog"
	"github.com/kvarot/michel/internal/target"
)

const logPage = "http://127.0.0.1:7331/#/servers/01SRVDEMO"

func logServer() target.Target {
	t := demoServer()
	t.Host, t.User, t.Port = "198.51.100.7", "deploy", 22
	return t
}

func phpAlert() serverlog.AlertInput {
	return serverlog.AlertInput{Target: logServer(), Kind: serverlog.AlertNew, Items: []serverlog.AlertItem{
		{Kind: serverlog.AlertNew, Level: serverlog.LevelCritical, Type: "PDOException", Location: "Invoice.php:42", Count: 37},
	}}
}

func hookText(t *testing.T, h *hookServer) string {
	t.Helper()
	_, body := h.last()
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("body: %v\n%s", err, body)
	}
	s, _ := doc["text"].(string)
	return s
}

func slackHook(t *testing.T) (*hookServer, Notifier) {
	t.Helper()
	h := startHook(t, http.StatusOK, "")
	n, err := New(policy.ChannelConfig{Name: "hook", Type: "webhook", URL: h.URL + "/m", Format: "slack"}, smsDeps(t, nil, memSecrets{}, nil, 3))
	if err != nil {
		t.Fatal(err)
	}
	return h, n
}

func TestLogAlertExactDefaultBody(t *testing.T) {
	h, n := slackHook(t)
	out := SendLogAlert(context.Background(), []Notifier{n}, phpAlert(), false, logPage, alertNow)
	if len(out) != 1 || out[0].Result != ResultOK {
		t.Fatalf("%+v", out)
	}
	want := "Michel · errors in the server logs\nServer srv-demo: 1 error in the logs\n- PDOException, Invoice.php:42, 37 times (new)\n" + logPage
	got := hookText(t, h)
	if got != want {
		t.Errorf("text = %q, want %q", got, want)
	}
	for _, bad := range []string{"198.51.100.7", "deploy"} {
		if strings.Contains(got, bad) {
			t.Errorf("the alert holds %q", bad)
		}
	}
	// The French text keeps the same facts.
	_, body := logMessage(i18n.FR, phpAlert(), logPage)
	for _, w := range []string{"PDOException", "Invoice.php:42", "37 fois", "srv-demo", logPage, "(nouvelle)"} {
		if !strings.Contains(body, w) {
			t.Errorf("fr %q lacks %q", body, w)
		}
	}
}

func TestLogAlertNamesTheReasonOfEachItem(t *testing.T) {
	in := serverlog.AlertInput{Target: logServer(), Kind: serverlog.AlertNew, Items: []serverlog.AlertItem{
		{Kind: serverlog.AlertNew, Type: "A", Location: "a.php:1", Count: 2},
		{Kind: serverlog.AlertReopened, Type: "B", Location: "b.php:2", Count: 1},
		{Kind: serverlog.AlertSpike, Type: "C", Count: 400},
	}}
	_, body := logMessage(i18n.EN, in, "")
	for _, w := range []string{"3 errors in the logs", "- A, a.php:1, 2 times (new)", "- B, b.php:2, 1 time (back)", "- C, 400 times (far more often than before)"} {
		if !strings.Contains(body, w) {
			t.Errorf("%q lacks %q", body, w)
		}
	}
}

func TestLogAlertListIsBounded(t *testing.T) {
	in := serverlog.AlertInput{Target: logServer(), Kind: serverlog.AlertNew}
	for i := 0; i < 8; i++ {
		in.Items = append(in.Items, serverlog.AlertItem{Kind: serverlog.AlertNew, Type: "E", Location: "f.php:1", Count: 1})
	}
	_, body := logMessage(i18n.EN, in, "")
	if !strings.Contains(body, "8 errors in the logs") || !strings.Contains(body, "… and 3 more errors, see the server page in Michel") ||
		strings.Count(body, "- E") != maxLogItems {
		t.Errorf("body = %q", body)
	}
}

func TestLogAlertNoTextByDefault(t *testing.T) {
	h, n := slackHook(t)
	SendLogAlert(context.Background(), []Notifier{n}, phpAlert(), false, logPage, alertNow)
	// Title, header, one item, link: nothing else.
	if got := hookText(t, h); strings.Count(got, "\n") != 3 {
		t.Errorf("an unexpected line in %q", got)
	}
}

func TestLogAlertTextWhenAllowed(t *testing.T) {
	h, n := slackHook(t)
	in := phpAlert()
	in.Items[0].Text = "SQLSTATE[HY000] connection to \"\" refused"
	SendLogAlert(context.Background(), []Notifier{n}, in, false, logPage, alertNow)
	if got := hookText(t, h); !strings.Contains(got, "SQLSTATE[HY000] connection to") {
		t.Errorf("the allowed text is missing: %q", got)
	}
	// Whatever the item holds is capped.
	in.Items[0].Text = strings.Repeat("x", 500)
	SendLogAlert(context.Background(), []Notifier{n}, in, false, logPage, alertNow)
	if got := hookText(t, h); strings.Contains(got, strings.Repeat("x", 201)) {
		t.Errorf("text not capped: %d bytes", len(got))
	}
}

func TestLogSMSOffByDefault(t *testing.T) {
	srv := startSMS(t, http.StatusOK)
	n, err := New(freeMobile(srv.URL, true), smsDeps(t, nil, memSecrets{"fm-key": "k-secret-1"}, newStoreCounter(t), 3))
	if err != nil {
		t.Fatal(err)
	}
	out := SendLogAlert(context.Background(), []Notifier{n}, phpAlert(), false, logPage, alertNow)
	if out[0].Result != ResultSkipped || srv.count() != 0 {
		t.Fatalf("sms sent by default: %+v, %d requests", out, srv.count())
	}
	// Ticked for the server, but the channel does not take urgent messages.
	off, err := New(freeMobile(srv.URL, false), smsDeps(t, nil, memSecrets{"fm-key": "k-secret-1"}, newStoreCounter(t), 3))
	if err != nil {
		t.Fatal(err)
	}
	out = SendLogAlert(context.Background(), []Notifier{off}, phpAlert(), true, logPage, alertNow)
	if out[0].Result != ResultSkipped || srv.count() != 0 {
		t.Fatalf("channel not urgent: %+v", out)
	}
	// Ticked: one SMS.
	out = SendLogAlert(context.Background(), []Notifier{n}, phpAlert(), true, logPage, alertNow)
	if out[0].Result != ResultOK || srv.count() != 1 {
		t.Fatalf("ticked: %+v, %d requests", out, srv.count())
	}
	if msg := srv.reqs[0].URL.Query().Get("msg"); !strings.Contains(msg, "PDOException") {
		t.Errorf("msg = %q", msg)
	}
}

func TestLogSMSRespectsDailyCap(t *testing.T) {
	srv := startSMS(t, http.StatusOK)
	n, err := New(freeMobile(srv.URL, true), smsDeps(t, nil, memSecrets{"fm-key": "k-secret-1"}, newStoreCounter(t), 2))
	if err != nil {
		t.Fatal(err)
	}
	var res []string
	for i := 0; i < 3; i++ {
		out := SendLogAlert(context.Background(), []Notifier{n}, phpAlert(), true, logPage, alertNow)
		res = append(res, out[0].Result)
	}
	if strings.Join(res, ",") != "ok,ok,skipped" || srv.count() != 2 {
		t.Errorf("results %v, %d requests", res, srv.count())
	}
}

func TestScopedChannelSkipped(t *testing.T) {
	hook := startHook(t, http.StatusOK, "")
	deps := smsDeps(t, nil, memSecrets{}, nil, 3)
	scoped, err := New(policy.ChannelConfig{Name: "client", Type: "webhook", URL: hook.URL + "/m", Format: "slack", Projects: []string{"demo"}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	open, err := New(policy.ChannelConfig{Name: "mine", Type: "webhook", URL: hook.URL + "/m", Format: "slack"}, deps)
	if err != nil {
		t.Fatal(err)
	}
	out := SendLogAlert(context.Background(), []Notifier{scoped, open}, phpAlert(), false, "", alertNow)
	if out[0].Result != ResultSkipped || out[1].Result != ResultOK {
		t.Fatalf("deliveries = %+v", out)
	}
}

func TestWebhookMarker(t *testing.T) {
	h := startHook(t, http.StatusNoContent, "")
	n, err := New(hookChannel(h.URL, "", ""), hookDeps(nil, memSecrets{}))
	if err != nil {
		t.Fatal(err)
	}
	out := SendLogAlert(context.Background(), []Notifier{n}, phpAlert(), false, "", alertNow)
	if len(out) != 1 || out[0].Result != ResultOK {
		t.Fatalf("%+v", out)
	}
	_, body := h.last()
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["michel_server_log_alert"] != float64(1) || doc["kind"] != string(serverlog.AlertNew) {
		t.Errorf("payload: %s", body)
	}
	for _, other := range []string{"michel_server_alert", "michel_fix_waiting"} {
		if _, ok := doc[other]; ok {
			t.Errorf("reuses the marker %s: %s", other, body)
		}
	}
}

func TestNotReadingMessageSaysWhy(t *testing.T) {
	in := serverlog.AlertInput{Target: logServer(), Kind: serverlog.AlertNotReading, Reason: serverlog.ReasonNoAgent,
		Items: []serverlog.AlertItem{{Kind: serverlog.AlertNotReading, Type: "srv-demo"}, {Kind: serverlog.AlertNotReading, Type: "srv-demo-2"}}}
	for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
		_, body := logMessage(lang, in, logPage)
		for _, w := range []string{"srv-demo", "srv-demo-2", logPage} {
			if !strings.Contains(body, w) {
				t.Errorf("%s: %q lacks %q", lang, body, w)
			}
		}
		for _, bad := range []string{"198.51.100.7", "deploy", "!"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s: %q holds %q", lang, body, bad)
			}
		}
	}
	_, body := logMessage(i18n.EN, in, "")
	if !strings.Contains(body, "ssh-agent) is locked") {
		t.Errorf("no cause: %q", body)
	}
	for _, r := range []string{serverlog.ReasonNoAgent, serverlog.ReasonNoKeyAccepted, serverlog.ReasonHostKeyUnknown, serverlog.ReasonHostKeyChanged,
		serverlog.ReasonDenied, serverlog.ReasonTimeout, serverlog.ReasonRefused, serverlog.ReasonOutputCut, serverlog.ReasonTools, serverlog.ReasonInactive, serverlog.ReasonBusy, serverlog.ReasonError, "something else"} {
		for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
			in.Reason = r
			if _, b := logMessage(lang, in, ""); strings.Contains(b, "!") {
				t.Errorf("%s/%s: %q", lang, r, b)
			}
		}
	}
}

// The cap skips the start of a big log and reads its end: the message says so.
func TestVolumeMessageSaysTheEndIsRead(t *testing.T) {
	in := serverlog.AlertInput{Target: logServer(), Kind: serverlog.AlertVolume, Items: []serverlog.AlertItem{{Kind: serverlog.AlertVolume, Count: 9 << 20}}}
	if _, body := logMessage(i18n.EN, in, ""); !strings.Contains(body, "read only the end") {
		t.Errorf("en: %q", body)
	}
	if _, body := logMessage(i18n.FR, in, ""); !strings.Contains(body, "que la fin") {
		t.Errorf("fr: %q", body)
	}
}

func TestVolumeAndCapMessagesHideTheSource(t *testing.T) {
	vol := serverlog.AlertInput{Target: logServer(), Kind: serverlog.AlertVolume,
		Items: []serverlog.AlertItem{{Kind: serverlog.AlertVolume, SourceID: "01SRCDEMO", Count: 9 << 20}}}
	capped := serverlog.AlertInput{Target: logServer(), Kind: serverlog.AlertCapReached}
	for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
		for _, in := range []serverlog.AlertInput{vol, capped} {
			_, body := logMessage(lang, in, "")
			if strings.Contains(body, "!") || strings.Contains(body, "01SRCDEMO") || !strings.Contains(body, "srv-demo") {
				t.Errorf("%s/%s: %q", lang, in.Kind, body)
			}
		}
	}
}

// One source failing is told as that source, by the path the sheet shows, with
// the others said to be read: not as the server.
func TestNotReadingNamesTheSourceAndSaysTheOthersWereRead(t *testing.T) {
	in := serverlog.AlertInput{Target: logServer(), Kind: serverlog.AlertNotReading, Reason: serverlog.ReasonDenied,
		Items:   []serverlog.AlertItem{{Kind: serverlog.AlertNotReading, Type: "srv-demo"}},
		Sources: []string{"/var/log/demo/other.log"}}
	_, en := logMessage(i18n.EN, in, "")
	want := "Michel can no longer read one error log of server srv-demo: /var/log/demo/other.log. The other logs of this server were read.\nCause: the server refused Michel access to the logs."
	if !strings.HasPrefix(en, want) {
		t.Errorf("en = %q, want it to start with %q", en, want)
	}
	_, fr := logMessage(i18n.FR, in, "")
	for _, w := range []string{"srv-demo", "/var/log/demo/other.log", "Les autres journaux de ce serveur ont bien été lus", "Cause : le serveur a refusé"} {
		if !strings.Contains(fr, w) {
			t.Errorf("fr %q lacks %q", fr, w)
		}
	}
	// Several, a path cleaned of control characters, never the line of a log.
	in.Sources = []string{"/var/log/a.log", "/var/log/b\x1b[31m.log"}
	for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
		_, body := logMessage(lang, in, "")
		for _, w := range []string{"/var/log/a.log", "/var/log/b[31m.log"} {
			if !strings.Contains(body, w) {
				t.Errorf("%s: %q lacks %q", lang, body, w)
			}
		}
		if strings.Contains(body, "\x1b") || strings.Contains(body, "!") {
			t.Errorf("%s: %q", lang, body)
		}
	}
	// Without a named source it is the server, as before.
	in.Sources = nil
	if _, body := logMessage(i18n.EN, in, ""); strings.Contains(body, "other logs") || !strings.Contains(body, "of this server: srv-demo.") {
		t.Errorf("server wording = %q", body)
	}
}

// A long list of sources is cut, and so is a long path.
func TestNotReadingSourcesAreBounded(t *testing.T) {
	in := serverlog.AlertInput{Target: logServer(), Kind: serverlog.AlertNotReading, Reason: serverlog.ReasonDenied,
		Items: []serverlog.AlertItem{{Kind: serverlog.AlertNotReading, Type: "srv-demo"}}}
	for i := 0; i < 8; i++ {
		in.Sources = append(in.Sources, "/var/log/demo/"+strings.Repeat("x", 300)+string(rune('a'+i))+".log")
	}
	_, body := logMessage(i18n.EN, in, "")
	if len(body) > 900 || strings.Contains(body, strings.Repeat("x", 150)) || strings.Contains(body, "g.log") {
		t.Errorf("not bounded (%d bytes): %q", len(body), body)
	}
}

// A refused connection has its own sentence, in both languages, and an unknown
// cause keeps the general one.
func TestNotReadingSaysARefusedConnection(t *testing.T) {
	in := serverlog.AlertInput{Target: logServer(), Kind: serverlog.AlertNotReading, Reason: serverlog.ReasonRefused,
		Items: []serverlog.AlertItem{{Kind: serverlog.AlertNotReading, Type: "srv-demo"}}}
	if _, body := logMessage(i18n.EN, in, ""); !strings.Contains(body, "Cause: the server refused the connection.") || strings.Contains(body, "the read failed") {
		t.Errorf("en: %q", body)
	}
	if _, body := logMessage(i18n.FR, in, ""); !strings.Contains(body, "Cause : le serveur a refusé la connexion.") {
		t.Errorf("fr: %q", body)
	}
	in.Reason = "something else"
	if _, body := logMessage(i18n.EN, in, ""); !strings.Contains(body, "Cause: the read failed.") {
		t.Errorf("unknown cause: %q", body)
	}
}
