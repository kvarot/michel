package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

var alertNow = time.Date(2026, 10, 23, 6, 0, 0, 0, time.UTC)

// smsServer records the requests it gets.
type smsServer struct {
	*httptest.Server
	mu     sync.Mutex
	status int
	reqs   []*http.Request
	bodies []string
}

func startSMS(t *testing.T, status int) *smsServer {
	t.Helper()
	s := &smsServer{status: status}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		s.mu.Lock()
		s.reqs, s.bodies = append(s.reqs, r), append(s.bodies, b.String())
		s.mu.Unlock()
		w.WriteHeader(s.status)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *smsServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

func smsDeps(t *testing.T, sink egress.Sink, secrets memSecrets, counter SMSCounter, perDay int) Deps {
	t.Helper()
	rules := []policy.AllowRule{{Host: "127.0.0.1", Purpose: policy.PurposeNotifySMS}, {Host: "127.0.0.1", Purpose: policy.PurposeWebhook}}
	return Deps{Gateway: gateway(sink, rules...), Secrets: secrets, Version: "1.2.3", Lang: i18n.EN,
		Now: func() time.Time { return alertNow }, SMSCounter: counter, SMSPerDay: perDay}
}

func freeMobile(u string, urgent bool) policy.ChannelConfig {
	return policy.ChannelConfig{Name: "sms", Type: "sms", Provider: "freemobile", User: "12345678", Secret: "fm-key", URL: u + "/sendmsg", Urgent: urgent}
}

func demoServer() target.Target {
	return target.Target{ID: "01SRVDEMO", Name: "srv-demo", Env: target.EnvProd}
}

func newStoreCounter(t *testing.T) StoreCounter {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return StoreCounter{S: st}
}

func TestSMSOnlyWhenUrgent(t *testing.T) {
	srv := startSMS(t, http.StatusOK)
	n, err := New(freeMobile(srv.URL, true), smsDeps(t, nil, memSecrets{"fm-key": "k-secret-1"}, newStoreCounter(t), 3))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	page := "http://127.0.0.1:7331/servers/01SRVDEMO"
	// A grave but not urgent finding: no SMS.
	out := SendServerAlert(ctx, []Notifier{n}, servercheck.AlertInput{Target: demoServer(), New: []scan.Finding{{OSVID: "X-1"}}, Kind: servercheck.AlertNew}, page, alertNow)
	if len(out) != 1 || out[0].Result != ResultSkipped || srv.count() != 0 {
		t.Fatalf("non urgent: %+v, %d requests", out, srv.count())
	}
	// Urgent: one SMS.
	out = SendServerAlert(ctx, []Notifier{n}, servercheck.AlertInput{Target: demoServer(), New: []scan.Finding{{OSVID: "X-1"}}, Urgent: true, Kind: servercheck.AlertNew}, page, alertNow)
	if len(out) != 1 || out[0].Result != ResultOK || srv.count() != 1 {
		t.Fatalf("urgent: %+v, %d requests", out, srv.count())
	}
	r := srv.reqs[0]
	if r.Method != http.MethodGet || r.URL.Path != "/sendmsg" || r.URL.Query().Get("user") != "12345678" || r.URL.Query().Get("pass") != "k-secret-1" {
		t.Errorf("request = %s %s", r.Method, r.URL.Path)
	}
	if msg := r.URL.Query().Get("msg"); !strings.Contains(msg, "Server srv-demo: 1 serious flaw") || !strings.Contains(msg, page) {
		t.Errorf("msg = %q", msg)
	}
	// A rollback that failed is urgent whatever the flag.
	out = SendServerAlert(ctx, []Notifier{n}, servercheck.AlertInput{Target: demoServer(), Kind: servercheck.AlertRollbackFailed}, page, alertNow)
	if out[0].Result != ResultOK || srv.count() != 2 {
		t.Fatalf("rollback_failed: %+v, %d requests", out, srv.count())
	}
	// A rollback that worked is not.
	out = SendServerAlert(ctx, []Notifier{n}, servercheck.AlertInput{Target: demoServer(), Kind: servercheck.AlertRolledBack}, page, alertNow)
	if out[0].Result != ResultSkipped || srv.count() != 2 {
		t.Fatalf("rolled_back: %+v", out)
	}
	// A channel without urgent: true never sends.
	off, err := New(freeMobile(srv.URL, false), smsDeps(t, nil, memSecrets{"fm-key": "k-secret-1"}, newStoreCounter(t), 3))
	if err != nil {
		t.Fatal(err)
	}
	out = SendServerAlert(ctx, []Notifier{off}, servercheck.AlertInput{Target: demoServer(), Urgent: true, Kind: servercheck.AlertNew}, page, alertNow)
	if out[0].Result != ResultSkipped || srv.count() != 2 {
		t.Fatalf("channel not urgent: %+v", out)
	}
	// The digest never goes by SMS.
	dl := Deliver(ctx, []Notifier{n}, sample())
	if dl[0].Result != ResultSkipped || srv.count() != 2 {
		t.Fatalf("digest: %+v", dl)
	}
}

func TestSMSDailyCap(t *testing.T) {
	srv := startSMS(t, http.StatusOK)
	counter := newStoreCounter(t)
	n, err := New(freeMobile(srv.URL, true), smsDeps(t, nil, memSecrets{"fm-key": "k"}, counter, 2))
	if err != nil {
		t.Fatal(err)
	}
	in := servercheck.AlertInput{Target: demoServer(), Urgent: true, Kind: servercheck.AlertNew}
	var results []string
	for i := 0; i < 3; i++ {
		out := SendServerAlert(context.Background(), []Notifier{n}, in, "", alertNow.Add(time.Duration(i)*time.Minute))
		results = append(results, out[0].Result)
	}
	if strings.Join(results, " ") != "ok ok skipped" || srv.count() != 2 {
		t.Fatalf("results = %v, %d requests", results, srv.count())
	}
	// The next day the count starts again.
	out := SendServerAlert(context.Background(), []Notifier{n}, in, "", alertNow.Add(24*time.Hour))
	if out[0].Result != ResultOK || srv.count() != 3 {
		t.Fatalf("next day: %+v", out)
	}
	// A failed send gives its place back.
	bad := startSMS(t, http.StatusInternalServerError)
	nb, _ := New(freeMobile(bad.URL, true), smsDeps(t, nil, memSecrets{"fm-key": "k"}, counter, 2))
	later := alertNow.Add(48 * time.Hour)
	for i := 0; i < 3; i++ {
		out = SendServerAlert(context.Background(), []Notifier{nb}, in, "", later)
		if out[0].Result != ResultError {
			t.Fatalf("attempt %d: %+v", i, out)
		}
	}
	// Without a counter nothing goes out.
	nc, _ := New(freeMobile(srv.URL, true), smsDeps(t, nil, memSecrets{"fm-key": "k"}, nil, 2))
	out = SendServerAlert(context.Background(), []Notifier{nc}, in, "", alertNow)
	if out[0].Result != ResultError || srv.count() != 3 {
		t.Fatalf("no counter: %+v", out)
	}
}

type memSink struct {
	mu   sync.Mutex
	list []egress.Attempt
}

func (m *memSink) Record(a egress.Attempt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.list = append(m.list, a)
	return nil
}

func TestFreeMobileSecretNeverInErrorOrAudit(t *testing.T) {
	const pass, user = "PASS-TOP-SECRET", "87654321"
	srv := startSMS(t, http.StatusInternalServerError)
	sink := &memSink{}
	cfg := freeMobile(srv.URL, true)
	cfg.User = user
	deps := smsDeps(t, sink, memSecrets{"fm-key": pass}, newStoreCounter(t), 3)
	n, err := New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	in := servercheck.AlertInput{Target: demoServer(), Urgent: true, Kind: servercheck.AlertNew}
	check := func(label string, out []Delivery) {
		t.Helper()
		if out[0].Result != ResultError {
			t.Fatalf("%s: %+v", label, out)
		}
		all := out[0].Error + " " + out[0].Err.Error()
		if strings.Contains(all, pass) || strings.Contains(all, user) || strings.Contains(all, "pass=") {
			t.Errorf("%s: the error holds the credentials: %s", label, all)
		}
	}
	check("http 500", SendServerAlert(context.Background(), []Notifier{n}, in, "", alertNow))
	// A test message goes the same way.
	if d := TestOne(context.Background(), n); d.Result != ResultError || strings.Contains(d.Error, pass) || strings.Contains(d.Error, user) {
		t.Errorf("test: %+v", d)
	}
	// A refused connection: the transport error holds the URL, which must go.
	srv.Close()
	check("closed", SendServerAlert(context.Background(), []Notifier{n}, in, "", alertNow))
	// A denied connection (no rule).
	denied, _ := New(cfg, Deps{Gateway: gateway(sink), Secrets: memSecrets{"fm-key": pass}, SMSCounter: newStoreCounter(t), SMSPerDay: 3, Lang: i18n.EN})
	check("denied", SendServerAlert(context.Background(), []Notifier{denied}, in, "", alertNow))
	for _, a := range sink.list {
		if strings.Contains(a.Host+a.Purpose+a.Reason, pass) || strings.Contains(a.Host+a.Purpose+a.Reason, user) {
			t.Errorf("the audit holds the credentials: %+v", a)
		}
		if a.Purpose != policy.PurposeNotifySMS {
			t.Errorf("purpose = %q", a.Purpose)
		}
	}
	if len(sink.list) == 0 {
		t.Error("the gateway recorded nothing")
	}
	// A missing secret names the secret, never a value.
	miss, _ := New(cfg, smsDeps(t, nil, memSecrets{}, newStoreCounter(t), 3))
	out := SendServerAlert(context.Background(), []Notifier{miss}, in, "", alertNow)
	if out[0].Result != ResultError || !strings.Contains(out[0].Error, "fm-key") {
		t.Errorf("missing secret: %+v", out)
	}
}

func TestGenericSMSIsSigned(t *testing.T) {
	srv := startSMS(t, http.StatusOK)
	cfg := policy.ChannelConfig{Name: "sms", Type: "sms", Provider: "generic", URL: srv.URL + "/send", Secret: "sms-hmac", Urgent: true}
	n, err := New(cfg, smsDeps(t, nil, memSecrets{"sms-hmac": "k3y"}, newStoreCounter(t), 3))
	if err != nil {
		t.Fatal(err)
	}
	out := SendServerAlert(context.Background(), []Notifier{n}, servercheck.AlertInput{Target: demoServer(), Urgent: true, Kind: servercheck.AlertNew}, "", alertNow)
	if out[0].Result != ResultOK || srv.count() != 1 {
		t.Fatalf("%+v", out)
	}
	r, body := srv.reqs[0], srv.bodies[0]
	var doc map[string]string
	if err := json.Unmarshal([]byte(body), &doc); err != nil || len(doc) != 1 || doc["text"] != "Server srv-demo: 1 serious flaw" {
		t.Errorf("body = %s (%v)", body, err)
	}
	mac := hmac.New(sha256.New, []byte("k3y"))
	mac.Write([]byte(r.Header.Get("X-Michel-Timestamp") + "." + body))
	if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); r.Header.Get("X-Michel-Signature") != want {
		t.Errorf("signature = %q", r.Header.Get("X-Michel-Signature"))
	}
}

func TestServerAlertHasNoDetail(t *testing.T) {
	hook := startHook(t, http.StatusOK, "")
	wh, err := New(policy.ChannelConfig{Name: "hook", Type: "webhook", URL: hook.URL + "/m", Format: "slack"}, smsDeps(t, nil, memSecrets{}, nil, 3))
	if err != nil {
		t.Fatal(err)
	}
	f := scan.Finding{ID: "f1", Package: "php", Ecosystem: "os", OSVID: "CVE-2026-0001", InstalledVersion: "8.1.2-1ubuntu2.14",
		Location: "/etc/php/8.1/fpm/php.ini:12", Summary: "allow_url_include is on", KEV: true}
	in := servercheck.AlertInput{Target: demoServer(), New: []scan.Finding{f, f}, Urgent: true, Kind: servercheck.AlertNew}
	page := "http://127.0.0.1:7331/servers/01SRVDEMO"
	out := SendServerAlert(context.Background(), []Notifier{wh}, in, page, alertNow)
	if out[0].Result != ResultOK {
		t.Fatalf("%+v", out)
	}
	_, body := hook.last()
	var doc map[string]string
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	want := "Michel · server alert\nServer srv-demo: 2 serious flaws\n" + page
	if doc["text"] != want {
		t.Errorf("text = %q, want %q", doc["text"], want)
	}
	for _, bad := range []string{"8.1", "ubuntu", "php", "allow_url", "CVE", "/etc"} {
		if strings.Contains(doc["text"], bad) {
			t.Errorf("the alert holds %q: %q", bad, doc["text"])
		}
	}
	// The French text.
	title, text := serverMessage(i18n.FR, servercheck.AlertInput{Target: demoServer(), New: []scan.Finding{f}, Kind: servercheck.AlertNew}, "")
	if title != "Michel · alerte serveur" || text != "Serveur srv-demo : 1 faille grave" {
		t.Errorf("fr = %q %q", title, text)
	}
	for _, k := range []string{servercheck.AlertRollbackFailed, servercheck.AlertRolledBack, servercheck.AlertAppliedAuto, servercheck.AlertUndoNow} {
		for _, l := range []i18n.Lang{i18n.EN, i18n.FR} {
			_, tx := serverMessage(l, servercheck.AlertInput{Target: demoServer(), Kind: k}, "")
			if strings.HasPrefix(tx, "!") || !strings.Contains(tx, "srv-demo") {
				t.Errorf("%s/%s = %q", k, l, tx)
			}
		}
	}
}

func TestSMSChannelValidation(t *testing.T) {
	rules := []policy.AllowRule{{Host: "smsapi.free-mobile.fr", Purpose: policy.PurposeNotifySMS}, {Host: "sms.example.test", Purpose: policy.PurposeNotifySMS}}
	good := policy.ChannelConfig{Name: "sms", Type: "sms", Provider: "freemobile", User: "12345678", Secret: "fm-key", Urgent: true}
	generic := policy.ChannelConfig{Name: "sms2", Type: "sms", Provider: "generic", URL: "https://sms.example.test/send", Secret: "sms-hmac"}
	cases := []struct {
		name  string
		ch    []policy.ChannelConfig
		rules []policy.AllowRule
		want  string
	}{
		{"freemobile ok", []policy.ChannelConfig{good}, rules, ""},
		{"generic ok", []policy.ChannelConfig{generic}, rules, ""},
		{"no provider", []policy.ChannelConfig{{Name: "s", Type: "sms", User: "1", Secret: "k"}}, rules, "provider"},
		{"unknown provider", []policy.ChannelConfig{{Name: "s", Type: "sms", Provider: "x"}}, rules, "provider"},
		{"no user", []policy.ChannelConfig{{Name: "s", Type: "sms", Provider: "freemobile", Secret: "k"}}, rules, "user"},
		{"no secret", []policy.ChannelConfig{{Name: "s", Type: "sms", Provider: "freemobile", User: "1"}}, rules, "secret"},
		{"generic no url", []policy.ChannelConfig{{Name: "s", Type: "sms", Provider: "generic", Secret: "k"}}, rules, "url"},
		{"generic http", []policy.ChannelConfig{{Name: "s", Type: "sms", Provider: "generic", URL: "http://sms.example.test/x", Secret: "k"}}, rules, "https"},
		{"no network rule", []policy.ChannelConfig{good}, nil, "network.allow"},
		{"reserved secret", []policy.ChannelConfig{{Name: "s", Type: "sms", Provider: "freemobile", User: "1", Secret: "api-token"}}, rules, "reserved"},
	}
	for _, tc := range cases {
		err := policy.ValidateNotify(policy.NotifyConfig{Channels: tc.ch}, tc.rules)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	if err := policy.ValidateNotify(policy.NotifyConfig{SMSPerDay: -1}, nil); err == nil {
		t.Error("a negative sms_per_day is accepted")
	}
	if (policy.NotifyConfig{}).EffectiveSMSPerDay() != 3 || (policy.NotifyConfig{SMSPerDay: 5}).EffectiveSMSPerDay() != 5 {
		t.Error("sms_per_day default")
	}
	// Build gives the policy's cap to the channels.
	ns, err := Build(policy.NotifyConfig{SMSPerDay: 7, Channels: []policy.ChannelConfig{good}}, Deps{})
	if err != nil || ns[0].(*sms).deps.SMSPerDay != 7 {
		t.Errorf("build: %v", err)
	}
}

func TestServerAlertSkipsScopedChannels(t *testing.T) {
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
	in := servercheck.AlertInput{Target: demoServer(), Urgent: true, Kind: servercheck.AlertNew}
	out := SendServerAlert(context.Background(), []Notifier{scoped, open}, in, "", alertNow)
	if out[0].Result != ResultSkipped || out[1].Result != ResultOK {
		t.Fatalf("deliveries = %+v", out)
	}
}

func TestSMSBodyIsShort(t *testing.T) {
	srv := startSMS(t, http.StatusOK)
	n, _ := New(freeMobile(srv.URL, true), smsDeps(t, nil, memSecrets{"fm-key": "k"}, newStoreCounter(t), 3))
	long := demoServer()
	long.Name = strings.Repeat("a-very-long-server-name-", 20)
	out := SendServerAlert(context.Background(), []Notifier{n}, servercheck.AlertInput{Target: long, Kind: servercheck.AlertRollbackFailed}, "http://127.0.0.1:7331/#/servers/01SRVDEMO", alertNow)
	if out[0].Result != ResultOK {
		t.Fatalf("%+v", out)
	}
	msg := srv.reqs[0].URL.Query().Get("msg")
	if len([]rune(msg)) > 160 {
		t.Errorf("sms is %d characters: %q", len([]rune(msg)), msg)
	}
	if !strings.Contains(msg, "…") || !strings.Contains(msg, "#/servers/01SRVDEMO") {
		t.Errorf("msg = %q", msg)
	}
}

func TestSMSCounterConcurrentTake(t *testing.T) {
	c := newStoreCounter(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := c.Take(context.Background(), alertNow, 1)
			if err != nil {
				t.Error(err)
			}
			if ok {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 1 {
		t.Fatalf("%d goroutines won a cap of 1", won)
	}
}
