package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

func (tf *targetFixture) setState(attemptID string, st fix.State) {
	tf.t.Helper()
	if _, err := tf.st.DB().Exec(`UPDATE fix_attempt SET state = ? WHERE id = ?`, string(st), attemptID); err != nil {
		tf.t.Fatal(err)
	}
}

func busyCode(body string) string {
	var eb FixErrorBody
	_ = json.Unmarshal([]byte(body), &eb)
	return eb.Code
}

func TestDeleteAnswersADistinctKeyPerPendingFix(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.add("")
	tf.seedServerFinding(v.ID, "fsrv000000000050", scan.KindServerConfig, "allow_url_include")
	cases := []struct {
		name     string
		state    fix.State
		executor target.Executor
		code     string
	}{
		{"preparing", fix.StatePreparing, target.ExecUser, "api.target.busy"},
		{"running", fix.StateRunning, target.ExecMichel, "api.target.busy"},
		{"approved, run by michel", fix.StateApproved, target.ExecMichel, "api.target.busy"},
		{"unknown", fix.StateUnknown, target.ExecMichel, "api.target.busy_unknown"},
		{"approved, run by the user", fix.StateApproved, target.ExecUser, "api.target.busy_approved"},
	}
	for _, c := range cases {
		a, _ := tf.seedServerAttempt(v, "fsrv000000000050", c.executor, false)
		tf.setState(a.ID, c.state)
		for _, lang := range []string{"en", "fr"} {
			code, body := tf.send("DELETE", "/api/v1/targets/"+v.ID+"?lang="+lang, "")
			var eb FixErrorBody
			_ = json.Unmarshal([]byte(body), &eb)
			if code != http.StatusConflict || eb.Code != c.code || eb.Error == "" || eb.Hint == "" || strings.HasPrefix(eb.Error, "!") {
				t.Errorf("%s (%s) = %d %s", c.name, lang, code, body)
			}
		}
		if c.state == fix.StateUnknown && !strings.Contains(tf.sendBody("DELETE", "/api/v1/targets/"+v.ID+"?lang=fr"), "érifie le serveur") {
			t.Error("the unknown refusal does not name the way out in French")
		}
		if c.state == fix.StateApproved && c.executor == target.ExecUser && !strings.Contains(tf.sendBody("DELETE", "/api/v1/targets/"+v.ID), "refuse") {
			t.Error("the approved refusal does not name Refuse")
		}
		tf.setState(a.ID, fix.StateRefused)
	}
	if code, body := tf.send("DELETE", "/api/v1/targets/"+v.ID, ""); code != http.StatusOK {
		t.Errorf("free = %d %s", code, body)
	}
}

func (tf *targetFixture) sendBody(method, path string) string {
	_, b := tf.send(method, path, "")
	return b
}

func TestResolveUnknownIsTheWayOut(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.add("")
	tf.seedServerFinding(v.ID, "fsrv000000000051", scan.KindServerConfig, "allow_url_include")
	a, _ := tf.seedServerAttempt(v, "fsrv000000000051", target.ExecMichel, false)
	// Only a fix of unknown outcome can be marked checked.
	code, body := tf.send("POST", "/api/v1/fix/"+a.ID+"/resolve", "")
	if code != http.StatusConflict || busyCode(body) != "fix.err.bad_state" {
		t.Fatalf("resolve a proposed fix = %d %s", code, body)
	}
	tf.setState(a.ID, fix.StateUnknown)
	code, body = tf.send("POST", "/api/v1/fix/"+a.ID+"/resolve?lang=fr", "")
	if code != http.StatusOK {
		t.Fatalf("resolve = %d %s", code, body)
	}
	var v2 AttemptView
	_ = json.Unmarshal([]byte(body), &v2)
	if v2.State != "failed" || !strings.Contains(v2.Cause, "toi-même") {
		t.Errorf("after resolve = %s / %q", v2.State, v2.Cause)
	}
	got, _ := fix.NewRepo(tf.st).GetAttempt(context.Background(), a.ID)
	if got.Cause != fix.CauseUserChecked {
		t.Errorf("stored cause = %q", got.Cause)
	}
	if rows := tf.auditRows("server_fix.resolved"); len(rows) != 1 || rows[0].evidence["author"] != "web" {
		t.Errorf("audit = %+v", rows)
	}
	if code, body := tf.send("POST", "/api/v1/fix/"+a.ID+"/resolve", ""); code != http.StatusConflict {
		t.Errorf("second resolve = %d %s", code, body)
	}
	if code, body := tf.send("POST", "/api/v1/fix/nope/resolve", ""); code != http.StatusNotFound {
		t.Errorf("unknown attempt = %d %s", code, body)
	}
	if resp, _ := tf.do("POST", "/api/v1/fix/"+a.ID+"/resolve", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("without token = %d", resp.StatusCode)
	}
	// With the fix resolved, the server can leave.
	if code, body := tf.send("DELETE", "/api/v1/targets/"+v.ID, ""); code != http.StatusOK {
		t.Errorf("delete after resolve = %d %s", code, body)
	}
}

func TestRuleRemovalFailureIsReportedAndAudited(t *testing.T) {
	failReload := false
	tf := newTargetFixture(t, func(tf *targetFixture) {
		orig := tf.fixture.deps.Reload
		tf.fixture.deps.Reload = func() (policy.Policy, error) {
			if failReload {
				return policy.Policy{}, errors.New("policy cannot be reloaded")
			}
			return orig()
		}
	})
	v := tf.add("")
	failReload = true
	code, body := tf.send("DELETE", "/api/v1/targets/"+v.ID, "")
	if code != http.StatusOK || !strings.Contains(body, `"rules_not_removed":true`) {
		t.Fatalf("delete = %d %s", code, body)
	}
	if _, err := target.NewRepo(tf.st).Get(context.Background(), v.ID); err == nil {
		t.Error("the server is still there")
	}
	if rows := tf.auditRows("target.remove"); len(rows) != 1 || rows[0].evidence["rules_error"] != true {
		t.Errorf("audit = %+v", rows)
	}
}

func TestHandWrittenRulesAreNeverReleased(t *testing.T) {
	tf := newTargetFixture(t)
	hand := policy.AllowRule{Host: "192.0.2.95", Purpose: policy.PurposeTargetSSH}
	if _, err := policy.AddAllowRules(tf.policyPath, hand); err != nil {
		t.Fatal(err)
	}
	p, err := tf.deps.Reload()
	if err != nil {
		t.Fatal(err)
	}
	tf.gw.SetRules(p.Sovereignty.Network.Allow)
	// The first server shares the hand-written rule, the second brings its own site rule.
	code, body := tf.send("POST", "/api/v1/targets", `{"name":"hand","host":"192.0.2.95","user":"d","site_url":"https://www.example.test/"}`)
	if code != http.StatusCreated {
		t.Fatalf("add = %d %s", code, body)
	}
	var v TargetView
	_ = json.Unmarshal([]byte(body), &v)
	if code, _ := tf.send("DELETE", "/api/v1/targets/"+v.ID, ""); code != http.StatusOK {
		t.Fatal("delete")
	}
	text := func() string { b, _ := os.ReadFile(tf.policyPath); return string(b) }
	if !strings.Contains(text(), "192.0.2.95") {
		t.Errorf("the hand-written rule was removed:\n%s", text())
	}
	if strings.Contains(text(), "www.example.test") {
		t.Errorf("the rule Michel wrote stayed:\n%s", text())
	}
}

func TestHostCaseNeverDropsASharedRule(t *testing.T) {
	tf := newTargetFixture(t)
	a := tf.addHost("up", "Example.TEST")
	tf.addHost("low", "example.test")
	if a.Host != "example.test" {
		t.Errorf("host stored as %q", a.Host)
	}
	if code, _ := tf.send("DELETE", "/api/v1/targets/"+a.ID, ""); code != http.StatusOK {
		t.Fatal("delete")
	}
	if ok, _ := tf.gw.Allowed("example.test", policy.PurposeTargetSSH); !ok {
		t.Error("the rule of the server that stays was removed")
	}
}

func (tf *targetFixture) addHost(name, host string) TargetView {
	tf.t.Helper()
	code, body := tf.send("POST", "/api/v1/targets", `{"name":"`+name+`","host":"`+host+`","user":"d"}`)
	if code != http.StatusCreated {
		tf.t.Fatalf("add %s = %d %s", name, code, body)
	}
	var v TargetView
	_ = json.Unmarshal([]byte(body), &v)
	return v
}

func TestAnIPv6LiteralIsToldToUseItsHostName(t *testing.T) {
	tf := newTargetFixture(t)
	for _, lang := range []string{"en", "fr"} {
		code, body := tf.send("POST", "/api/v1/targets?lang="+lang, `{"name":"v6","host":"::1","user":"d"}`)
		var eb FixErrorBody
		_ = json.Unmarshal([]byte(body), &eb)
		want := map[string]string{"en": "host name", "fr": "nom d'hôte"}[lang]
		if code != http.StatusBadRequest || eb.Code != "api.target.bad_host" || !strings.Contains(eb.Hint, want) {
			t.Errorf("%s = %d %s", lang, code, body)
		}
	}
}
