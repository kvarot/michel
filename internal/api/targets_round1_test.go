package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/target"
)

func (tf *targetFixture) policyText() string {
	tf.t.Helper()
	b, err := os.ReadFile(tf.policyPath)
	if err != nil {
		tf.t.Fatal(err)
	}
	return string(b)
}

func TestDeleteAndPatchReleaseTheNetworkRules(t *testing.T) {
	tf := newTargetFixture(t)
	post := func(name, host, site string) TargetView {
		extra := ""
		if site != "" {
			extra = `,"site_url":"` + site + `"`
		}
		code, body := tf.send("POST", "/api/v1/targets", `{"name":"`+name+`","host":"`+host+`","user":"deploy"`+extra+`}`)
		if code != http.StatusCreated {
			t.Fatalf("add %s = %d %s", name, code, body)
		}
		var v TargetView
		_ = json.Unmarshal([]byte(body), &v)
		return v
	}
	a := post("one", "192.0.2.90", "https://www.example.test/")
	b := post("two", "192.0.2.90", "")
	allowed := func(host, purpose string) bool { ok, _ := tf.gw.Allowed(host, purpose); return ok }
	if !allowed("192.0.2.90", policy.PurposeTargetSSH) || !allowed("www.example.test", policy.PurposeTargetHTTP) {
		t.Fatal("the rules were not written")
	}
	// Deleting the first keeps the ssh rule the second still needs, and drops its own site rule.
	if code, body := tf.send("DELETE", "/api/v1/targets/"+a.ID, ""); code != http.StatusOK {
		t.Fatalf("delete one = %d %s", code, body)
	}
	if !allowed("192.0.2.90", policy.PurposeTargetSSH) || !strings.Contains(tf.policyText(), "192.0.2.90") {
		t.Error("the rule another server uses was removed")
	}
	if allowed("www.example.test", policy.PurposeTargetHTTP) || strings.Contains(tf.policyText(), "www.example.test") {
		t.Error("the site rule of the deleted server stayed")
	}
	if rows := tf.auditRows("target.remove"); len(rows) != 1 || rows[0].evidence["rules_removed"] != float64(1) {
		t.Errorf("audit = %+v", rows)
	}
	// A new host and site on the second: the old host goes, the new ones come.
	if code, body := tf.send("PATCH", "/api/v1/targets/"+b.ID, `{"host":"192.0.2.91","site_url":"https://new.example.test/"}`); code != http.StatusOK {
		t.Fatalf("patch = %d %s", code, body)
	}
	if allowed("192.0.2.90", policy.PurposeTargetSSH) || !allowed("192.0.2.91", policy.PurposeTargetSSH) || !allowed("new.example.test", policy.PurposeTargetHTTP) {
		t.Errorf("rules after patch:\n%s", tf.policyText())
	}
	// Deleting the last one takes its rules back: the gateway refuses the host again.
	if code, _ := tf.send("DELETE", "/api/v1/targets/"+b.ID, ""); code != http.StatusOK {
		t.Fatal("delete two")
	}
	if allowed("192.0.2.91", policy.PurposeTargetSSH) || allowed("new.example.test", policy.PurposeTargetHTTP) || strings.Contains(tf.policyText(), "192.0.2.91") {
		t.Errorf("rules left:\n%s", tf.policyText())
	}
}

func TestPatchWithABadHostChangesNothing(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.add("")
	tf.pin(v.ID)
	before := tf.policyText()
	for _, body := range []string{`{"host":"*.example.test"}`, `{"host":"a b"}`, `{"host":"user@example.test"}`, `{"site_url":"https://*.example.test/"}`} {
		code, out := tf.send("PATCH", "/api/v1/targets/"+v.ID, body)
		if code != http.StatusBadRequest {
			t.Errorf("%s = %d %s", body, code, out)
		}
	}
	got := tf.view(v.ID)
	if got.Host != v.Host || !got.HostKeyPinned || tf.policyText() != before {
		t.Errorf("something changed: %+v\n%s", got, tf.policyText())
	}
	// A refused update (a level out of range) after a changed host leaves no rule behind.
	code, out := tf.send("PATCH", "/api/v1/targets/"+v.ID, `{"host":"192.0.2.99","fix_level":9}`)
	if code != http.StatusBadRequest {
		t.Fatalf("patch = %d %s", code, out)
	}
	if strings.Contains(tf.policyText(), "192.0.2.99") || tf.view(v.ID).Host != v.Host {
		t.Errorf("a refused patch left a rule:\n%s", tf.policyText())
	}
	// Hosts and project folders of a new server are checked too.
	for _, b := range []string{`{"name":"w","host":"*.example.test","user":"d"}`, `{"name":"w","host":"a@b","user":"d"}`,
		`{"name":"w","host":"192.0.2.5","user":"d","site_url":"https://*.x.test/"}`, `{"name":"w","host":"::1","user":"d"}`} {
		if code, out := tf.send("POST", "/api/v1/targets", b); code != http.StatusBadRequest {
			t.Errorf("%s = %d %s", b, code, out)
		}
	}
	for _, dir := range []string{"/", "/home", "/root", "/home/deploy", "/a/../b"} {
		b := `{"name":"w","host":"192.0.2.5","user":"d","links":[{"project":"demo","remote_dir":"` + dir + `"}]}`
		code, out := tf.send("POST", "/api/v1/targets", b)
		if code != http.StatusBadRequest || !strings.Contains(out, "bad_remote_dir") {
			t.Errorf("dir %q = %d %s", dir, code, out)
		}
	}
	if list, _ := target.NewRepo(tf.st).List(context.Background()); len(list) != 1 {
		t.Errorf("servers = %d", len(list))
	}
}

func TestDeleteWaitsForChecksAndFixes(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.add("")
	// A check of the scheduler (or the CLI) holds the lock: the page's delete waits.
	unlock, ok := servercheck.TryLock(v.ID)
	if !ok {
		t.Fatal("lock")
	}
	if code, body := tf.send("DELETE", "/api/v1/targets/"+v.ID, ""); code != http.StatusConflict || !strings.Contains(body, "api.target.busy") {
		t.Errorf("during a check = %d %s", code, body)
	}
	unlock()
	tf.seedServerFinding(v.ID, "fsrv000000000030", scan.KindServerConfig, "allow_url_include")
	for _, st := range []fix.State{fix.StateRunning, fix.StateUnknown, fix.StateApproved, fix.StatePreparing} {
		a, _ := tf.seedServerAttempt(v, "fsrv000000000030", target.ExecMichel, false)
		if _, err := tf.st.DB().Exec(`UPDATE fix_attempt SET state = ? WHERE id = ?`, string(st), a.ID); err != nil {
			t.Fatal(err)
		}
		if code, body := tf.send("DELETE", "/api/v1/targets/"+v.ID, ""); code != http.StatusConflict || !strings.Contains(body, "api.target.busy") {
			t.Errorf("with a %s fix = %d %s", st, code, body)
		}
		if _, err := tf.st.DB().Exec(`UPDATE fix_attempt SET state = 'refused' WHERE id = ?`, a.ID); err != nil {
			t.Fatal(err)
		}
	}
	if code, body := tf.send("DELETE", "/api/v1/targets/"+v.ID, ""); code != http.StatusOK {
		t.Errorf("free = %d %s", code, body)
	}
}

func TestReplacingAPinnedFingerprintNeedsReplace(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.add("")
	if err := target.NewRepo(tf.st).SetHostKey(context.Background(), v.ID, "SHA256:previous"); err != nil {
		t.Fatal(err)
	}
	fp := tf.ssh.HostKeyFingerprint()
	code, body := tf.send("POST", "/api/v1/targets/"+v.ID+"/hostkey", `{"fingerprint":"`+fp+`"}`)
	var eb FixErrorBody
	_ = json.Unmarshal([]byte(body), &eb)
	if code != http.StatusConflict || eb.Code != "api.target.hostkey_changed" || eb.Hint == "" {
		t.Fatalf("without replace = %d %s", code, body)
	}
	if got := tf.view(v.ID); got.HostKey != "SHA256:previous" {
		t.Errorf("pin = %q", got.HostKey)
	}
	if code, body := tf.send("POST", "/api/v1/targets/"+v.ID+"/hostkey", `{"fingerprint":"`+fp+`","replace":true}`); code != http.StatusOK {
		t.Fatalf("with replace = %d %s", code, body)
	}
	if got := tf.view(v.ID); got.HostKey != fp {
		t.Errorf("pin = %q", got.HostKey)
	}
	rows := tf.auditRows("target.hostkey")
	if len(rows) != 2 || rows[1].evidence["replaced"] != true {
		t.Errorf("audit = %+v", rows)
	}
}

func TestServerApplyFailureIsAnsweredInClear(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.add("")
	tf.seedServerFinding(v.ID, "fsrv000000000040", scan.KindServerConfig, "allow_url_include")
	a, _ := tf.seedServerAttempt(v, "fsrv000000000040", target.ExecMichel, false)
	got, err := fix.NewRepo(tf.st).GetAttempt(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	sock := tf.dir + "/agent.sock"
	for name, cause := range map[string]error{
		"no agent": fmt.Errorf("cannot connect to server srv-demo: %w (dial unix %s: refused)", sshx.ErrNoAgent, sock),
		"no key":   fmt.Errorf("%w: deploy@192.0.2.1", sshx.ErrNoKeyAccepted),
		"other":    errors.New("dial tcp 192.0.2.1:22: i/o timeout for deploy"),
	} {
		for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/", nil)
			tf.h.s.applyFailed(w, r, lang, got, cause)
			body := w.Body.String()
			var eb FixErrorBody
			_ = json.Unmarshal([]byte(body), &eb)
			if eb.Detail != "" || eb.Code == "api.fix.apply_failed" || strings.HasPrefix(eb.Error, "!") ||
				strings.Contains(body, sock) || strings.Contains(body, "deploy") || strings.Contains(body, "192.0.2.1") {
				t.Errorf("%s (%s) = %d %s", name, lang, w.Code, body)
			}
		}
	}
	// A code fix keeps its generic answer.
	w := httptest.NewRecorder()
	tf.h.s.applyFailed(w, httptest.NewRequest("POST", "/", nil), i18n.EN, fix.Attempt{}, errors.New("branch failed"))
	if !strings.Contains(w.Body.String(), "api.fix.apply_failed") {
		t.Errorf("code fix = %s", w.Body.String())
	}
}
