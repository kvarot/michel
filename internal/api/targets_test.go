package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/kvarot/michel/internal/collect"
	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/target"
)

// targetFixture is the API fixture with the server routes: a simulated SSH
// server on loopback, its agent, a fake HOME for discovery and the fix
// service wired to the registry.
type targetFixture struct {
	*fixture
	ssh  *sshtest.Server
	home string
	// agentErr, when set, is what the SSH agent answers (a socket path of
	// this computer inside it, as a real one would put).
	agentErr error
	// shell, when set, runs the `sh -s` scripts sent to the simulated server
	// (the log filter); nil leaves `sh -s` unsupported.
	shell sshtest.ShellFunc
}

const osReleaseDemo = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nVERSION_ID=\"12\"\nID=debian\n"

func demoCommands() map[string]sshtest.Handler {
	out := map[string]sshtest.Handler{
		"cat": func(e sshtest.Exec) int {
			if len(e.Args) == 2 && e.Args[1] == "/etc/os-release" {
				io.WriteString(e.Stdout, osReleaseDemo)
				return 0
			}
			return 1
		},
		"uname":   func(e sshtest.Exec) int { io.WriteString(e.Stdout, "6.1.0-21-amd64\n"); return 0 },
		"command": func(e sshtest.Exec) int { return 1 },
		"dpkg-query": func(e sshtest.Exec) int {
			io.WriteString(e.Stdout, "openssl\topenssl\t3.0.11-1~deb12u1\tamd64\n")
			return 0
		},
		"ss": func(e sshtest.Exec) int {
			io.WriteString(e.Stdout, "State Recv-Q Send-Q Local Address:Port Peer Address:Port\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 200 127.0.0.1:5432 0.0.0.0:*\n")
			return 0
		},
	}
	// The collection runs its commands through env.
	out["env"] = func(e sshtest.Exec) int {
		i := 1
		for i < len(e.Args) && strings.Contains(e.Args[i], "=") {
			i++
		}
		if i >= len(e.Args) {
			return 127
		}
		inner, ok := out[e.Args[i]]
		if !ok {
			return 127
		}
		e.Args = e.Args[i:]
		return inner(e)
	}
	return out
}

func newTargetFixture(t *testing.T, opts ...func(tf *targetFixture)) *targetFixture {
	t.Helper()
	tf := &targetFixture{home: t.TempDir()}
	tf.ssh = sshtest.New(t, sshtest.Options{Commands: demoCommands(), Shell: func(s *sshtest.Server, script string, out, errw io.Writer) int {
		if tf.shell == nil {
			io.WriteString(errw, "sh: not supported\n")
			return 127
		}
		return tf.shell(s, script, out, errw)
	}})
	ag := tf.ssh.NewAgent(t)
	var agentFn func() (agent.ExtendedAgent, io.Closer, error)
	agentFn = func() (agent.ExtendedAgent, io.Closer, error) {
		if tf.agentErr != nil {
			return nil, nil, tf.agentErr
		}
		return ag, nil, nil
	}
	tf.fixture = newFixtureWith(t, nil, func(f *fixture) {
		tf.fixture = f
		for _, o := range opts {
			o(tf)
		}
		srcs := source.NewRepo(f.st)
		cd := servercheck.CheckDeps{
			Repo: target.NewRepo(f.st), Store: f.st, Audit: f.log,
			SSH:     sshx.Deps{Gateway: f.gw, Audit: f.log, Agent: agentFn, Now: func() time.Time { return now }},
			Collect: collect.Deps{Now: func() time.Time { return now }, Audit: f.log, Gateway: f.gw},
			OSVRoot: t.TempDir(), Sources: srcs, Now: func() time.Time { return now },
		}
		f.deps.Servers = Servers{Check: cd, Home: tf.home}
		f.deps.Fix = &fix.Deps{Store: f.st, Audit: f.log, Secrets: f.deps.Secrets, Gateway: f.gw, Policy: f.deps.Policy, PolicyPath: f.policyPath,
			DataDir: f.dir, Lang: i18n.EN, Targets: cd.Repo, SSH: cd.SSH, Now: func() time.Time { return now }, Sessions: fix.NewSessions(),
			Reload: f.deps.Reload}
	})
	return tf
}

// addBody is the body that adds the simulated server.
func (tf *targetFixture) addBody(extra string) string {
	host, port, _ := strings.Cut(tf.ssh.Addr(), ":")
	body := `{"name":"srv-demo","host":"` + host + `","port":` + port + `,"user":"deploy"`
	if extra != "" {
		body += "," + extra
	}
	return body + "}"
}

func (tf *targetFixture) add(extra string) TargetView {
	tf.t.Helper()
	code, body := tf.send("POST", "/api/v1/targets", tf.addBody(extra))
	if code != http.StatusCreated {
		tf.t.Fatalf("add = %d %s", code, body)
	}
	var v TargetView
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		tf.t.Fatal(err)
	}
	return v
}

func (tf *targetFixture) view(id string) TargetView {
	tf.t.Helper()
	var v TargetView
	tf.get("/api/v1/targets/"+id, &v)
	return v
}

// pin confirms the simulated server's fingerprint through the API.
func (tf *targetFixture) pin(id string) {
	tf.t.Helper()
	code, body := tf.send("POST", "/api/v1/targets/"+id+"/hostkey", `{"fingerprint":"`+tf.ssh.HostKeyFingerprint()+`"}`)
	if code != http.StatusOK {
		tf.t.Fatalf("pin = %d %s", code, body)
	}
}

// waitChecked waits for the check started from the page to end.
func (tf *targetFixture) waitChecked(id string) TargetView {
	tf.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		v := tf.view(id)
		if !v.Checking && v.LastCheck != nil {
			return v
		}
		time.Sleep(20 * time.Millisecond)
	}
	tf.t.Fatal("the check did not end")
	return TargetView{}
}

func TestTargetRoutesNeedToken(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.add("")
	routes := []struct{ method, path, body string }{
		{"GET", "/api/v1/targets", ""},
		{"POST", "/api/v1/targets", tf.addBody(`"name":"other"`)},
		{"POST", "/api/v1/targets/discover", ""},
		{"GET", "/api/v1/targets/" + v.ID, ""},
		{"PATCH", "/api/v1/targets/" + v.ID, `{"fix_level":2}`},
		{"DELETE", "/api/v1/targets/" + v.ID, ""},
		{"GET", "/api/v1/targets/" + v.ID + "/hostkey", ""},
		{"POST", "/api/v1/targets/" + v.ID + "/hostkey", `{"fingerprint":"x"}`},
		{"POST", "/api/v1/targets/" + v.ID + "/check", ""},
		{"GET", "/api/v1/targets/" + v.ID + "/inventory", ""},
		{"POST", "/api/v1/targets/" + v.ID + "/fix/f1", ""},
		{"POST", "/api/v1/targets/" + v.ID + "/agent-fix/f1", ""},
		{"GET", "/api/v1/targets/" + v.ID + "/ai-consent", ""},
		{"POST", "/api/v1/targets/" + v.ID + "/ai-consent", ""},
		{"DELETE", "/api/v1/targets/" + v.ID + "/ai-consent", ""},
		{"POST", "/api/v1/fix/a1/snapshot-done", ""},
		{"POST", "/api/v1/fix/a1/applied-by-me", ""},
	}
	for _, r := range routes {
		for _, tok := range []string{"", "wrong"} {
			resp, body := tf.do(r.method, r.path, tok, r.body)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s token %q = %d", r.method, r.path, tok, resp.StatusCode)
			}
			if strings.Contains(body, "srv-demo") || strings.Contains(body, v.ID) {
				t.Errorf("%s %s: 401 leaks: %s", r.method, r.path, body)
			}
		}
	}
	list, _ := target.NewRepo(tf.st).List(context.Background())
	if len(list) != 1 || list[0].FixLevel != 1 || !list[0].Active {
		t.Errorf("targets after unauthorized calls = %+v", list)
	}
}

func TestTargetAddDefaultsAndPreprod(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.add("")
	if v.FixLevel != 1 || v.CheckInterval != "24h" || v.Kind != "vps" || v.Env != "prod" || v.Executor != "user" || v.Sudo != "none" || !v.Active {
		t.Errorf("defaults = %+v", v)
	}
	stored, err := target.NewRepo(tf.st).Get(context.Background(), v.ID)
	if err != nil || stored.CheckInterval != 0 && stored.CheckInterval != target.DefaultCheckInterval || stored.FixLevel != 1 {
		t.Errorf("stored = %+v %v", stored, err)
	}
	// "manual" is the by-hand-only interval; a level of 0 is kept.
	code, body := tf.send("POST", "/api/v1/targets", `{"name":"b","host":"192.0.2.20","user":"deploy","check_interval":"manual","fix_level":0,"kind":"hds"}`)
	if code != http.StatusCreated {
		t.Fatalf("add manual = %d %s", code, body)
	}
	var b TargetView
	_ = json.Unmarshal([]byte(body), &b)
	if b.CheckInterval != "manual" || b.FixLevel != 0 || b.Classification != "health" {
		t.Errorf("manual target = %+v", b)
	}
	if got, _ := target.NewRepo(tf.st).Get(context.Background(), b.ID); got.CheckInterval != target.ManualOnly {
		t.Errorf("stored interval = %v", got.CheckInterval)
	}
	if code, _ := tf.send("PATCH", "/api/v1/targets/"+b.ID, `{"check_interval":"12h"}`); code != http.StatusOK {
		t.Errorf("patch interval = %d", code)
	}
	if code, _ := tf.send("PATCH", "/api/v1/targets/"+b.ID, `{"check_interval":""}`); code != http.StatusOK {
		t.Errorf("patch default interval = %d", code)
	}
	if v := tf.view(b.ID); v.CheckInterval != "24h" {
		t.Errorf("interval back to default = %q", v.CheckInterval)
	}

	// The preprod must exist, be a server, not be itself and make no chain.
	for name, tc := range map[string]struct {
		method, path, body, code string
		status                   int
	}{
		"unknown":    {"PATCH", "/api/v1/targets/" + v.ID, `{"preprod":"nope"}`, "api.target.preprod_not_found", 400},
		"self":       {"PATCH", "/api/v1/targets/" + v.ID, `{"preprod":"` + v.ID + `"}`, "api.target.preprod_self", 400},
		"self name":  {"PATCH", "/api/v1/targets/" + v.ID, `{"preprod":"srv-demo"}`, "api.target.preprod_self", 400},
		"on add":     {"POST", "/api/v1/targets", `{"name":"c","host":"192.0.2.30","user":"d","preprod":"ghost"}`, "api.target.preprod_not_found", 400},
		"bad ivl":    {"PATCH", "/api/v1/targets/" + v.ID, `{"check_interval":"soon"}`, "api.target.bad_interval", 400},
		"short ivl":  {"PATCH", "/api/v1/targets/" + v.ID, `{"check_interval":"1m"}`, "api.target.bad_interval", 400},
		"site url":   {"PATCH", "/api/v1/targets/" + v.ID, `{"site_url":"ftp://example.test"}`, "api.target.bad_site_url", 400},
		"bad level":  {"PATCH", "/api/v1/targets/" + v.ID, `{"fix_level":7}`, "api.target.bad_fix_level", 400},
		"duplicate":  {"POST", "/api/v1/targets", `{"name":"srv-demo","host":"192.0.2.31","user":"d"}`, "api.target.duplicate", 409},
		"no user":    {"POST", "/api/v1/targets", `{"name":"d","host":"192.0.2.32"}`, "api.target.bad_user", 400},
		"not a link": {"POST", "/api/v1/targets", `{"name":"e","host":"192.0.2.33","user":"d","links":[{"project":"demo","remote_dir":"var/www"}]}`, "api.target.bad_remote_dir", 400},
	} {
		code, body := tf.send(tc.method, tc.path, tc.body)
		var eb FixErrorBody
		_ = json.Unmarshal([]byte(body), &eb)
		if code != tc.status || eb.Code != tc.code || eb.Error == "" || strings.HasPrefix(eb.Error, "!") {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	// A preprod that has a preprod, and a server that is a preprod, make chains.
	prodAsPre := tf.addNamed("prod2", "192.0.2.39")
	if code, body := tf.send("PATCH", "/api/v1/targets/"+v.ID, `{"preprod":"prod2"}`); code != http.StatusBadRequest || !strings.Contains(body, "preprod_role") {
		t.Errorf("a production server as preprod = %d %s", code, body)
	}
	_ = prodAsPre
	pre := tf.addNamed("pre", "192.0.2.40", "preprod")
	if code, body := tf.send("PATCH", "/api/v1/targets/"+v.ID, `{"preprod":"pre"}`); code != http.StatusOK {
		t.Fatalf("set preprod = %d %s", code, body)
	}
	if got := tf.view(v.ID); got.Preprod == nil || got.Preprod.ID != pre.ID {
		t.Errorf("preprod = %+v", got.Preprod)
	}
	pre2 := tf.addNamed("pre2", "192.0.2.42", "preprod")
	if code, body := tf.send("PATCH", "/api/v1/targets/"+pre2.ID, `{"preprod":"pre"}`); code != http.StatusOK {
		t.Fatalf("pre2 gets a preprod = %d %s", code, body)
	}
	chain := tf.addNamed("chain", "192.0.2.41", "dev")
	if code, body := tf.send("PATCH", "/api/v1/targets/"+chain.ID, `{"preprod":"pre2"}`); code != http.StatusBadRequest || !strings.Contains(body, "preprod_chain") {
		t.Errorf("preprod that has a preprod = %d %s", code, body)
	}
	if code, body := tf.send("PATCH", "/api/v1/targets/"+pre.ID, `{"preprod":"chain"}`); code != http.StatusBadRequest || !strings.Contains(body, "preprod_chain") {
		t.Errorf("server that is a preprod gets one = %d %s", code, body)
	}
	// A server that is somebody's preprod cannot turn production.
	if code, body := tf.send("PATCH", "/api/v1/targets/"+pre.ID, `{"env":"prod"}`); code != http.StatusBadRequest || !strings.Contains(body, "preprod_role") {
		t.Errorf("preprod turned production = %d %s", code, body)
	}
	// Removing the preprod leaves no dangling name.
	if code, _ := tf.send("DELETE", "/api/v1/targets/"+pre.ID, ""); code != http.StatusOK {
		t.Fatalf("delete preprod = %d", code)
	}
	if got := tf.view(v.ID); got.Preprod != nil {
		t.Errorf("dangling preprod = %+v", got.Preprod)
	}
}

func (tf *targetFixture) addNamed(name, host string, env ...string) TargetView {
	tf.t.Helper()
	extra := ""
	if len(env) > 0 {
		extra = `,"env":"` + env[0] + `"`
	}
	code, body := tf.send("POST", "/api/v1/targets", `{"name":"`+name+`","host":"`+host+`","user":"deploy"`+extra+`}`)
	if code != http.StatusCreated {
		tf.t.Fatalf("add %s = %d %s", name, code, body)
	}
	var v TargetView
	_ = json.Unmarshal([]byte(body), &v)
	return v
}

func TestAddingAServerWritesItsNetworkRule(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.add(`"site_url":"https://www.example.test/"`)
	b, err := os.ReadFile(tf.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	host, _, _ := strings.Cut(tf.ssh.Addr(), ":")
	for _, want := range []string{host, "target.ssh", "www.example.test", "target.http"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("policy file lacks %q:\n%s", want, b)
		}
	}
	if ok, _ := tf.gw.Allowed(host, policy.PurposeTargetSSH); !ok {
		t.Error("the gateway does not allow the new server")
	}
	rows := tf.auditRows("target.add")
	if len(rows) != 1 || rows[0].target != v.ID || rows[0].evidence["rules_written"] != float64(2) {
		t.Errorf("audit = %+v", rows)
	}
}

func TestDiscoverReturnsCandidates(t *testing.T) {
	tf := newTargetFixture(t)
	if err := os.MkdirAll(filepath.Join(tf.home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := "Host srv-demo\n  HostName example.test\n  User deploy\n  Port 2222\n  IdentityFile ~/.ssh/id_demo\n\nHost ip-demo\n  HostName 192.0.2.10\n  User deploy\n"
	if err := os.WriteFile(filepath.Join(tf.home, ".ssh", "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	idea := filepath.Join(tf.proj.Path, ".idea")
	if err := os.MkdirAll(idea, 0o755); err != nil {
		t.Fatal(err)
	}
	web := `<project><component name="WebServers"><option name="servers"><webServer name="prod-demo" url="http://example.test">` +
		`<fileTransfer accessType="SFTP" host="example.test" port="2222" userName="deploy" password="hunter2-secret"/></webServer></option></component></project>`
	dep := `<project><component name="PublishConfigData" serverName="prod-demo"><serverData><paths name="prod-demo"><serverdata><mappings>` +
		`<mapping deploy="/var/www/app" local="$PROJECT_DIR$"/></mappings></serverdata></paths></serverData></component></project>`
	for n, c := range map[string]string{"webServers.xml": web, "deployment.xml": dep} {
		if err := os.WriteFile(filepath.Join(idea, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out []CandidateView
	code, body := tf.send("POST", "/api/v1/targets/discover", "")
	if code != http.StatusOK {
		t.Fatalf("discover = %d %s", code, body)
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	by := map[string]CandidateView{}
	for _, c := range out {
		by[c.Alias+"|"+c.Host] = c
	}
	srv, ok := by["srv-demo|example.test"]
	if !ok || srv.Port != 2222 || srv.User != "deploy" || srv.Known {
		t.Fatalf("candidates = %+v", out)
	}
	if ip, ok := by["ip-demo|192.0.2.10"]; !ok || ip.Port != 22 {
		t.Errorf("ip-demo = %+v", ip)
	}
	linked := false
	for _, c := range out {
		for _, l := range c.Projects {
			if l.Project == "demo" && l.RemoteDir == "/var/www/app" {
				linked = true
			}
		}
	}
	if !linked {
		t.Errorf("no candidate is linked to the project demo: %+v", out)
	}
	for _, leak := range []string{"hunter2", "id_demo", tf.home, tf.proj.Path} {
		if strings.Contains(body, leak) {
			t.Errorf("discover leaks %q: %s", leak, body)
		}
	}
	// Adding the candidate with its link, then discovering again: it is known.
	code, body = tf.send("POST", "/api/v1/targets", `{"alias":"srv-demo","name":"prod-demo","host":"example.test","port":2222,"user":"deploy",`+
		`"links":[{"project":"demo","remote_dir":"/var/www/app"}]}`)
	if code != http.StatusCreated {
		t.Fatalf("add candidate = %d %s", code, body)
	}
	var added TargetView
	_ = json.Unmarshal([]byte(body), &added)
	if len(added.Projects) != 1 || added.Projects[0].Project != "demo" || added.Projects[0].RemoteDir != "/var/www/app" {
		t.Errorf("projects = %+v", added.Projects)
	}
	_, body = tf.send("POST", "/api/v1/targets/discover", "")
	_ = json.Unmarshal([]byte(body), &out)
	for _, c := range out {
		if c.Host == "example.test" && !c.Known {
			t.Errorf("the added server is still a candidate: %+v", c)
		}
	}
}

func TestHostKeyConfirmFlow(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.add("")
	if v.HostKeyPinned || v.State.Code != "key_unconfirmed" {
		t.Errorf("new server = %+v", v)
	}
	var hk HostKeyView
	tf.get("/api/v1/targets/"+v.ID+"/hostkey", &hk)
	if hk.Fingerprint != tf.ssh.HostKeyFingerprint() || hk.Pinned != "" || hk.Matches || hk.KeyType == "" {
		t.Errorf("hostkey = %+v", hk)
	}
	// A wrong fingerprint pins nothing: 409.
	code, body := tf.send("POST", "/api/v1/targets/"+v.ID+"/hostkey", `{"fingerprint":"SHA256:wrong"}`)
	var eb FixErrorBody
	_ = json.Unmarshal([]byte(body), &eb)
	if code != http.StatusConflict || eb.Code != "api.target.hostkey_mismatch" {
		t.Fatalf("wrong fingerprint = %d %s", code, body)
	}
	if got := tf.view(v.ID); got.HostKeyPinned {
		t.Error("a wrong fingerprint was pinned")
	}
	if code, _ := tf.send("POST", "/api/v1/targets/"+v.ID+"/hostkey", `{"fingerprint":""}`); code != http.StatusBadRequest {
		t.Errorf("empty fingerprint = %d", code)
	}
	tf.pin(v.ID)
	got := tf.view(v.ID)
	if !got.HostKeyPinned || got.HostKey != tf.ssh.HostKeyFingerprint() {
		t.Errorf("after confirm = %+v", got)
	}
	tf.get("/api/v1/targets/"+v.ID+"/hostkey", &hk)
	if !hk.Matches || hk.Pinned != hk.Fingerprint {
		t.Errorf("hostkey after = %+v", hk)
	}
	rows := tf.auditRows("target.hostkey")
	if len(rows) != 2 || rows[0].evidence["reason"] == nil || rows[1].evidence["fingerprint"] != tf.ssh.HostKeyFingerprint() {
		t.Errorf("audit = %+v", rows)
	}
	// Moving the server asks for a new confirmation.
	if code, body := tf.send("PATCH", "/api/v1/targets/"+v.ID, `{"host":"192.0.2.77"}`); code != http.StatusOK {
		t.Fatalf("patch host = %d %s", code, body)
	}
	if got := tf.view(v.ID); got.HostKeyPinned {
		t.Error("the fingerprint outlived a change of host")
	}
}

func TestCheckReturns202(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.add("")
	tf.pin(v.ID)
	code, body := tf.send("POST", "/api/v1/targets/"+v.ID+"/check", "")
	if code != http.StatusAccepted || !strings.Contains(body, "started") {
		t.Fatalf("check = %d %s", code, body)
	}
	got := tf.waitChecked(v.ID)
	if !got.LastCheck.OK || got.LastCheckAt == "" {
		t.Fatalf("check outcome = %+v / %+v", got.LastCheck, got)
	}
	if len(got.History) != 1 {
		t.Errorf("history = %+v", got.History)
	}
	var inv InventoryView
	tf.get("/api/v1/targets/"+v.ID+"/inventory", &inv)
	if inv.OS.ID != "debian" || len(inv.Packages) == 0 {
		t.Errorf("inventory = %+v", inv)
	}
	// An unknown server, and an inactive one, answer in clear.
	if code, _ := tf.send("POST", "/api/v1/targets/nope/check", ""); code != http.StatusNotFound {
		t.Errorf("unknown server = %d", code)
	}
	if code, _ := tf.send("PATCH", "/api/v1/targets/"+v.ID, `{"active":false}`); code != http.StatusOK {
		t.Fatal("deactivate")
	}
	if code, body := tf.send("POST", "/api/v1/targets/"+v.ID+"/check", ""); code != http.StatusConflict || !strings.Contains(body, "api.target.inactive") {
		t.Errorf("inactive = %d %s", code, body)
	}
}

func TestCheckFailureIsShownInClearWithoutPaths(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent.sock")
	tf := newTargetFixture(t, func(tf *targetFixture) {
		tf.agentErr = errors.New("dial unix " + sock + ": connect: no such file or directory")
	})
	v := tf.add("")
	tf.pin(v.ID)
	if code, body := tf.send("POST", "/api/v1/targets/"+v.ID+"/check", ""); code != http.StatusAccepted {
		t.Fatalf("check = %d %s", code, body)
	}
	got := tf.waitChecked(v.ID)
	if got.LastCheck.OK || got.LastCheck.Code != "api.target.no_agent" || got.State.Code != "check_failed" {
		t.Fatalf("outcome = %+v / %+v", got.LastCheck, got.State)
	}
	want := sshx.ErrNoAgent.Error()
	if !strings.EqualFold(strings.TrimSuffix(got.LastCheck.Error, "."), want) {
		t.Errorf("error = %q, want the sentinel %q", got.LastCheck.Error, want)
	}
	_, fr := tf.send("GET", "/api/v1/targets/"+v.ID+"?lang=fr", "")
	if strings.Contains(fr, sock) || !strings.Contains(fr, "agent SSH") {
		t.Errorf("fr detail = %s", fr)
	}
	// The same for the fingerprint route and the fix routes.
	for _, path := range []string{"/api/v1/targets/" + v.ID} {
		_, b := tf.send("GET", path, "")
		for _, leak := range []string{sock, filepath.Dir(sock), "agent.sock", "dial unix"} {
			if strings.Contains(b, leak) {
				t.Errorf("%s leaks %q: %s", path, leak, b)
			}
		}
	}
}

func TestTargetResponsesHaveNoLocalPaths(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.add(`"site_url":"https://www.example.test/"`)
	tf.pin(v.ID)
	tf.send("POST", "/api/v1/targets/"+v.ID+"/check", "")
	tf.waitChecked(v.ID)
	// A server text that holds a path of a Windows computer is cut.
	repo := target.NewRepo(tf.st)
	inv, _, _ := repo.LatestInventory(context.Background(), v.ID)
	inv.Unseen = append(inv.Unseen, target.Unseen{What: `D:\Home\demo\keys`, Reason: `file:///D:/Home/demo/x`})
	inv.Web = append(inv.Web, target.WebServer{Name: `\\host\share\nginx`, Version: "1"})
	if err := repo.SaveInventory(context.Background(), inv); err != nil {
		t.Fatal(err)
	}
	locals := []string{tf.home, tf.dir, tf.policyPath, tf.proj.Path, os.TempDir(), `D:\Home`, `D:/Home`, `\\host`, "file:/", "demo/x", "keys"}
	paths := []string{"/api/v1/targets", "/api/v1/targets/" + v.ID, "/api/v1/targets/" + v.ID + "/inventory", "/api/v1/targets/" + v.ID + "/hostkey",
		"/api/v1/targets/" + v.ID + "/ai-consent", "/api/v1/fixes?target=" + v.ID}
	for _, p := range paths {
		for _, lang := range []string{"en", "fr"} {
			code, body := tf.send("GET", p+map[bool]string{true: "&", false: "?"}[strings.Contains(p, "?")]+"lang="+lang, "")
			if code >= 500 {
				t.Errorf("%s = %d %s", p, code, body)
			}
			for _, l := range locals {
				if l != "" && strings.Contains(body, l) {
					t.Errorf("%s (%s) holds %q: %s", p, lang, l, body)
				}
			}
		}
	}
	code, body := tf.send("POST", "/api/v1/targets/discover", "")
	if code != 200 {
		t.Errorf("discover = %d", code)
	}
	for _, l := range locals {
		if strings.Contains(body, l) {
			t.Errorf("discover holds %q", l)
		}
	}
}
