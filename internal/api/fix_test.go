package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/agent"
	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/workcopy"
)

// fakeAWS is a secret the masker always finds (built so that no scanner
// sees a key in this file).
func fakeAWS() string { return "AKIA" + "ABCDEFGHIJKLMNOP" }

const fixPolicy = "sovereignty:\n  mode: standard\n  data_classification: sensitive\n  network:\n    default_egress: deny\n    allow: []\n"

// fakeAgent is the Claude Code session of the API tests: the test emits its
// events and reads what was sent to it.
type fakeAgent struct {
	events chan agent.Event
	mu     sync.Mutex
	sent   []string
	closed bool
}

func (s *fakeAgent) Events() <-chan agent.Event { return s.events }
func (s *fakeAgent) ID() string                 { return "0f0f0f0f-0000-4000-8000-000000000002" }
func (s *fakeAgent) Send(text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("closed")
	}
	s.sent = append(s.sent, text)
	return nil
}
func (s *fakeAgent) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.events)
	}
	return nil
}
func (s *fakeAgent) emit(e agent.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.events <- e
	}
}
func (s *fakeAgent) received() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.sent...)
}

// fixFixture is the API fixture with the fix service: the project demo is a
// git repository, the policy is standard, the agent is fake and the
// commands other than git are recorded, not run.
type fixFixture struct {
	*fixture
	fd     *fix.Deps
	agents chan *fakeAgent
}

func gitRun(t *testing.T, env []string, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "core.autocrlf=false"}, args...)...)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

// newFixFixture builds the fixture; each opt runs on it before the handler
// is built.
func newFixFixture(t *testing.T, opts ...func(ff *fixFixture)) *fixFixture {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	ff := &fixFixture{agents: make(chan *fakeAgent, 4)}
	ff.fixture = newFixtureWith(t, nil, func(f *fixture) {
		gc := filepath.Join(t.TempDir(), "gitconfig")
		if err := os.WriteFile(gc, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		env := append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+gc,
			"GIT_AUTHOR_NAME=demo", "GIT_AUTHOR_EMAIL=demo@example.test", "GIT_COMMITTER_NAME=demo", "GIT_COMMITTER_EMAIL=demo@example.test")
		root := f.proj.Path
		for name, body := range map[string]string{
			"README.md":     "demo\n",
			"composer.json": `{"name":"demo/app","require":{"acme/framework":"^1.0"}}` + "\n",
			"composer.lock": `{"packages":[{"name":"acme/vuln","version":"1.0.0"}]}` + "\n",
		} {
			if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		gitRun(t, env, root, "init", "-q", "-b", "main")
		gitRun(t, env, root, "add", "-A")
		gitRun(t, env, root, "commit", "-q", "-m", "init")
		if err := os.WriteFile(f.policyPath, []byte(fixPolicy), 0o600); err != nil {
			t.Fatal(err)
		}
		pol, err := f.deps.Reload()
		if err != nil {
			t.Fatal(err)
		}
		f.deps.Policy = pol
		f.gw.SetRules(pol.Sovereignty.Network.Allow)
		exe := func(ctx context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
			if name == "git" {
				return workcopy.DefaultExec(ctx, name, args, env, dir)
			}
			return []byte("ok\n"), nil, nil
		}
		ff.fd = &fix.Deps{
			Store: f.st, Audit: f.log, Secrets: f.deps.Secrets, Gateway: f.gw, Policy: pol, PolicyPath: f.policyPath,
			DataDir: f.dir, Lang: i18n.EN,
			Work:   workcopy.Deps{DataDir: f.dir, Exec: exe, Now: func() time.Time { return now }},
			Rescan: func(context.Context, string, scan.Finding, project.Project) (bool, error) { return true, nil },
			AgentStatus: func(context.Context) agent.Status {
				return agent.Status{Installed: true, LoggedIn: true, Version: "2.1.314"}
			},
			Agent: func(ctx context.Context, ad agent.Deps, s agent.Spec) (fix.Session, error) {
				a := &fakeAgent{events: make(chan agent.Event, 16)}
				ff.agents <- a
				return a, nil
			},
			MCPCommand: []string{"michel", "mcp"}, Now: func() time.Time { return now },
			Sessions: fix.NewSessions(), Timeout: time.Minute, PollInterval: 20 * time.Millisecond,
		}
		f.deps.Fix = ff.fd
		ff.fixture = f
		for _, o := range opts {
			o(ff)
		}
	})
	return ff
}

// consent gives the project's AI consent through the API.
func (ff *fixFixture) consent() {
	ff.t.Helper()
	if code, body := ff.send("POST", "/api/v1/projects/demo/ai-consent", ""); code != http.StatusOK {
		ff.t.Fatalf("consent = %d %s", code, body)
	}
}

// start starts a fix of the first finding and returns the attempt and its
// fake agent.
func (ff *fixFixture) start() (AttemptView, *fakeAgent) {
	ff.t.Helper()
	code, body := ff.send("POST", "/api/v1/findings/"+ff.ids["ACME-2026-0001"]+"/fix", "")
	if code != http.StatusAccepted {
		ff.t.Fatalf("start = %d %s", code, body)
	}
	var v struct {
		Attempt AttemptView `json:"attempt"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil || v.Attempt.ID == "" {
		ff.t.Fatalf("start body: %v %s", err, body)
	}
	select {
	case a := <-ff.agents:
		return v.Attempt, a
	case <-time.After(10 * time.Second):
		ff.t.Fatal("the agent was not started")
	}
	return AttemptView{}, nil
}

// seedProposed stores an attempt in state proposed with one proposal
// (directly in the store, without any agent) and returns its id and hash.
// The attempt belongs to a second project, other, so that demo stays free.
func (ff *fixFixture) seedProposed() (string, string) {
	ff.t.Helper()
	ctx := context.Background()
	other, err := project.NewRepo(ff.st).Add(ctx, project.Project{Name: "other", Path: ff.t.TempDir()})
	if err != nil {
		ff.t.Fatal(err)
	}
	if _, err := ff.st.DB().Exec(`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, severity_label,
		installed_version, fixed_versions, status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, status_changed_at, summary)
		VALUES ('fother', ?, 'package-lock.json', 'npm', 'vuln-pkg', 'ACME-2026-0009', 'high', '1.0.0', '["1.2.5"]', 'new', 's1', 's1', ?, ?, ?, 'Remote code execution')`,
		other.ID, ts(now), ts(now), ts(now)); err != nil {
		ff.t.Fatal(err)
	}
	repo := fix.NewRepo(ff.st)
	a, err := repo.CreateAttempt(ctx, fix.Attempt{FindingID: "fother", ProjectID: other.ID, Origin: fix.OriginAgent})
	if err != nil {
		ff.t.Fatal(err)
	}
	p, err := repo.AddProposal(ctx, fix.Proposal{AttemptID: a.ID, Summary: "Upgrade vuln-pkg to 1.2.5.", Diff: "--- a/package-lock.json\n+++ b/package-lock.json\n",
		Files: []string{"package-lock.json"}, TestsStatus: "passed", RescanClean: true, Hash: "hash-one", CommitSHA: "abc",
		FromVersion: "1.0.0", ToVersion: "1.2.5"})
	if err != nil {
		ff.t.Fatal(err)
	}
	if err := repo.SetState(ctx, a.ID, []fix.State{fix.StatePreparing}, fix.StateProposed, ""); err != nil {
		ff.t.Fatal(err)
	}
	return a.ID, p.Hash
}

// sseEvent is one event of the stream.
type sseEvent struct {
	name, data string
}

// openStream opens the event stream of the attempt on srv and sends its
// events on the channel, which is closed when the stream ends.
func openStream(t *testing.T, srv *httptest.Server, attemptID, query string) (<-chan sseEvent, *http.Response, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/v1/fix/"+attemptID+"/events"+query, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := srv.Client().Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	out := make(chan sseEvent, 64)
	go func() {
		defer close(out)
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		var ev sseEvent
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if ev.name != "" || ev.data != "" {
					out <- ev
				}
				ev = sseEvent{}
			case strings.HasPrefix(line, "event: "):
				ev.name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				ev.data += strings.TrimPrefix(line, "data: ")
			}
		}
	}()
	return out, resp, cancel
}

// waitEvent reads events until match accepts one; all the events read are
// returned too.
func waitEvent(t *testing.T, ch <-chan sseEvent, match func(sseEvent) bool) (sseEvent, []sseEvent) {
	t.Helper()
	var seen []sseEvent
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("the stream ended before the expected event; seen %+v", seen)
			}
			seen = append(seen, ev)
			if match(ev) {
				return ev, seen
			}
		case <-deadline:
			t.Fatalf("no expected event; seen %+v", seen)
		}
	}
}

func TestFixRoutesNeedToken(t *testing.T) {
	ff := newFixFixture(t)
	id, hash := ff.seedProposed()
	fid := ff.ids["ACME-2026-0001"]
	routes := []struct{ method, path, body string }{
		{"POST", "/api/v1/findings/" + fid + "/fix", ""},
		{"GET", "/api/v1/fix/" + id, ""},
		{"GET", "/api/v1/fix/" + id + "/events", ""},
		{"POST", "/api/v1/fix/" + id + "/message", `{"text":"hello"}`},
		{"POST", "/api/v1/fix/" + id + "/approve", `{"hash":"` + hash + `"}`},
		{"POST", "/api/v1/fix/" + id + "/refuse", `{"reason":"no"}`},
		{"GET", "/api/v1/fixes", ""},
		{"GET", "/api/v1/agent/status", ""},
		{"GET", "/api/v1/projects/demo/ai-consent", ""},
		{"POST", "/api/v1/projects/demo/ai-consent", ""},
	}
	for _, r := range routes {
		for _, tok := range []string{"", "wrong"} {
			resp, body := ff.do(r.method, r.path, tok, r.body)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s token %q = %d", r.method, r.path, tok, resp.StatusCode)
			}
			if strings.Contains(body, "vuln-pkg") || strings.Contains(body, id) {
				t.Errorf("%s %s: 401 leaks: %s", r.method, r.path, body)
			}
		}
	}
	// Nothing changed: no new attempt, no consent, the proposal waits.
	a, err := fix.NewRepo(ff.st).GetAttempt(context.Background(), id)
	if err != nil || a.State != fix.StateProposed {
		t.Errorf("attempt = %+v %v", a, err)
	}
	if list, _ := fix.NewRepo(ff.st).ListAttempts(context.Background(), "", ""); len(list) != 1 {
		t.Errorf("attempts = %d", len(list))
	}
	if _, _, ok, _ := fix.NewRepo(ff.st).Consent(context.Background(), ff.proj.ID); ok {
		t.Error("consent recorded without a token")
	}
}

func TestStartFixReturns202(t *testing.T) {
	ff := newFixFixture(t)
	fid := ff.ids["ACME-2026-0001"]
	// Without the project's consent: 409 with the reason in clear, and the
	// consent lines to show.
	resp, body := ff.do("POST", "/api/v1/findings/"+fid+"/fix?lang=fr", testToken, "")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("start without consent = %d %s", resp.StatusCode, body)
	}
	var eb FixErrorBody
	if err := json.Unmarshal([]byte(body), &eb); err != nil || eb.Code != "fix.err.consent_required" ||
		eb.Error != i18n.T(i18n.FR, "fix.err.consent_required") || len(eb.Consent) == 0 {
		t.Errorf("refusal body = %s", body)
	}
	// The consent screen, then the consent.
	var cv AIConsentView
	ff.get("/api/v1/projects/demo/ai-consent?lang=fr", &cv)
	if cv.Ready || cv.Consented || len(cv.Lines) == 0 {
		t.Fatalf("consent view = %+v", cv)
	}
	runsCode := false
	for _, l := range cv.Lines {
		if l.Text == "" || strings.HasPrefix(l.Text, "!") {
			t.Errorf("line without text: %+v", l)
		}
		if l.What == "fix.consent.runs_code" && l.Text == i18n.T(i18n.FR, "fix.consent.runs_code") {
			runsCode = true
		}
	}
	if !runsCode {
		t.Errorf("the consent screen lacks the sentence on the code that runs: %+v", cv.Lines)
	}
	ff.consent()
	ff.get("/api/v1/projects/demo/ai-consent", &cv)
	if !cv.Ready || !cv.Consented || len(cv.Lines) != 0 {
		t.Errorf("consent view after consent = %+v", cv)
	}
	if rows := ff.auditRows("ai.consent"); len(rows) != 1 {
		t.Errorf("ai.consent rows = %d", len(rows))
	}

	// Unknown finding: 404.
	if code, _ := ff.send("POST", "/api/v1/findings/nope/fix", ""); code != http.StatusNotFound {
		t.Errorf("unknown finding = %d", code)
	}
	a, ag := ff.start()
	if a.State != string(fix.StatePreparing) || a.Project != "demo" || a.Finding.ID != fid || a.Finding.Package != "acme/vuln" {
		t.Errorf("attempt = %+v", a)
	}
	// One at a time per project.
	resp, body = ff.do("POST", "/api/v1/findings/"+ff.ids["ACME-2026-0002"]+"/fix", testToken, "")
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "fix.err.busy") {
		t.Errorf("second start = %d %s", resp.StatusCode, body)
	}
	// The view, a message to the agent, the list, then a refusal.
	var v AttemptView
	ff.get("/api/v1/fix/"+a.ID, &v)
	if v.ID != a.ID || v.Messages == nil {
		t.Errorf("view = %+v", v)
	}
	if code, body := ff.send("POST", "/api/v1/fix/"+a.ID+"/message", `{"text":"   "}`); code != http.StatusBadRequest {
		t.Errorf("empty message = %d %s", code, body)
	}
	if code, body := ff.send("POST", "/api/v1/fix/"+a.ID+"/message", `{"text":"Keep the old API."}`); code != http.StatusAccepted {
		t.Errorf("message = %d %s", code, body)
	}
	if got := ag.received(); len(got) != 1 || got[0] != "Keep the old API." {
		t.Errorf("the agent received %q", got)
	}
	var list []AttemptView
	ff.get("/api/v1/fixes?state=preparing,proposed", &list)
	if len(list) != 1 || list[0].ID != a.ID || list[0].Messages != nil {
		t.Errorf("list = %+v", list)
	}
	if code, body := ff.send("GET", "/api/v1/fixes?state=bogus", ""); code != http.StatusBadRequest {
		t.Errorf("bad state filter = %d %s", code, body)
	}
	var st AgentStatusView
	ff.get("/api/v1/agent/status", &st)
	if !st.Ready || !st.Installed || st.Version != "2.1.314" {
		t.Errorf("agent status = %+v", st)
	}
	if code, body := ff.send("POST", "/api/v1/fix/"+a.ID+"/refuse", `{"reason":"not now"}`); code != http.StatusOK {
		t.Errorf("refuse = %d %s", code, body)
	} else if err := json.Unmarshal([]byte(body), &v); err != nil || v.State != string(fix.StateRefused) || v.Cause != "not now" {
		t.Errorf("refused view = %s", body)
	}
	// A refused attempt takes no more message.
	if code, body := ff.send("POST", "/api/v1/fix/"+a.ID+"/message", `{"text":"hello"}`); code != http.StatusConflict {
		t.Errorf("message after refusal = %d %s", code, body)
	}
}

func TestEventsStreamDeliversMessagesAndClosesOnHandlerClose(t *testing.T) {
	ff := newFixFixture(t)
	ctx := context.Background()
	repo := fix.NewRepo(ff.st)
	a, err := repo.CreateAttempt(ctx, fix.Attempt{FindingID: ff.ids["ACME-2026-0001"], ProjectID: ff.proj.ID, Origin: fix.OriginAgent})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.AddMessage(ctx, fix.Message{AttemptID: a.ID, Role: fix.RoleMichel, Text: "I look at your project."}); err != nil {
		t.Fatal(err)
	}
	// A server whose write timeout is shorter than the stream: the route
	// lifts it.
	srv := httptest.NewUnstartedServer(ff.h)
	srv.Config.WriteTimeout = 300 * time.Millisecond
	srv.Start()
	defer srv.Close()
	ch, resp, cancel := openStream(t, srv, a.ID, "")
	defer cancel()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream = %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	// The conversation first, then the proposal, then the state: once the
	// state says proposed, the proposal is known.
	waitEvent(t, ch, func(e sseEvent) bool {
		return e.name == "message" && strings.Contains(e.data, "I look at your project.")
	})
	waitEvent(t, ch, func(e sseEvent) bool { return e.name == "state" && strings.Contains(e.data, `"preparing"`) })
	// After the write timeout, written by another process (michel mcp
	// shares the store): a tool line, a message, the proposal.
	time.Sleep(500 * time.Millisecond)
	if _, err := repo.AddMessage(ctx, fix.Message{AttemptID: a.ID, Role: fix.RoleTool, Text: "Read composer.json"}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.AddMessage(ctx, fix.Message{AttemptID: a.ID, Role: fix.RoleAgent, Text: "The update is enough."}); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, ch, func(e sseEvent) bool { return e.name == "activity" && strings.Contains(e.data, "Read composer.json") })
	waitEvent(t, ch, func(e sseEvent) bool { return e.name == "message" && strings.Contains(e.data, "The update is enough.") })
	if _, err := repo.AddProposal(ctx, fix.Proposal{AttemptID: a.ID, Summary: "Upgrade acme/vuln to 1.2.5.", Files: []string{"composer.lock"},
		TestsStatus: "passed", Hash: "h1"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetState(ctx, a.ID, []fix.State{fix.StatePreparing}, fix.StateProposed, ""); err != nil {
		t.Fatal(err)
	}
	ev, _ := waitEvent(t, ch, func(e sseEvent) bool { return e.name == "proposal" })
	var pv ProposalView
	if err := json.Unmarshal([]byte(ev.data), &pv); err != nil || pv.Hash != "h1" || pv.Summary != "Upgrade acme/vuln to 1.2.5." {
		t.Errorf("proposal event = %s", ev.data)
	}
	waitEvent(t, ch, func(e sseEvent) bool { return e.name == "state" && strings.Contains(e.data, `"proposed"`) })

	// A second stream starts with the whole conversation.
	ch2, _, cancel2 := openStream(t, srv, a.ID, "")
	defer cancel2()
	_, seen := waitEvent(t, ch2, func(e sseEvent) bool { return e.name == "proposal" })
	n := 0
	for _, e := range seen {
		if e.name == "message" || e.name == "activity" {
			n++
		}
	}
	if n != 3 {
		t.Errorf("a new stream replays %d lines, want 3: %+v", n, seen)
	}

	// Handler.Close ends the streams.
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()
	ff.h.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not end on Handler.Close")
	}
}

// tokenRe is a whole mask token.
var tokenRe = regexp.MustCompile(`\[secret-[0-9a-f]{8}-[0-9]+\]`)

func TestEventsNeverShowMaskFragment(t *testing.T) {
	ff := newFixFixture(t)
	ff.consent()
	a, ag := ff.start()
	ch, _, cancel := openStream(t, ff.srv, a.ID, "")
	defer cancel()
	secret := fakeAWS()
	// The agent quotes the secret in two chunks and whole; a raw secret
	// that reached the store (an older row) is masked again on the way
	// out.
	ag.emit(agent.Event{Kind: agent.KindText, Text: "Found AWS_KEY=" + secret[:10]})
	ag.emit(agent.Event{Kind: agent.KindText, Text: secret[10:] + " in .env"})
	ag.emit(agent.Event{Kind: agent.KindText, Text: "The key " + secret + " is used in src/app.php."})
	if _, err := fix.NewRepo(ff.st).AddMessage(context.Background(), fix.Message{AttemptID: a.ID, Role: fix.RoleAgent,
		Text: "raw " + secret + " and the folder " + ff.proj.Path}); err != nil {
		t.Fatal(err)
	}
	_, seen := waitEvent(t, ch, func(e sseEvent) bool { return strings.Contains(e.data, "raw ") })
	var view AttemptView
	body := ff.get("/api/v1/fix/"+a.ID, &view)
	all := []string{body}
	for _, e := range seen {
		all = append(all, e.data)
	}
	for _, text := range all {
		if strings.Contains(text, secret) || strings.Contains(text, ff.proj.Path) || strings.Contains(text, filepath.ToSlash(ff.proj.Path)) {
			t.Errorf("a secret or a path leaks: %s", text)
		}
		rest := tokenRe.ReplaceAllString(text, "")
		if strings.Contains(rest, "[secr") || strings.Contains(rest, "[secret") {
			t.Errorf("a fragment of a token is shown: %s", text)
		}
	}
	if !tokenRe.MatchString(strings.Join(all, "\n")) {
		t.Errorf("the masked secret shows no token:\n%s", strings.Join(all, "\n"))
	}
}

func TestApproveStaleReturns409(t *testing.T) {
	ff := newFixFixture(t)
	id, hash := ff.seedProposed()
	resp, body := ff.do("POST", "/api/v1/fix/"+id+"/approve?lang=fr", testToken, `{"hash":"`+hash+`-old"}`)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale approve = %d %s", resp.StatusCode, body)
	}
	var eb FixErrorBody
	if err := json.Unmarshal([]byte(body), &eb); err != nil || eb.Code != "fix.err.stale_proposal" || eb.Error != i18n.T(i18n.FR, "fix.err.stale_proposal") {
		t.Errorf("stale body = %s", body)
	}
	if code, body := ff.send("POST", "/api/v1/fix/"+id+"/approve", `{}`); code != http.StatusBadRequest {
		t.Errorf("approve without hash = %d %s", code, body)
	}
	a, err := fix.NewRepo(ff.st).GetAttempt(context.Background(), id)
	if err != nil || a.State != fix.StateProposed || a.ApprovedBy != "" {
		t.Errorf("attempt after stale approve = %+v %v", a, err)
	}
	if code, _ := ff.send("POST", "/api/v1/fix/nope/approve", `{"hash":"x"}`); code != http.StatusNotFound {
		t.Errorf("unknown attempt = %d", code)
	}
}

func TestFixResponsesHaveNoAbsolutePaths(t *testing.T) {
	ff := newFixFixture(t)
	var bodies []string
	keep := func(_ int, b string) { bodies = append(bodies, b) }
	fid := ff.ids["ACME-2026-0001"]
	for _, lang := range []string{"en", "fr"} {
		keep(ff.send("POST", "/api/v1/findings/"+fid+"/fix?lang="+lang, ""))
		keep(ff.send("GET", "/api/v1/projects/demo/ai-consent?lang="+lang, ""))
	}
	ff.consent()
	a, ag := ff.start()
	ch, _, cancel := openStream(t, ff.srv, a.ID, "")
	defer cancel()
	ag.emit(agent.Event{Kind: agent.KindTool, Tool: "Read", Text: filepath.Join(ff.dir, "worktrees", "x", "composer.json")})
	ag.emit(agent.Event{Kind: agent.KindText, Text: "Copy in " + ff.dir})
	_, seen := waitEvent(t, ch, func(e sseEvent) bool { return strings.Contains(e.data, "Copy in") })
	for _, e := range seen {
		bodies = append(bodies, e.data)
	}
	id, hash := ff.seedProposed()
	for _, lang := range []string{"en", "fr"} {
		q := "?lang=" + lang
		for _, path := range []string{"/api/v1/fix/" + a.ID, "/api/v1/fix/" + id, "/api/v1/fixes", "/api/v1/agent/status",
			"/api/v1/projects/demo/ai-consent", "/api/v1/fix/nope"} {
			keep(ff.send("GET", path+q, ""))
		}
		keep(ff.send("POST", "/api/v1/fix/"+a.ID+"/message"+q, `{"text":"hello"}`))
		keep(ff.send("POST", "/api/v1/fix/"+id+"/approve"+q, `{"hash":"stale"}`))
		keep(ff.send("POST", "/api/v1/findings/"+fid+"/fix"+q, ""))
	}
	// Approving the seeded proposal fails to apply (no copy): the error
	// names no folder either.
	keep(ff.send("POST", "/api/v1/fix/"+id+"/approve", `{"hash":"`+hash+`"}`))
	keep(ff.send("GET", "/api/v1/fix/"+id, ""))
	reason, _ := json.Marshal(map[string]string{"reason": "see " + ff.proj.Path})
	keep(ff.send("POST", "/api/v1/fix/"+a.ID+"/refuse", string(reason)))
	keep(ff.send("GET", "/api/v1/fix/"+a.ID, ""))
	keep(ff.send("POST", "/api/v1/fix/"+a.ID+"/message", `{"text":"hello"}`))

	banned := []string{ff.proj.Path, filepath.ToSlash(ff.proj.Path), strings.ReplaceAll(ff.proj.Path, `\`, `\\`),
		ff.dir, filepath.ToSlash(ff.dir), strings.ReplaceAll(ff.dir, `\`, `\\`), "worktrees", "fix-mirrors", "http://michel:",
		"fix-token", testCmdMarker, installCmdMarker, testToken, "clone_dir", "michel mcp"}
	for _, body := range bodies {
		for _, s := range banned {
			if strings.Contains(body, s) {
				t.Errorf("response contains %q:\n%s", s, body)
			}
		}
	}
	if len(bodies) < 30 {
		t.Errorf("only %d responses checked", len(bodies))
	}
}

// TestRefusalsAreTranslated: every refusal of the fix service reaches the
// page as a sentence in the request's language with its own status.
func TestRefusalsAreTranslated(t *testing.T) {
	errs := []error{fix.ErrNotGit, fix.ErrConsentRequired, fix.ErrHealthForbidden, fix.ErrStrictLocal, fix.ErrAgentUnavailable,
		&fix.AgentUnavailableError{Status: agent.Status{Hint: agent.HintNotInstalled}}, fix.ErrBusy, fix.ErrStaleProposal,
		fix.ErrMaskToken, fix.ErrNoChange, fix.ErrNoProposal, fix.ErrAgentGone, fix.ErrChangeRefused, fix.ErrBadTransition, fix.ErrNotFound}
	for _, err := range errs {
		key := fix.ErrorKey(err)
		if key == "" {
			t.Errorf("%v has no key", err)
			continue
		}
		status, ok := fixStatus[key]
		if !ok || status < 400 || status >= 500 && status != http.StatusServiceUnavailable {
			t.Errorf("%s: status %d", key, status)
		}
		en, fr := fix.Explain(i18n.EN, err), fix.Explain(i18n.FR, err)
		if en == "" || fr == "" || en == fr || strings.Contains(en, key) || strings.Contains(fr, key) {
			t.Errorf("%s: EN %q FR %q", key, en, fr)
		}
	}
	if len(fixStatus) != len(errs)-1 {
		t.Errorf("fixStatus maps %d keys, the service has %d refusals", len(fixStatus), len(errs)-1)
	}
}

// TestWorkerSeesConsentGivenAfterStart: the level 2 queue of serve works
// with the policy in force, so a consent given on the page after the start
// lets the next automatic attempt start (no restart needed).
func TestWorkerSeesConsentGivenAfterStart(t *testing.T) {
	fid := ""
	ff := newFixFixture(t, func(ff *fixFixture) {
		ff.deps.FixWorker = true
		ff.fd.WorkerInterval = 20 * time.Millisecond
		fid = ff.ids["ACME-2026-0001"]
		if err := fix.NewRepo(ff.st).Enqueue(context.Background(), fid, ff.proj.ID); err != nil {
			t.Fatal(err)
		}
	})
	// Before the consent: the automatic start is refused, and audited.
	deadline := time.Now().Add(10 * time.Second)
	for len(ff.auditRows("fix.start")) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the worker made no attempt")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if rows := ff.auditRows("fix.start"); rows[0].evidence["reason"] != "fix.err.consent_required" {
		t.Fatalf("first automatic start = %+v", rows[0])
	}
	ff.consent()
	if err := fix.NewRepo(ff.st).Enqueue(context.Background(), fid, ff.proj.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ff.agents:
	case <-time.After(10 * time.Second):
		t.Fatalf("the worker did not start the attempt after the consent: %+v", ff.auditRows("fix.start"))
	}
	list, err := fix.NewRepo(ff.st).ListAttempts(context.Background(), ff.proj.ID, "")
	if err != nil || len(list) != 1 || list[0].Origin != fix.OriginAgentAuto {
		t.Errorf("attempts = %+v %v", list, err)
	}
}

// TestProposalViewCarriesVersions: the proposal names the versions it moves
// the package between, in the attempt's view and in the list.
func TestProposalViewCarriesVersions(t *testing.T) {
	ff := newFixFixture(t)
	id, _ := ff.seedProposed()
	resp, body := ff.do("GET", "/api/v1/fix/"+id, testToken, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attempt = %d %s", resp.StatusCode, body)
	}
	var v AttemptView
	if err := json.Unmarshal([]byte(body), &v); err != nil || v.Proposal == nil {
		t.Fatalf("attempt body: %v %s", err, body)
	}
	if v.Proposal.FromVersion != "1.0.0" || v.Proposal.ToVersion != "1.2.5" {
		t.Errorf("versions = %q -> %q", v.Proposal.FromVersion, v.Proposal.ToVersion)
	}
	resp, body = ff.do("GET", "/api/v1/fixes?state=proposed", testToken, "")
	var list []AttemptView
	if err := json.Unmarshal([]byte(body), &list); err != nil || resp.StatusCode != http.StatusOK || len(list) != 1 || list[0].Proposal == nil ||
		list[0].Proposal.ToVersion != "1.2.5" {
		t.Errorf("list = %d %s", resp.StatusCode, body)
	}
}

// TestFailedCauseIsPlainWithDetailApart: the cause of a failed attempt is
// the plain sentence; the technical detail comes apart, without any path.
func TestFailedCauseIsPlainWithDetailApart(t *testing.T) {
	ff := newFixFixture(t)
	id, _ := ff.seedProposed()
	repo := fix.NewRepo(ff.st)
	ctx := context.Background()
	cause := i18n.T(i18n.FR, "fix.cause.git_failed")
	if err := repo.SetState(ctx, id, []fix.State{fix.StateProposed}, fix.StateFailed, cause); err != nil {
		t.Fatal(err)
	}
	detail := `git clone failed: exit status 128 (fatal: failed to unlink 'C:\Users\demo\AppData\michel\worktrees\x': Filename too long) /home/demo/.local/michel/x`
	if err := repo.SetCauseDetail(ctx, id, detail); err != nil {
		t.Fatal(err)
	}
	resp, body := ff.do("GET", "/api/v1/fix/"+id+"?lang=fr", testToken, "")
	var v AttemptView
	if err := json.Unmarshal([]byte(body), &v); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("attempt = %d %s", resp.StatusCode, body)
	}
	if v.Cause != cause || strings.Contains(v.Cause, "git clone") {
		t.Errorf("cause = %q", v.Cause)
	}
	if !strings.Contains(v.CauseDetail, "Filename too long") || strings.Contains(v.CauseDetail, `Users\demo`) || strings.Contains(v.CauseDetail, "/home/demo") {
		t.Errorf("cause detail = %q", v.CauseDetail)
	}
}
