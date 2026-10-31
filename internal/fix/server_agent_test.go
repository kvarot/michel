package fix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/agent"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/target"
)

// serverAgent is the fake Claude Code of the server tests: act runs once
// the session starts, with the attempt id; the session then ends.
type serverAgent struct {
	mu      sync.Mutex
	started int
	specs   []agent.Spec
	act     func(ctx context.Context, d Deps, attemptID string)
	acting  sync.WaitGroup
}

// withAgent gives the fixture what an agent attempt needs: a policy file
// (the SSH rule of the test servers only), its reload, the gateway, a data
// folder and the fake agent.
func (f *serverFixture) withAgent(act func(ctx context.Context, d Deps, attemptID string)) *serverAgent {
	f.t.Helper()
	dir := f.t.TempDir()
	data := f.t.TempDir()
	path := policyFile(f.t, dir, "sovereignty:\n  mode: standard\n  data_classification: sensitive\n  network:\n    default_egress: deny\n    allow:\n"+
		"      - host: 127.0.0.1\n        purpose: "+policy.PurposeTargetSSH+"\n")
	pol, _, err := policy.Load(path, data)
	if err != nil {
		f.t.Fatal(err)
	}
	f.gw.SetRules(pol.Sovereignty.Network.Allow)
	sa := &serverAgent{act: act}
	f.d.Policy, f.d.PolicyPath, f.d.DataDir, f.d.Gateway = pol, path, data, f.gw
	f.d.Reload = func() (policy.Policy, error) {
		p, _, err := policy.Load(path, data)
		if err == nil {
			err = policy.Validate(p)
		}
		return p, err
	}
	f.d.AgentStatus = func(context.Context) agent.Status {
		return agent.Status{Installed: true, LoggedIn: true, Version: "2.1.314"}
	}
	f.d.MCPCommand = []string{"michel", "mcp"}
	f.d.Timeout = time.Minute
	f.d.PollInterval = 20 * time.Millisecond
	f.d.Agent = func(ctx context.Context, ad agent.Deps, s agent.Spec) (Session, error) {
		sa.mu.Lock()
		sa.started++
		sa.specs = append(sa.specs, s)
		act := sa.act
		sa.mu.Unlock()
		sess := &fakeSession{events: make(chan agent.Event, 16)}
		sa.acting.Add(1)
		go func() {
			defer sa.acting.Done()
			if act != nil {
				act(ctx, f.d, s.MCPEnv[EnvAttempt])
			}
			sess.emit(agent.Event{Kind: agent.KindDone})
			sess.Close()
		}()
		return sess, nil
	}
	return sa
}

// consent gives the server's AI consent.
func (f *serverFixture) consent(s *demoServer) {
	f.t.Helper()
	if err := GiveServerConsent(context.Background(), f.d, s.t.ID); err != nil {
		f.t.Fatalf("GiveServerConsent: %v", err)
	}
	p, err := f.d.Reload()
	if err != nil {
		f.t.Fatal(err)
	}
	f.d.Policy = p
}

// wait waits for the session of the attempt to end.
func (f *serverFixture) wait(sa *serverAgent, id string) {
	f.t.Helper()
	sa.acting.Wait()
	if !f.d.sessions().Wait(id, 5*time.Second) {
		f.t.Fatal("the session did not end")
	}
}

func TestHealthTargetRefusesAgent(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	sa := f.withAgent(nil)
	hds := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) {
		tg.Kind, tg.Classification = target.KindHDS, policy.ClassHealth
	})
	vps := f.addServer("srv-demo-2", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) {
		tg.Classification = policy.ClassHealth
	})
	for _, s := range []*demoServer{hds, vps} {
		f.mustCheck(s)
		if err := GiveServerConsent(ctx, f.d, s.t.ID); !errors.Is(err, ErrHealthForbidden) {
			t.Errorf("%s: GiveServerConsent = %v, want ErrHealthForbidden", s.t.Name, err)
		}
		// A consent row written by any other way does not open the door.
		if err := f.d.repo().SetConsent(ctx, serverConsentKey(s.t.ID), AgentHosts); err != nil {
			t.Fatal(err)
		}
		if _, err := StartServerAgent(ctx, f.d, f.finding(s, "expose_php").ID); !errors.Is(err, ErrHealthForbidden) {
			t.Errorf("%s: StartServerAgent = %v, want ErrHealthForbidden", s.t.Name, err)
		}
		if got := ServerConsentNeeded(s.t, f.d.Policy, true); len(got) == 0 || got[0].What != "fix.consent.server_health" {
			t.Errorf("%s: consent screen = %+v", s.t.Name, got)
		}
	}
	if sa.started != 0 {
		t.Fatalf("an agent was started for a health server (%d)", sa.started)
	}
	// An agent attempt made by hand still gets no proposal.
	a, err := f.d.repo().CreateAttempt(ctx, Attempt{FindingID: f.finding(vps, "expose_php").ID, ProjectID: vps.t.ID, Origin: OriginAgent,
		Work: Work{Server: &ServerWork{TargetID: vps.t.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	in := ServerProposeInput{Summary: "x", Actions: []ServerActionInput{{Op: "set_directive", Directive: "expose_php", Value: "0", SAPI: "fpm"}}}
	if _, err := ProposeServer(ctx, f.d, a.ID, in); !errors.Is(err, ErrHealthForbidden) {
		t.Errorf("ProposeServer on a health server = %v", err)
	}
	if err := f.d.repo().SetState(ctx, a.ID, []State{StatePreparing}, StateFailed, "test"); err != nil {
		t.Fatal(err)
	}
	// Michel's own fixes stay allowed on a health server.
	got, err := StartServer(ctx, f.d, f.finding(hds, "expose_php").ID)
	if err != nil || got.State != StateProposed {
		t.Fatalf("StartServer on hds: %v %+v", err, got)
	}
}

func TestProposeServerRejectsHostileAction(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	type try struct {
		in   ServerProposeInput
		prop Proposal
		err  error
		// proposed tells whether a proposal existed right after the call.
		proposed bool
	}
	var tries []try
	hostile := []ServerProposeInput{
		{Summary: "outside the inventory", Actions: []ServerActionInput{{Op: "set_directive", Path: "/etc/ssh/sshd_config", Directive: "expose_php", Value: "0", SAPI: "fpm"}}},
		{Summary: "a new line in the value", Actions: []ServerActionInput{{Op: "set_directive", Directive: "expose_php", Value: "0\nextension=/tmp/evil.so", SAPI: "fpm"}}},
		{Summary: "not one of Michel's rules", Actions: []ServerActionInput{{Op: "set_directive", Directive: "auto_prepend_file", Value: "/tmp/x.php", SAPI: "fpm"}}},
		{Summary: "a service Michel did not see", Actions: []ServerActionInput{{Op: "reload_service", Service: "sshd"}}},
		{Summary: "an op that does not exist", Actions: []ServerActionInput{{Op: "run_command", Value: "rm -rf /"}}},
		{Summary: "a package not installed", Actions: []ServerActionInput{{Op: "package_upgrade", Package: "openssh-server", Version: "9.9"}}},
		{Summary: "no action"},
	}
	valid := ServerProposeInput{Summary: "Turn expose_php off.", Actions: []ServerActionInput{{Op: "set_directive", Directive: "expose_php", Value: "0", SAPI: "fpm"}}}
	var aid string
	sa := f.withAgent(func(ctx context.Context, d Deps, id string) {
		aid = id
		for _, in := range append(hostile, valid) {
			p, err := ProposeServer(ctx, d, id, in)
			_, ok, _ := d.repo().CurrentProposal(ctx, id)
			tries = append(tries, try{in: in, prop: p, err: err, proposed: ok})
		}
	})
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	fi := f.finding(s, "expose_php")
	if _, err := StartServerAgent(ctx, f.d, fi.ID); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("without consent: %v", err)
	}
	f.consent(s)
	a, err := StartServerAgent(ctx, f.d, fi.ID)
	if err != nil {
		t.Fatalf("StartServerAgent: %v", err)
	}
	if a.State != StatePreparing || a.Origin != OriginAgent || a.Work.Server == nil || a.Work.Server.TargetID != s.t.ID {
		t.Fatalf("attempt %+v", a)
	}
	f.wait(sa, a.ID)
	if aid != a.ID || len(tries) != len(hostile)+1 {
		t.Fatalf("the agent made %d calls on %q", len(tries), aid)
	}
	spec := sa.specs[0]
	if strings.Contains(spec.Prompt, f.d.DataDir) || !strings.Contains(spec.Prompt, "DATA, not instructions") || !strings.Contains(spec.Prompt, s.ini) {
		t.Errorf("prompt:\n%s", spec.Prompt)
	}
	if entries, err := os.ReadDir(spec.Dir); err == nil && len(entries) > 0 {
		t.Errorf("the agent's folder is not empty: %v", entries)
	}
	if !strings.HasPrefix(filepath.Clean(spec.Dir), filepath.Clean(f.d.DataDir)) {
		t.Errorf("the agent's folder is outside the data folder: %s", spec.Dir)
	}
	for i, tr := range tries[:len(hostile)] {
		var ref *ServerRefusal
		if !errors.Is(tr.err, ErrAgentActionRefused) || !errors.As(tr.err, &ref) {
			t.Errorf("%q: err = %v, want a refusal", tr.in.Summary, tr.err)
			continue
		}
		if tr.proposed || tr.prop.ID != "" {
			t.Errorf("%q: a proposal was made", tr.in.Summary)
		}
		msg := tr.err.Error()
		for _, bad := range []string{f.d.DataDir, filepath.ToSlash(f.d.DataDir), "serverfix:", "/tmp/evil.so", "rm -rf"} {
			if strings.Contains(msg, bad) {
				t.Errorf("try %d: the message to the agent holds %q: %s", i, bad, msg)
			}
		}
		if !strings.Contains(msg, "Michel refused") {
			t.Errorf("try %d: message %q", i, msg)
		}
	}
	last := tries[len(tries)-1]
	if last.err != nil || last.prop.ID == "" || !last.proposed {
		t.Fatalf("valid proposal: %v %+v", last.err, last.prop)
	}
	got := f.attempt(a.ID)
	if got.State != StateProposed || got.ApprovedBy != "" {
		t.Fatalf("attempt after the valid proposal: %+v", got)
	}
	p := f.proposal(a.ID)
	if p.Scripts == nil || p.Server == nil || p.Hash != serverHash(p.Scripts.Hash, *p.Server) || p.Summary != "Turn expose_php off." {
		t.Fatalf("proposal %+v", p)
	}
	if len(p.Server.Requested) != 1 || p.Server.Requested[0].Key != "" {
		t.Errorf("requested actions %+v", p.Server.Requested)
	}
	msgs, err := f.d.repo().ListMessages(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	refusals := 0
	for _, m := range msgs {
		if m.Role == RoleMichel && strings.Contains(m.Text, "refused an action") {
			refusals++
		}
	}
	if refusals != len(hostile) {
		t.Errorf("%d refusals told in the conversation, want %d: %+v", refusals, len(hostile), msgs)
	}
	// The agent's proposal goes through the same approval and run as
	// Michel's own; nothing was sent before.
	if sent(s) != 0 {
		t.Fatal("a script was sent before the approval")
	}
	if err := Approve(ctx, f.d, a.ID, p.Hash); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, f.d, a.ID); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed {
		t.Fatalf("after apply: %s %s", got.State, got.Cause)
	}
	if !strings.Contains(file(t, s, s.ini), "expose_php = 0") {
		t.Errorf("php.ini:\n%s", file(t, s, s.ini))
	}
}

func TestAutoApplicableServerRules(t *testing.T) {
	ini := "/etc/php/8.2/fpm/php.ini"
	base := func() (target.Target, serverfix.Plan) {
		tg := target.Target{ID: "T1", Kind: target.KindVPS, Env: target.EnvProd, FixLevel: 3, AutoConfig: true, Executor: target.ExecMichel,
			Sudo: target.SudoNopasswd, SiteURL: "https://srv-demo.example.test", Active: true}
		p := serverfix.Plan{TargetID: "T1", FindingID: "F1", Actions: []serverfix.Action{
			{Op: serverfix.OpBackup, Path: ini},
			{Op: serverfix.OpSetDirective, Path: ini, Directive: "expose_php", Value: "0", SAPI: "fpm", Key: "expose_php", Line: 3},
			{Op: serverfix.OpTestConfig, SAPI: "fpm", Binary: "/usr/sbin/php-fpm8.2"},
			{Op: serverfix.OpReload, Service: "php8.2-fpm", Manager: "systemctl"},
			{Op: serverfix.OpCheckSite},
		}}
		return tg, p
	}
	if tg, p := base(); !AutoApplicableServer(tg, p, OriginServer, false) {
		t.Fatal("the base case must be applicable")
	}
	if tg, p := base(); !AutoApplicableServer(tg, p, OriginManual, false) {
		t.Fatal("a manual origin is Michel's own")
	}
	for _, c := range []struct {
		name   string
		origin string
		proven bool
		mod    func(*target.Target, *serverfix.Plan)
	}{
		{name: "level 2", mod: func(tg *target.Target, _ *serverfix.Plan) { tg.FixLevel = 2 }},
		{name: "rule not checked", mod: func(tg *target.Target, _ *serverfix.Plan) { tg.AutoConfig = false }},
		{name: "executor user", mod: func(tg *target.Target, _ *serverfix.Plan) { tg.Executor = target.ExecUser }},
		{name: "inactive", mod: func(tg *target.Target, _ *serverfix.Plan) { tg.Active = false }},
		{name: "agent origin", origin: OriginAgent},
		{name: "agent auto origin", origin: OriginAgentAuto},
		{name: "unknown origin", origin: "someone"},
		{name: "no site", mod: func(tg *target.Target, _ *serverfix.Plan) { tg.SiteURL = "" }},
		{name: "preprod not proven", mod: func(tg *target.Target, _ *serverfix.Plan) { tg.PreprodID = "T0" }},
		{name: "root without sudo", mod: func(tg *target.Target, _ *serverfix.Plan) { tg.Sudo = target.SudoNone }},
		{name: "package upgrade", mod: func(_ *target.Target, p *serverfix.Plan) {
			p.Actions = append(p.Actions, serverfix.Action{Op: serverfix.OpPackageUpgrade, Package: "libdemo", Version: "1.1-1", Manager: "apt"})
		}},
		{name: "needs snapshot", mod: func(_ *target.Target, p *serverfix.Plan) { p.NeedsSnapshot = true }},
		{name: "value not advised", mod: func(_ *target.Target, p *serverfix.Plan) { p.Actions[1].Value = "Off" }},
		{name: "directive not a rule", mod: func(_ *target.Target, p *serverfix.Plan) {
			p.Actions[1].Directive, p.Actions[1].Key = "memory_limit", "memory_limit"
		}},
		{name: "rule without advised value", mod: func(_ *target.Target, p *serverfix.Plan) {
			p.Actions[1].Directive, p.Actions[1].Key, p.Actions[1].Value = "open_basedir", "open_basedir", "/var/www"
		}},
		{name: "no config test", mod: func(_ *target.Target, p *serverfix.Plan) { p.Actions = append(p.Actions[:2], p.Actions[3:]...) }},
		{name: "no site check", mod: func(_ *target.Target, p *serverfix.Plan) { p.Actions = p.Actions[:4] }},
		{name: "unknown op", mod: func(_ *target.Target, p *serverfix.Plan) { p.Actions = append(p.Actions, serverfix.Action{Op: "run"}) }},
		{name: "no change", mod: func(_ *target.Target, p *serverfix.Plan) {
			p.Actions = []serverfix.Action{{Op: serverfix.OpTestConfig, SAPI: "fpm"}, {Op: serverfix.OpCheckSite}}
		}},
	} {
		tg, p := base()
		if c.mod != nil {
			c.mod(&tg, &p)
		}
		origin := c.origin
		if origin == "" {
			origin = OriginServer
		}
		if AutoApplicableServer(tg, p, origin, c.proven) {
			t.Errorf("%s: applicable", c.name)
		}
	}
	tg, p := base()
	tg.PreprodID = "T0"
	if !AutoApplicableServer(tg, p, OriginServer, true) {
		t.Error("a proven preprod opens the production")
	}
}

func TestLevel2QueuesServerFindings(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	low := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	s := f.addServer("srv-demo-2", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) { tg.FixLevel = 2 })
	f.mustCheck(low)
	f.mustCheck(s)
	if n, err := QueueEligibleServer(ctx, f.d, low.t.ID); err != nil || n != 0 {
		t.Fatalf("level 1 queued %d (%v)", n, err)
	}
	fi := f.finding(s, "expose_php")
	if !EligibleServer(fi, s.t, nil) {
		t.Fatal("an open finding of a level 2 server is eligible")
	}
	for name, c := range map[string]struct {
		f   scan.Finding
		t   target.Target
		dec string
	}{
		"level 1":  {fi, low.t, ""},
		"gone":     {func() scan.Finding { g := fi; g.Status = scan.StatusGone; return g }(), s.t, ""},
		"code":     {func() scan.Finding { g := fi; g.Kind = scan.KindDependency; return g }(), s.t, ""},
		"inactive": {fi, func() target.Target { x := s.t; x.Active = false; return x }(), ""},
		"deferred": {fi, s.t, "defer"},
		"ignored":  {fi, s.t, "ignore"},
	} {
		dec := c.dec
		if EligibleServer(c.f, c.t, func(string) string { return dec }) {
			t.Errorf("%s: eligible", name)
		}
	}
	n, err := QueueEligibleServer(ctx, f.d, s.t.ID)
	if err != nil || n == 0 {
		t.Fatalf("level 2 queued %d (%v)", n, err)
	}
	started, err := WorkOnce(ctx, f.d)
	if err != nil || !started {
		t.Fatalf("WorkOnce: %v %v", started, err)
	}
	list, err := f.d.repo().ListAttempts(ctx, s.t.ID, "")
	if err != nil || len(list) != 1 {
		t.Fatalf("attempts %+v %v", list, err)
	}
	a := list[0]
	if a.State != StateProposed || a.Origin != OriginServer || a.Work.Server == nil {
		t.Fatalf("attempt %+v", a)
	}
	// Level 2 prepares and waits: nothing runs alone.
	if n, err := ApplyAutoServer(ctx, f.d); err != nil || n != 0 {
		t.Fatalf("ApplyAutoServer at level 2: %d %v", n, err)
	}
	if sent(s) != 0 || f.attempt(a.ID).State != StateProposed {
		t.Fatal("a level 2 fix ran alone")
	}
	// A finding already tried is not queued again.
	before, _ := f.d.repo().CountQueued(ctx, s.t.ID)
	if _, err := QueueEligibleServer(ctx, f.d, s.t.ID); err != nil {
		t.Fatal(err)
	}
	after, _ := f.d.repo().CountQueued(ctx, s.t.ID)
	if after > before {
		t.Errorf("queue grew from %d to %d with the same findings", before, after)
	}
	for _, x := range f.queued(t) {
		if x == a.FindingID {
			t.Error("the finding with an attempt is queued again")
		}
	}
}

// queued lists the findings in the queue.
func (f *serverFixture) queued(t *testing.T) []string {
	t.Helper()
	rows, err := f.st.DB().Query(`SELECT finding_id FROM fix_queue`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

func TestLevel3AppliesConfigFixAlone(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) {
		tg.FixLevel, tg.AutoConfig = 3, true
	})
	f.mustCheck(s)
	a, err := StartServer(ctx, f.d, f.finding(s, "expose_php").ID)
	if err != nil {
		t.Fatal(err)
	}
	// An attempt whose state is unknown on the server stops every fix that
	// would run alone.
	other, err := f.d.repo().CreateAttempt(ctx, Attempt{FindingID: "Fx", ProjectID: "elsewhere", Origin: OriginServer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DB().Exec(`UPDATE fix_attempt SET project_id = ?, state = ? WHERE id = ?`, s.t.ID, string(StateUnknown), other.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := ApplyAutoServer(ctx, f.d); err != nil || n != 0 || sent(s) != 0 {
		t.Fatalf("applied %d (%v) with an unknown attempt on the server", n, err)
	}
	if _, err := f.st.DB().Exec(`UPDATE fix_attempt SET state = ? WHERE id = ?`, string(StateFailed), other.ID); err != nil {
		t.Fatal(err)
	}
	n, err := ApplyAutoServer(ctx, f.d)
	if err != nil || n != 1 {
		t.Fatalf("ApplyAutoServer: %d %v", n, err)
	}
	got := f.attempt(a.ID)
	if got.State != StateProvenFixed || got.ApprovedBy != ActorAuto {
		t.Fatalf("attempt %s by %q (%s)", got.State, got.ApprovedBy, got.Cause)
	}
	auto := 0
	for _, al := range f.alerts {
		if al.Kind == servercheck.AlertAppliedAuto && al.Target.ID == s.t.ID {
			auto++
		}
	}
	if auto != 1 {
		t.Errorf("applied_auto alerts: %d (%+v)", auto, f.alerts)
	}
	// The rule unchecked: nothing more runs alone.
	f2 := newServerFixture(t)
	s2 := f2.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) { tg.FixLevel = 3 })
	f2.mustCheck(s2)
	if _, err := StartServer(ctx, f2.d, f2.finding(s2, "expose_php").ID); err != nil {
		t.Fatal(err)
	}
	if n, err := ApplyAutoServer(ctx, f2.d); err != nil || n != 0 || sent(s2) != 0 {
		t.Fatalf("applied %d (%v) without the rule", n, err)
	}
}

func TestPackageUpgradeNeverAuto(t *testing.T) {
	ctx := context.Background()
	f := newServerFixture(t)
	f.pkgFinding = true
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, func(tg *target.Target) {
		tg.FixLevel, tg.AutoConfig = 3, true
	})
	s.sim = "Inst libdemo [1.0-1] (1.1-1 Debian:12/stable [amd64])\n"
	f.mustCheck(s)
	var pf scan.Finding
	list, err := scan.NewRepo(f.st).ListServerFindings(ctx, s.t.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range list {
		if x.Kind == scan.KindServerPackage && x.OSVID == "DSA-DEMO-1" {
			pf = x
		}
	}
	if pf.ID == "" {
		t.Fatal("no package finding")
	}
	a, err := StartServer(ctx, f.d, pf.ID)
	if err != nil {
		t.Fatal(err)
	}
	p := f.proposal(a.ID)
	if p.Server == nil || !p.Server.NeedsSnapshot {
		t.Fatalf("proposal %+v", p.Server)
	}
	plan := serverfix.Plan{TargetID: s.t.ID, FindingID: pf.ID, Actions: p.Server.Actions, NeedsSnapshot: true}
	for _, origin := range []string{OriginServer, OriginManual} {
		if AutoApplicableServer(s.t, plan, origin, true) {
			t.Errorf("a package upgrade is applicable alone (%s)", origin)
		}
	}
	// Even with the snapshot acknowledged, nothing runs alone.
	if err := SnapshotDone(ctx, f.d, a.ID, "test"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if n, err := ApplyAutoServer(ctx, f.d); err != nil || n != 0 {
			t.Fatalf("ApplyAutoServer: %d %v", n, err)
		}
	}
	if got := f.attempt(a.ID); got.State != StateProposed || got.ApprovedBy != "" {
		t.Fatalf("attempt %s by %q", got.State, got.ApprovedBy)
	}
	for _, l := range s.srv.Log() {
		if strings.Contains(l, "--only-upgrade") && !strings.Contains(l, "-s") {
			t.Errorf("the package was upgraded: %s", l)
		}
	}
	if sent(s) != 0 || s.pkgVer != "1.0-1" {
		t.Fatalf("sent %d, package %s", sent(s), s.pkgVer)
	}
	// The worker does not apply it either.
	if _, err := QueueEligibleServer(ctx, f.d, s.t.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := WorkOnce(ctx, f.d); err != nil {
			t.Fatal(err)
		}
		if _, err := ApplyAutoServer(ctx, f.d); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.attempt(a.ID); got.State != StateProposed || s.pkgVer != "1.0-1" {
		t.Fatalf("after the worker: %s, package %s", got.State, s.pkgVer)
	}
}
