package target

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/store"
)

// zwsp is an invisible character a name may not hold.
const zwsp = string(rune(0x200b))

type regFixture struct {
	st         *store.Store
	repo       *Repo
	policyPath string
	gw         *egress.Gateway
	reloads    int
}

func newRegFixture(t *testing.T) *regFixture {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return &regFixture{st: s, repo: NewRepo(s), policyPath: filepath.Join(dir, "config.yaml"), gw: egress.New(policy.Defaults(), nil)}
}

// deps are the shared dependencies; the policy in force is the one of the
// start, without what was written in the file since.
func (f *regFixture) deps() Deps {
	return Deps{Repo: f.repo, Audit: audit.NewLogger(f.st, time.Now), Actor: "test", PolicyPath: f.policyPath,
		Reload: func() (policy.Policy, error) {
			f.reloads++
			p, _, err := policy.Load(f.policyPath, "")
			if err == nil {
				err = policy.Validate(p)
			}
			return p, err
		},
		Current: policy.Defaults, Gateway: f.gw}
}

func (f *regFixture) policyText() string {
	b, _ := os.ReadFile(f.policyPath)
	return string(b)
}

func (f *regFixture) addRows(t *testing.T) []map[string]any {
	t.Helper()
	rs, err := f.st.DB().Query(`SELECT actor, result, evidence FROM audit_event WHERE action = 'target.add' ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []map[string]any
	for rs.Next() {
		var actor, result, ev string
		if err := rs.Scan(&actor, &result, &ev); err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		if err := json.Unmarshal([]byte(ev), &m); err != nil {
			t.Fatal(err)
		}
		m["_actor"], m["_result"] = actor, result
		out = append(out, m)
	}
	return out
}

func TestChangeRulesKeepsARuleWrittenByHandSinceTheStart(t *testing.T) {
	f := newRegFixture(t)
	ctx := context.Background()
	hand := policy.AllowRule{Host: "192.0.2.95", Purpose: policy.PurposeTargetSSH}
	// Written in the file after the policy in force was read.
	if _, err := policy.AddAllowRules(f.policyPath, hand); err != nil {
		t.Fatal(err)
	}
	site := policy.AllowRule{Host: "www.example.test", Purpose: policy.PurposeTargetHTTP}
	added, _, err := ChangeRules(ctx, f.deps(), []policy.AllowRule{hand, site}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0] != site {
		t.Fatalf("added = %+v, want only the site rule", added)
	}
	if ok, _ := f.gw.Allowed("www.example.test", policy.PurposeTargetHTTP); !ok {
		t.Error("the gateway did not learn the new rule")
	}
	_, removed, err := ChangeRules(ctx, f.deps(), nil, []policy.AllowRule{hand, site})
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != site {
		t.Errorf("removed = %+v, want only the site rule", removed)
	}
	if text := f.policyText(); !strings.Contains(text, "192.0.2.95") || strings.Contains(text, "www.example.test") {
		t.Errorf("policy file:\n%s", text)
	}
}

func TestChangeRulesDoesNothingWithoutAPolicyFile(t *testing.T) {
	f := newRegFixture(t)
	d := f.deps()
	d.PolicyPath = ""
	added, removed, err := ChangeRules(context.Background(), d, []policy.AllowRule{{Host: "192.0.2.5", Purpose: policy.PurposeTargetSSH}}, nil)
	if err != nil || added != nil || removed != nil || f.reloads != 0 {
		t.Fatalf("added %v removed %v err %v reloads %d", added, removed, err, f.reloads)
	}
	if _, err := os.Stat(f.policyPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a policy file was written: %v", err)
	}
}

func TestRegisterDefaultsTrimsAndAudits(t *testing.T) {
	f := newRegFixture(t)
	got, err := Register(context.Background(), f.deps(), RegisterRequest{Alias: " web-demo ", Host: " 192.0.2.20 ", User: " deploy ",
		Env: EnvProd, Classification: policy.ClassSensitive, AutoConfig: true, SiteURL: " https://www.example.test/ "})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "web-demo" || got.Alias != "web-demo" || got.Host != "192.0.2.20" || got.User != "deploy" || got.Kind != KindVPS ||
		got.FixLevel != 1 || got.CheckInterval != 0 || got.Classification != policy.ClassSensitive || !got.AutoConfig ||
		got.SiteURL != "https://www.example.test/" {
		t.Errorf("added = %+v", got)
	}
	if text := f.policyText(); !strings.Contains(text, "192.0.2.20") || !strings.Contains(text, "www.example.test") {
		t.Errorf("rules not written:\n%s", text)
	}
	rows := f.addRows(t)
	want := map[string]any{"_actor": "test", "_result": "ok", "name": "web-demo", "kind": "vps", "env": "prod",
		"fix_level": float64(1), "links": float64(0), "rules_written": float64(2)}
	if len(rows) != 1 || len(rows[0]) != len(want) {
		t.Fatalf("audit = %+v", rows)
	}
	for k, v := range want {
		if rows[0][k] != v {
			t.Errorf("audit %s = %v, want %v", k, rows[0][k], v)
		}
	}
}

func TestRegisterChecksInOneOrder(t *testing.T) {
	f := newRegFixture(t)
	ctx := context.Background()
	zero := 0
	for _, c := range []struct {
		req  RegisterRequest
		want error
	}{
		{RegisterRequest{Host: "192.0.2.5", User: "  "}, ErrEmptyUser},
		// The fields are checked before the interval, the interval before the preprod.
		{RegisterRequest{Host: "192.0.2.5", Name: "a" + zwsp + "b", User: "d", CheckInterval: "soon"}, ErrEmptyName},
		{RegisterRequest{Host: "192.0.2.5", User: "d", CheckInterval: "soon", Preprod: "nowhere"}, ErrInvalidInterval},
		{RegisterRequest{Host: "192.0.2.5", User: "d", Preprod: "nowhere"}, ErrPreprodNotFound},
		{RegisterRequest{Host: "192.0.2.5", User: "d", FixLevel: &zero, Kind: "castle"}, ErrInvalidKind},
	} {
		if _, err := Register(ctx, f.deps(), c.req); !errors.Is(err, c.want) {
			t.Errorf("%+v: err = %v, want %v", c.req, err, c.want)
		}
	}
	if list, _ := f.repo.List(ctx); len(list) != 0 {
		t.Errorf("servers = %+v", list)
	}
	if rows := f.addRows(t); len(rows) != 0 {
		t.Errorf("a refusal was audited: %+v", rows)
	}
	if _, err := os.Stat(f.policyPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refusal wrote the policy file: %v", err)
	}
}

func TestRegisterTakesTheServerOutWhenALinkFails(t *testing.T) {
	f := newRegFixture(t)
	ctx := context.Background()
	p, err := project.NewRepo(f.st).Add(ctx, project.Project{Name: "demo", Path: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DB().Exec(`CREATE TRIGGER boom BEFORE INSERT ON target_project BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`); err != nil {
		t.Fatal(err)
	}
	_, err = Register(ctx, f.deps(), RegisterRequest{Host: "192.0.2.30", User: "d", Links: []Link{{ProjectID: p.ID, RemoteDir: "/var/www/demo"}}})
	if !errors.As(err, new(*LinkError)) {
		t.Fatalf("err = %v", err)
	}
	if list, _ := f.repo.List(ctx); len(list) != 0 {
		t.Errorf("servers = %+v, want the server taken out", list)
	}
	if strings.Contains(f.policyText(), "192.0.2.30") {
		t.Errorf("a rule was written:\n%s", f.policyText())
	}
	if rows := f.addRows(t); len(rows) != 0 {
		t.Errorf("audit = %+v", rows)
	}
}

func TestRegisterTakesTheServerOutWhenTheRulesFail(t *testing.T) {
	f := newRegFixture(t)
	ctx := context.Background()
	// A folder in place of the policy file: it cannot be written.
	if err := os.Mkdir(f.policyPath, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Register(ctx, f.deps(), RegisterRequest{Host: "192.0.2.31", User: "d"})
	if !errors.As(err, new(*RulesError)) {
		t.Fatalf("err = %v", err)
	}
	if list, _ := f.repo.List(ctx); len(list) != 0 {
		t.Errorf("servers = %+v, want the server taken out", list)
	}
	if rows := f.addRows(t); len(rows) != 0 {
		t.Errorf("audit = %+v", rows)
	}
}

func TestRegisterAuditFailureKeepsTheServer(t *testing.T) {
	f := newRegFixture(t)
	ctx := context.Background()
	if _, err := f.st.DB().Exec(`CREATE TRIGGER fail_add BEFORE INSERT ON audit_event WHEN NEW.action = 'target.add'
		BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`); err != nil {
		t.Fatal(err)
	}
	got, err := Register(ctx, f.deps(), RegisterRequest{Host: "192.0.2.32", User: "d"})
	if !errors.As(err, new(*AuditError)) || got.ID == "" {
		t.Fatalf("added %+v err = %v", got, err)
	}
	if list, _ := f.repo.List(ctx); len(list) != 1 {
		t.Errorf("servers = %+v", list)
	}
}

// A caller that goes away while the rules are written (a closed page) leaves
// no rule behind that Michel would not know as its own, and no server
// without its trace: once the server is stored, Register ends its work.
func TestRegisterEndsItsWorkWhenTheCallerGoesAway(t *testing.T) {
	f := newRegFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := f.deps()
	// Current is read when the rule step starts: the caller goes away there.
	d.Current = func() policy.Policy { cancel(); return policy.Defaults() }
	got, err := Register(ctx, d, RegisterRequest{Host: "192.0.2.33", User: "d"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	rule := policy.AllowRule{Host: "192.0.2.33", Purpose: policy.PurposeTargetSSH}
	if owned, err := f.repo.OwnedOnly(context.Background(), []policy.AllowRule{rule}); err != nil || len(owned) != 1 {
		t.Errorf("the rule written is not recorded as Michel's: %v %v\n%s", owned, err, f.policyText())
	}
	if list, _ := f.repo.List(context.Background()); len(list) != 1 || list[0].ID != got.ID {
		t.Errorf("servers = %+v", list)
	}
	if rows := f.addRows(t); len(rows) != 1 {
		t.Errorf("audit = %+v", rows)
	}
}
