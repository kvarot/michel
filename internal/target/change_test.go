package target

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/policy"
)

func (f *regFixture) rows(t *testing.T, action string) []map[string]any {
	t.Helper()
	rs, err := f.st.DB().Query(`SELECT actor, result, evidence FROM audit_event WHERE action = ? ORDER BY seq`, action)
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

func (f *regFixture) register(t *testing.T, req RegisterRequest) Target {
	t.Helper()
	got, err := Register(context.Background(), f.deps(), req)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func (f *regFixture) owned(t *testing.T, r policy.AllowRule) bool {
	t.Helper()
	got, err := f.repo.OwnedOnly(context.Background(), []policy.AllowRule{r})
	if err != nil {
		t.Fatal(err)
	}
	return len(got) == 1
}

func ptr[T any](v T) *T { return &v }

// The audit names the fields as the page does, from both sides.
func TestApplyUpdateNamesTheChangesAsThePage(t *testing.T) {
	f := newRegFixture(t)
	old := f.register(t, RegisterRequest{Host: "192.0.2.40", User: "d", Name: "upd"})
	got, err := ApplyUpdate(context.Background(), f.deps(), old, Patch{SiteURL: ptr(" https://www.example.test/ "), FixLevel: ptr(2),
		CheckInterval: ptr("12h"), Active: ptr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if got.SiteURL != "https://www.example.test/" || got.FixLevel != 2 || got.Active || got.CheckInterval == 0 {
		t.Errorf("updated = %+v", got)
	}
	if stored, _ := f.repo.Get(context.Background(), old.ID); stored.FixLevel != 2 || stored.SiteURL != got.SiteURL {
		t.Errorf("stored = %+v", stored)
	}
	rows := f.rows(t, "target.update")
	want := map[string]any{"_actor": "test", "_result": "ok", "name": "upd", "changed": []any{"site_url", "fix_level", "active", "check_interval"},
		"rules_written": float64(1), "rules_removed": float64(0), "host_key_reset": false}
	if len(rows) != 1 || !reflect.DeepEqual(rows[0], want) {
		t.Errorf("audit = %+v, want %v", rows, want)
	}
	if !strings.Contains(f.policyText(), "www.example.test") {
		t.Errorf("site rule not written:\n%s", f.policyText())
	}
}

// A host that changes takes its rules along, and the confirmed key is
// reset with the old address.
func TestApplyUpdateMovesTheRulesWithTheHost(t *testing.T) {
	f := newRegFixture(t)
	ctx := context.Background()
	old := f.register(t, RegisterRequest{Host: "192.0.2.41", User: "d", Name: "mv"})
	if err := f.repo.SetHostKey(ctx, old.ID, "SHA256:old"); err != nil {
		t.Fatal(err)
	}
	old, _ = f.repo.Get(ctx, old.ID)
	got, err := ApplyUpdate(ctx, f.deps(), old, Patch{Host: ptr("192.0.2.42")})
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "192.0.2.42" {
		t.Errorf("updated = %+v", got)
	}
	text := f.policyText()
	if strings.Contains(text, "192.0.2.41") || !strings.Contains(text, "192.0.2.42") {
		t.Errorf("rules not moved:\n%s", text)
	}
	if stored, _ := f.repo.Get(ctx, old.ID); stored.HostKey != "" {
		t.Errorf("host key kept: %q", stored.HostKey)
	}
	rows := f.rows(t, "target.update")
	if len(rows) != 1 || rows[0]["rules_written"] != float64(1) || rows[0]["rules_removed"] != float64(1) || rows[0]["host_key_reset"] != true {
		t.Errorf("audit = %+v", rows)
	}
}

// The new rules come out again when the update is refused; the old ones stay.
func TestApplyUpdateRollsTheRulesBackWhenTheUpdateFails(t *testing.T) {
	f := newRegFixture(t)
	ctx := context.Background()
	old := f.register(t, RegisterRequest{Host: "192.0.2.43", User: "d", Name: "rb"})
	if _, err := f.st.DB().Exec(`CREATE TRIGGER boom BEFORE UPDATE ON target BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`); err != nil {
		t.Fatal(err)
	}
	_, err := ApplyUpdate(ctx, f.deps(), old, Patch{Host: ptr("192.0.2.44")})
	if err == nil {
		t.Fatal("no error")
	}
	text := f.policyText()
	if strings.Contains(text, "192.0.2.44") || !strings.Contains(text, "192.0.2.43") {
		t.Errorf("rules not rolled back:\n%s", text)
	}
	if f.owned(t, policy.AllowRule{Host: "192.0.2.44", Purpose: policy.PurposeTargetSSH}) {
		t.Error("the rolled back rule is still recorded")
	}
	if rows := f.rows(t, "target.update"); len(rows) != 0 {
		t.Errorf("audit = %+v", rows)
	}
}

// The checks come in one order and a refusal changes nothing.
func TestApplyUpdateChecksInOneOrder(t *testing.T) {
	f := newRegFixture(t)
	ctx := context.Background()
	old := f.register(t, RegisterRequest{Host: "192.0.2.45", User: "d", Name: "ord"})
	before := f.policyText()
	for _, c := range []struct {
		p    Patch
		want error
	}{
		{Patch{CheckInterval: ptr("soon"), SiteURL: ptr("ftp://www.example.test/")}, ErrInvalidInterval},
		{Patch{SiteURL: ptr("ftp://www.example.test/"), Preprod: ptr("nowhere")}, ErrInvalidSiteURL},
		{Patch{Preprod: ptr("nowhere"), Host: ptr("192.0.2.46")}, ErrPreprodNotFound},
	} {
		if _, err := ApplyUpdate(ctx, f.deps(), old, c.p); !errors.Is(err, c.want) {
			t.Errorf("%+v: err = %v, want %v", c.p, err, c.want)
		}
	}
	if f.policyText() != before {
		t.Errorf("a refusal wrote the policy file:\n%s", f.policyText())
	}
	if rows := f.rows(t, "target.update"); len(rows) != 0 {
		t.Errorf("a refusal was audited: %+v", rows)
	}
}

// A caller that goes away while the new rules are written still has them
// taken back when the update cannot be stored.
func TestApplyUpdateRollsBackWhenTheCallerGoesAway(t *testing.T) {
	f := newRegFixture(t)
	old := f.register(t, RegisterRequest{Host: "192.0.2.47", User: "d", Name: "gone"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := f.deps()
	d.Current = func() policy.Policy { cancel(); return policy.Defaults() }
	if _, err := ApplyUpdate(ctx, d, old, Patch{Host: ptr("192.0.2.48")}); err == nil {
		t.Fatal("the update was stored on a cancelled context")
	}
	if strings.Contains(f.policyText(), "192.0.2.48") {
		t.Errorf("an unrecorded rule stayed:\n%s", f.policyText())
	}
	if f.owned(t, policy.AllowRule{Host: "192.0.2.48", Purpose: policy.PurposeTargetSSH}) {
		t.Error("the rolled back rule is still recorded")
	}
}

// Once the update is stored, the old rules are released and the trace
// written even if the caller goes away.
func TestApplyUpdateEndsItsWorkOnceStored(t *testing.T) {
	f := newRegFixture(t)
	old := f.register(t, RegisterRequest{Host: "192.0.2.49", User: "d", Name: "end"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := f.deps()
	calls := 0
	// The second rule step is the release, after the store write.
	d.Current = func() policy.Policy {
		if calls++; calls == 2 {
			cancel()
		}
		return policy.Defaults()
	}
	if _, err := ApplyUpdate(ctx, d, old, Patch{Host: ptr("192.0.2.50")}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.policyText(), "192.0.2.49") {
		t.Errorf("the old rule was not released:\n%s", f.policyText())
	}
	if rows := f.rows(t, "target.update"); len(rows) != 1 || rows[0]["rules_removed"] != float64(1) {
		t.Errorf("audit = %+v", rows)
	}
}

// ChangeRules ends its edit even if the caller goes away: a rule written but
// not recorded would count as the user's and never be taken back.
func TestChangeRulesEndsItsEditWhenTheCallerGoesAway(t *testing.T) {
	f := newRegFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := f.deps()
	d.Current = func() policy.Policy { cancel(); return policy.Defaults() }
	rule := policy.AllowRule{Host: "192.0.2.51", Purpose: policy.PurposeTargetSSH}
	if _, _, err := ChangeRules(ctx, d, []policy.AllowRule{rule}, nil); err != nil {
		t.Fatal(err)
	}
	if !f.owned(t, rule) {
		t.Errorf("the rule written is not recorded as Michel's:\n%s", f.policyText())
	}
}

func TestRemoveErasesTheLogsFirstAndReleasesTheRules(t *testing.T) {
	f := newRegFixture(t)
	ctx := context.Background()
	pre := f.register(t, RegisterRequest{Host: "192.0.2.60", User: "d", Name: "pre", Env: EnvPreprod, SiteURL: "https://shared.example.test/"})
	f.register(t, RegisterRequest{Host: "192.0.2.61", User: "d", Name: "prod", SiteURL: "https://shared.example.test/", Preprod: "pre"})
	erased := false
	res, err := Remove(ctx, f.deps(), pre, func(context.Context) (bool, error) {
		if list, _ := f.repo.List(ctx); len(list) != 2 {
			t.Errorf("the server went before its logs: %+v", list)
		}
		erased = true
		return true, nil
	})
	if err != nil || !erased {
		t.Fatalf("err = %v, erased %v", err, erased)
	}
	if res.RulesRemoved != 1 || res.RulesFailed {
		t.Errorf("result = %+v", res)
	}
	text := f.policyText()
	if strings.Contains(text, "192.0.2.60") || !strings.Contains(text, "shared.example.test") {
		t.Errorf("rules:\n%s", text)
	}
	rows := f.rows(t, "target.remove")
	want := map[string]any{"_actor": "test", "_result": "ok", "name": "pre", "rules_removed": float64(1), "rules_error": false,
		"preprod_cleared": float64(1), "logs_error": false}
	if len(rows) != 1 || !reflect.DeepEqual(rows[0], want) {
		t.Errorf("audit = %+v, want %v", rows, want)
	}
}

func TestRemoveKeepsTheServerWhenTheLogsStay(t *testing.T) {
	f := newRegFixture(t)
	ctx := context.Background()
	tg := f.register(t, RegisterRequest{Host: "192.0.2.62", User: "d", Name: "stay"})
	_, err := Remove(ctx, f.deps(), tg, func(context.Context) (bool, error) { return false, errors.New("disk on fire") })
	if !errors.Is(err, ErrLogsNotErased) {
		t.Fatalf("err = %v", err)
	}
	if list, _ := f.repo.List(ctx); len(list) != 1 {
		t.Errorf("servers = %+v", list)
	}
	if !strings.Contains(f.policyText(), "192.0.2.62") {
		t.Errorf("rule released:\n%s", f.policyText())
	}
	if rows := f.rows(t, "target.remove"); len(rows) != 0 {
		t.Errorf("audit = %+v", rows)
	}
}

// Logs erased in part, rules that cannot be taken back: the server goes,
// and the trace says so.
func TestRemoveTellsWhatCouldNotBeUndone(t *testing.T) {
	f := newRegFixture(t)
	ctx := context.Background()
	tg := f.register(t, RegisterRequest{Host: "192.0.2.63", User: "d", Name: "half"})
	if err := os.Remove(f.policyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.policyPath, 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := Remove(ctx, f.deps(), tg, func(context.Context) (bool, error) { return true, errors.New("one row stayed") })
	if err != nil || !res.RulesFailed {
		t.Fatalf("result %+v err = %v", res, err)
	}
	if list, _ := f.repo.List(ctx); len(list) != 0 {
		t.Errorf("servers = %+v", list)
	}
	rows := f.rows(t, "target.remove")
	if len(rows) != 1 || rows[0]["rules_error"] != true || rows[0]["logs_error"] != true {
		t.Errorf("audit = %+v", rows)
	}
}

// From the erasure of the logs on, the caller going away stops nothing.
func TestRemoveEndsItsWorkWhenTheCallerGoesAway(t *testing.T) {
	f := newRegFixture(t)
	tg := f.register(t, RegisterRequest{Host: "192.0.2.64", User: "d", Name: "bye"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := Remove(ctx, f.deps(), tg, func(context.Context) (bool, error) { cancel(); return true, nil }); err != nil {
		t.Fatal(err)
	}
	if list, _ := f.repo.List(context.Background()); len(list) != 0 {
		t.Errorf("servers = %+v", list)
	}
	if strings.Contains(f.policyText(), "192.0.2.64") {
		t.Errorf("rule kept:\n%s", f.policyText())
	}
	if rows := f.rows(t, "target.remove"); len(rows) != 1 {
		t.Errorf("audit = %+v", rows)
	}
}

func TestConfirmHostKey(t *testing.T) {
	f := newRegFixture(t)
	ctx := context.Background()
	tg := f.register(t, RegisterRequest{Host: "192.0.2.70", User: "d", Name: "hk"})
	if _, err := ConfirmHostKey(ctx, f.deps(), tg, "SHA256:typed", "SHA256:shown", false); !errors.Is(err, ErrFingerprintMismatch) {
		t.Errorf("mismatch: err = %v", err)
	}
	if _, err := ConfirmHostKey(ctx, f.deps(), tg, " SHA256:one ", "SHA256:one", false); err != nil {
		t.Fatal(err)
	}
	tg, _ = f.repo.Get(ctx, tg.ID)
	if tg.HostKey != "SHA256:one" {
		t.Errorf("pinned = %q", tg.HostKey)
	}
	if _, err := ConfirmHostKey(ctx, f.deps(), tg, "SHA256:two", "SHA256:two", false); !errors.Is(err, ErrHostKeyReplaceNotAsked) {
		t.Errorf("changed: err = %v", err)
	}
	if replaced, err := ConfirmHostKey(ctx, f.deps(), tg, "SHA256:two", "SHA256:two", true); err != nil || !replaced {
		t.Errorf("replace: %v %v", replaced, err)
	}
	rows := f.rows(t, "target.hostkey")
	want := []map[string]any{
		{"_actor": "test", "_result": "refused", "name": "hk", "reason": "fingerprint mismatch"},
		{"_actor": "test", "_result": "ok", "name": "hk", "fingerprint": "SHA256:one", "replaced": false},
		{"_actor": "test", "_result": "refused", "name": "hk", "reason": "key changed, replace not asked"},
		{"_actor": "test", "_result": "ok", "name": "hk", "fingerprint": "SHA256:two", "replaced": true},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("audit = %+v\nwant %+v", rows, want)
	}
}

func TestConfirmHostKeyRefusalAuditFailure(t *testing.T) {
	f := newRegFixture(t)
	ctx := context.Background()
	tg := f.register(t, RegisterRequest{Host: "192.0.2.71", User: "d", Name: "hka"})
	if _, err := f.st.DB().Exec(`CREATE TRIGGER fail_refusal BEFORE INSERT ON audit_event WHEN NEW.action = 'target.hostkey'
		BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`); err != nil {
		t.Fatal(err)
	}
	_, err := ConfirmHostKey(ctx, f.deps(), tg, "SHA256:a", "SHA256:b", false)
	var ra *RefusalAuditError
	if !errors.As(err, &ra) || !errors.Is(err, ErrFingerprintMismatch) {
		t.Errorf("err = %v", err)
	}
	_, err = ConfirmHostKey(ctx, f.deps(), tg, "SHA256:b", "SHA256:b", false)
	if !errors.As(err, new(*AuditError)) {
		t.Errorf("ok audit: err = %v", err)
	}
	if got, _ := f.repo.Get(ctx, tg.ID); got.HostKey != "SHA256:b" {
		t.Errorf("pinned = %q", got.HostKey)
	}
}
