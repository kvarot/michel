package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/policy"
)

// A rule the user wrote by hand in the policy file stays theirs: michel
// target add does not count it as Michel's, and michel target remove leaves
// it, while the rule Michel wrote for the site goes.
func TestTargetHandWrittenRuleStaysTheUsers(t *testing.T) {
	e := newTargetEnv(t)
	cfg := filepath.Join(e.dir, "config.yaml")
	hand := policy.AllowRule{Host: "192.0.2.95", Purpose: policy.PurposeTargetSSH}
	if _, err := policy.AddAllowRules(cfg, hand); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, e.dir, "target", "add", "192.0.2.95", "--user", "d", "--name", "hand", "--site-url", "https://www.example.test/"); err != nil {
		t.Fatal(err)
	}
	if ev := auditRows(t, e.dir, "target.add"); len(ev) != 1 || ev[0].evidence["rules_written"] != float64(1) {
		t.Errorf("audit = %+v", ev)
	}
	if _, _, _, err := run(t, e.dir, "target", "remove", "hand"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(cfg)
	if !strings.Contains(string(b), "192.0.2.95") {
		t.Errorf("the hand-written rule was removed:\n%s", b)
	}
	if strings.Contains(string(b), "www.example.test") {
		t.Errorf("the rule Michel wrote stayed:\n%s", b)
	}
}

// michel target add leaves the trace the page leaves: same action, same
// evidence (internal/api TestTargetAddAuditIsTheSharedOne).
func TestTargetAddAuditIsTheSharedOne(t *testing.T) {
	e := newTargetEnv(t)
	if _, _, _, err := run(t, e.dir, "target", "add", "192.0.2.96", "--user", "d", "--name", "shared", "--kind", "shared", "--env", "preprod", "--level", "2"); err != nil {
		t.Fatal(err)
	}
	ev := auditRows(t, e.dir, "target.add")
	want := map[string]any{"name": "shared", "kind": "shared", "env": "preprod", "fix_level": float64(2), "links": float64(0), "rules_written": float64(1)}
	if len(ev) != 1 || ev[0].result != "ok" || !reflect.DeepEqual(ev[0].evidence, want) {
		t.Errorf("audit = %+v, want %v", ev, want)
	}
}

// An empty user is refused by the shared check; the command line keeps its
// sentence, which names --user.
func TestTargetAddWithoutUserNamesTheFlag(t *testing.T) {
	e := newTargetEnv(t)
	_, _, _, err := run(t, e.dir, "target", "add", "192.0.2.97")
	if err == nil || !strings.Contains(err.Error(), "--user") {
		t.Fatalf("err = %v", err)
	}
	if list := listTargets(t, e.dir); len(list) != 0 {
		t.Errorf("servers = %+v", list)
	}
}

// michel target set leaves the trace the page leaves: the fields are named
// as the page names them (internal/api TestTargetUpdateAuditIsTheSharedOne).
func TestTargetSetAuditIsTheSharedOne(t *testing.T) {
	e := newTargetEnv(t)
	if _, _, _, err := run(t, e.dir, "target", "add", "192.0.2.98", "--user", "d", "--name", "upd"); err != nil {
		t.Fatal(err)
	}
	_, out, _, err := run(t, e.dir, "target", "set", "upd", "--level", "2", "--site-url", "https://www.example.test/", "--interval", "12h")
	if err != nil {
		t.Fatal(err)
	}
	// The sentence keeps the flags' names.
	if !strings.Contains(out, "level, site-url, interval") {
		t.Errorf("out = %q", out)
	}
	ev := auditRows(t, e.dir, "target.update")
	want := map[string]any{"name": "upd", "changed": []any{"site_url", "fix_level", "check_interval"}, "rules_written": float64(1),
		"rules_removed": float64(0), "host_key_reset": false}
	if len(ev) != 1 || ev[0].result != "ok" || !reflect.DeepEqual(ev[0].evidence, want) {
		t.Errorf("audit = %+v, want %v", ev, want)
	}
}
