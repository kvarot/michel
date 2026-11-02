package policy

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const commented = `# Michel policy of the demo machine.
sovereignty:
  mode: strict_local # keep local
  network:
    default_egress: deny
    # rules written by hand
    allow:
      - host: smtp.example.org
        purpose: notify.email
risk:
  major_jump: 35 # a bit less than the default
`

func TestAddAllowRuleKeepsCommentsAndOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(commented), 0o600); err != nil {
		t.Fatal(err)
	}
	added, err := AddAllowRule(path, AllowRule{Host: "www.cisa.gov", Purpose: PurposeEnrich})
	if err != nil || !added {
		t.Fatalf("added=%v err=%v", added, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{"# Michel policy of the demo machine.", "# keep local", "# rules written by hand", "# a bit less than the default"} {
		if !strings.Contains(text, want) {
			t.Errorf("comment %q lost:\n%s", want, text)
		}
	}
	if strings.Index(text, "sovereignty:") > strings.Index(text, "risk:") {
		t.Errorf("order changed:\n%s", text)
	}
	bak, err := os.ReadFile(path + ".bak")
	if err != nil || string(bak) != commented {
		t.Errorf(".bak = %q err %v", bak, err)
	}
	p, _, err := Load(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(p); err != nil {
		t.Fatal(err)
	}
	allow := p.Sovereignty.Network.Allow
	if len(allow) != 2 || allow[1] != (AllowRule{Host: "www.cisa.gov", Purpose: PurposeEnrich}) || p.Risk.MajorJump != 35 {
		t.Errorf("allow = %+v, risk = %+v", allow, p.Risk)
	}

	added, err = AddAllowRule(path, AllowRule{Host: "www.cisa.gov", Purpose: PurposeEnrich})
	if err != nil || added {
		t.Fatalf("second add: added=%v err=%v", added, err)
	}
	again, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(again, raw) {
		t.Errorf("file changed on a second identical add")
	}

	removed, err := RemoveAllowRule(path, AllowRule{Host: "www.cisa.gov", Purpose: PurposeEnrich})
	if err != nil || !removed {
		t.Fatalf("remove: removed=%v err=%v", removed, err)
	}
	p, _, err = Load(path, dir)
	if err != nil || len(p.Sovereignty.Network.Allow) != 1 {
		t.Fatalf("after remove: %+v err %v", p.Sovereignty.Network.Allow, err)
	}
	if removed, err := RemoveAllowRule(path, AllowRule{Host: "www.cisa.gov", Purpose: PurposeEnrich}); err != nil || removed {
		t.Errorf("second remove: removed=%v err=%v", removed, err)
	}
}

func TestAddAllowRuleOnFlowListAndMissingFile(t *testing.T) {
	dir := t.TempDir()
	example, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, example, 0o600); err != nil {
		t.Fatal(err)
	}
	if added, err := AddAllowRule(path, AllowRule{Host: "epss.empiricalsecurity.com", Purpose: PurposeEnrich}); err != nil || !added {
		t.Fatalf("added=%v err=%v", added, err)
	}
	p, _, err := Load(path, dir)
	if err != nil || len(p.Sovereignty.Network.Allow) != 1 {
		t.Fatalf("allow = %+v err %v", p.Sovereignty.Network.Allow, err)
	}

	missing := filepath.Join(dir, "sub", "absent.yaml")
	if added, err := AddAllowRule(missing, AllowRule{Host: "www.cisa.gov", Purpose: PurposeEnrich}); err != nil || !added {
		t.Fatalf("absent file: added=%v err=%v", added, err)
	}
	if _, err := os.Stat(missing + ".bak"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a .bak was written for an absent file: %v", err)
	}
}

func TestAddAllowRuleRestoresOnInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// The file parses as YAML, but Load refuses it (unknown key): after the
	// rule is added, the reload fails and the original content is restored.
	original := "sovereignty:\n  network:\n    allow: []\nnot_a_policy_key: true\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AddAllowRule(path, AllowRule{Host: "www.cisa.gov", Purpose: PurposeEnrich}); err == nil {
		t.Fatal("expected an error")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != original {
		t.Errorf("content = %q err %v", raw, err)
	}

	// A file that is not YAML is never rewritten.
	broken := "sovereignty: [unclosed\n"
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AddAllowRule(path, AllowRule{Host: "www.cisa.gov", Purpose: PurposeEnrich}); err == nil {
		t.Fatal("expected an error on a broken file")
	}
	if raw, _ := os.ReadFile(path); string(raw) != broken {
		t.Errorf("broken file rewritten: %q", raw)
	}
}

func TestAddAllowRulesWritesAllOrNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := "sovereignty:\n  mode: strict_local\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AddAllowRules(path, AllowRule{Host: "a.example.org", Purpose: PurposeFeed}, AllowRule{Host: "b.example.org/x", Purpose: PurposeFeed}); err == nil {
		t.Fatal("expected the invalid second rule to fail")
	}
	if raw, _ := os.ReadFile(path); string(raw) != original {
		t.Errorf("a rule stayed: %q", raw)
	}
	n, err := AddAllowRules(path, AllowRule{Host: "a.example.org", Purpose: PurposeFeed}, AllowRule{Host: "b.example.org", Purpose: PurposeFeed},
		AllowRule{Host: "A.example.org", Purpose: PurposeFeed})
	if err != nil || n != 2 {
		t.Fatalf("n = %d err %v", n, err)
	}
	p, _, err := Load(path, t.TempDir())
	if err != nil || len(p.Sovereignty.Network.Allow) != 2 {
		t.Fatalf("allow = %+v err %v", p.Sovereignty.Network.Allow, err)
	}
	if n, err := AddAllowRules(path, AllowRule{Host: "b.example.org", Purpose: PurposeFeed}); err != nil || n != 0 {
		t.Errorf("again: n = %d err %v", n, err)
	}
}

const standardPolicy = `# Michel policy.
sovereignty:
  mode: standard # external services allowed
  ai:
    provider_policy: local_first # keep
  network:
    allow: []
risk:
  major_jump: 35
`

func TestSetExternalProvidersCreatesFileWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "config.yaml")
	// strict_local (the default) forbids the key: the new file is not kept.
	changed, err := SetExternalProviders(path, true)
	if err == nil || changed || !strings.Contains(err.Error(), "strict_local forbids ai.external_providers_enabled") {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the invalid new file is still there: %v", err)
	}
	// Disabling what is already off creates nothing.
	if changed, err := SetExternalProviders(path, false); err != nil || changed {
		t.Fatalf("disable on absent: %v %v", changed, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a file was created: %v", err)
	}
}

func TestSetExternalProvidersEditsInPlaceWithBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(standardPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := SetExternalProviders(path, true)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	raw, _ := os.ReadFile(path)
	for _, want := range []string{"# Michel policy.", "# external services allowed", "# keep", "major_jump: 35"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("%q lost:\n%s", want, raw)
		}
	}
	if bak, err := os.ReadFile(path + ".bak"); err != nil || string(bak) != standardPolicy {
		t.Errorf(".bak = %q err %v", bak, err)
	}
	p, _, err := Load(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(p); err != nil || !p.Sovereignty.AI.ExternalProvidersEnabled {
		t.Fatalf("validate %v, enabled %v", err, p.Sovereignty.AI.ExternalProvidersEnabled)
	}
	if changed, err := SetExternalProviders(path, true); err != nil || changed {
		t.Fatalf("second call: %v %v", changed, err)
	}
	if changed, err := SetExternalProviders(path, false); err != nil || !changed {
		t.Fatalf("disable: %v %v", changed, err)
	}
	p, _, _ = Load(path, dir)
	if p.Sovereignty.AI.ExternalProvidersEnabled {
		t.Error("still enabled")
	}
}

func TestSetExternalProvidersRefusedInStrictLocalKeepsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(commented), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SetExternalProviders(path, true); err == nil {
		t.Fatal("strict_local accepted external providers")
	}
	if raw, _ := os.ReadFile(path); string(raw) != commented {
		t.Errorf("file changed:\n%s", raw)
	}
}

const strictPolicy = `# Michel policy.
sovereignty:
  mode: strict_local # nothing leaves
  network:
    default_egress: deny
risk:
  major_jump: 35
`

// TestSetModeSwitchesToStandardWithExternalAI: one atomic edit writes
// sovereignty.mode and ai.external_providers_enabled together (strict_local
// forbids the key, so two edits would fail), keeps comments, leaves a .bak.
func TestSetModeSwitchesToStandardWithExternalAI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(strictPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := SetMode(path, ModeStandard, true)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	raw, _ := os.ReadFile(path)
	for _, want := range []string{"# Michel policy.", "# nothing leaves", "major_jump: 35", "mode: standard"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("%q missing:\n%s", want, raw)
		}
	}
	if bak, err := os.ReadFile(path + ".bak"); err != nil || string(bak) != strictPolicy {
		t.Errorf(".bak = %q err %v", bak, err)
	}
	p, _, err := Load(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(p); err != nil || p.Sovereignty.Mode != ModeStandard || !p.Sovereignty.AI.ExternalProvidersEnabled {
		t.Fatalf("validate %v, mode %s, external %v", err, p.Sovereignty.Mode, p.Sovereignty.AI.ExternalProvidersEnabled)
	}
	if changed, err := SetMode(path, ModeStandard, true); err != nil || changed {
		t.Fatalf("second call: %v %v", changed, err)
	}
	// Back to strict_local with external AI on is invalid: the file stays.
	before, _ := os.ReadFile(path)
	if changed, err := SetMode(path, ModeStrictLocal, false); err == nil || changed {
		t.Fatalf("strict_local with external AI on: %v %v", changed, err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Errorf("an invalid edit was kept:\n%s", after)
	}
	if _, err := SetMode(path, Mode("open_bar"), false); err == nil {
		t.Error("an unknown mode was written")
	}
	// An absent file (strict_local by default) is created in standard mode.
	fresh := filepath.Join(dir, "sub", "new.yaml")
	if changed, err := SetMode(fresh, ModeStandard, true); err != nil || !changed {
		t.Fatalf("absent file: %v %v", changed, err)
	}
}

func TestRemoveAllowRulesWritesOnceAndKeepsTheOthers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	a := AllowRule{Host: "a.example.test", Purpose: PurposeTargetSSH}
	b := AllowRule{Host: "b.example.test", Purpose: PurposeTargetSSH}
	c := AllowRule{Host: "a.example.test", Purpose: PurposeTargetHTTP}
	if n, err := AddAllowRules(path, a, b, c); err != nil || n != 3 {
		t.Fatalf("add = %d %v", n, err)
	}
	n, err := RemoveAllowRules(path, a, c, AllowRule{Host: "none.example.test", Purpose: "x"})
	if err != nil || n != 2 {
		t.Fatalf("remove = %d %v", n, err)
	}
	p, _, err := Load(path, t.TempDir())
	if err != nil || len(p.Sovereignty.Network.Allow) != 1 || p.Sovereignty.Network.Allow[0] != b {
		t.Fatalf("rules = %+v %v", p.Sovereignty.Network.Allow, err)
	}
	if n, err := RemoveAllowRules(path, a); err != nil || n != 0 {
		t.Errorf("removing what is gone = %d %v", n, err)
	}
	if n, err := RemoveAllowRules(path, b); err != nil || n != 1 {
		t.Fatalf("last = %d %v", n, err)
	}
	if p, _, err := Load(path, t.TempDir()); err != nil || len(p.Sovereignty.Network.Allow) != 0 {
		t.Errorf("after the last = %+v %v", p.Sovereignty.Network.Allow, err)
	}
}
