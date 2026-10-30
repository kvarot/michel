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
