package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsAreStrictLocal(t *testing.T) {
	p := Defaults()
	s := p.Sovereignty
	if s.Mode != ModeStrictLocal || s.Network.DefaultEgress != "deny" {
		t.Fatalf("mode=%q egress=%q", s.Mode, s.Network.DefaultEgress)
	}
	for name, on := range map[string]bool{
		"external": s.AI.ExternalProvidersEnabled, "downloads": s.AI.ModelDownloadsEnabled,
		"updates": s.AI.AutomaticModelUpdates, "telemetry": s.Network.TelemetryEnabled,
		"errors": s.Network.RemoteErrorReporting, "db": p.DB.AutoUpdate,
		"prod": s.Remediation.ProductionDeploymentAllowed,
	} {
		if on {
			t.Errorf("%s is true by default", name)
		}
	}
	if s.DataClassification != ClassSensitive || s.Audit.IntegrityProtection != "required" ||
		s.Audit.PromptContentRetention != "encrypted_configurable" || !s.Audit.Enabled {
		t.Errorf("classification=%q audit=%+v", s.DataClassification, s.Audit)
	}
	if len(s.Network.Allow) != 0 || p.Assistant.Name != "Michel" {
		t.Errorf("allow=%v name=%q", s.Network.Allow, p.Assistant.Name)
	}
	if err := Validate(p); err != nil {
		t.Errorf("defaults invalid: %v", err)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	dir := t.TempDir()
	p, src, err := Load(filepath.Join(dir, "nope.yaml"), dir)
	if err != nil || src != SourceDefaults {
		t.Fatalf("src=%q err=%v", src, err)
	}
	if want := filepath.Join(dir, "osv"); p.DB.OSVPath != want {
		t.Errorf("OSVPath=%q want %q", p.DB.OSVPath, want)
	}
}

func TestLoadFileOverrides(t *testing.T) {
	dir := t.TempDir()
	p, src, err := Load(filepath.Join("testdata", "standard.yaml"), dir)
	if err != nil || src != SourceFile {
		t.Fatalf("src=%q err=%v", src, err)
	}
	if p.Sovereignty.Mode != ModeStandard || !p.DB.AutoUpdate {
		t.Errorf("overrides not applied: %+v", p)
	}
	if p.Sovereignty.Network.DefaultEgress != "deny" || p.Assistant.Name != "Michel" {
		t.Errorf("omitted keys lost their defaults: %+v", p)
	}
	if p.DB.OSVPath != filepath.Join(dir, "osv") {
		t.Errorf("OSVPath=%q", p.DB.OSVPath)
	}
}

func TestUnknownKeyIsError(t *testing.T) {
	if _, _, err := Load(filepath.Join("testdata", "unknown_key.yaml"), t.TempDir()); err == nil {
		t.Fatal("want error for unknown key")
	}
}

func TestLoadEmptyFileKeepsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	p, src, err := Load(path, dir)
	if err != nil || src != SourceFile || p.Sovereignty.Mode != ModeStrictLocal {
		t.Fatalf("p=%+v src=%q err=%v", p, src, err)
	}
}

func mustFail(t *testing.T, mutate func(*Policy), want string) {
	t.Helper()
	p := Defaults()
	mutate(&p)
	err := Validate(p)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err=%v, want it to contain %q", err, want)
	}
}

func TestValidateRejectsStrictLocalWithExternalProviders(t *testing.T) {
	mustFail(t, func(p *Policy) { p.Sovereignty.AI.ExternalProvidersEnabled = true },
		"strict_local forbids ai.external_providers_enabled")
}

func TestValidateRejectsUnknownMode(t *testing.T) {
	mustFail(t, func(p *Policy) { p.Sovereignty.Mode = "yolo" }, "sovereignty.mode")
}

func TestValidateRejectsStrictLocalTelemetry(t *testing.T) {
	mustFail(t, func(p *Policy) { p.Sovereignty.Network.TelemetryEnabled = true },
		"strict_local forbids network.telemetry_enabled")
}

func TestValidateRejectsStrictLocalOpenEgress(t *testing.T) {
	mustFail(t, func(p *Policy) { p.Sovereignty.Network.DefaultEgress = "allow" }, "default_egress")
}

func TestValidateRejectsAllowRuleWithoutPurpose(t *testing.T) {
	mustFail(t, func(p *Policy) {
		p.Sovereignty.Network.Allow = []AllowRule{{Host: "osv.dev"}}
	}, "purpose")
}

func TestValidateRejectsProductionDeploymentInAnyMode(t *testing.T) {
	for _, m := range []Mode{ModeStrictLocal, ModeStandard} {
		mustFail(t, func(p *Policy) {
			p.Sovereignty.Mode = m
			p.Sovereignty.Remediation.ProductionDeploymentAllowed = true
		}, "production_deployment_allowed")
	}
}

func TestValidateAllowRuleHosts(t *testing.T) {
	for _, h := range []string{"https://osv.dev", "osv.dev/x", "osv.dev:443", "*.", "a.*.b"} {
		mustFail(t, func(p *Policy) {
			p.Sovereignty.Network.Allow = []AllowRule{{Host: h, Purpose: "db"}}
		}, "network.allow[0]")
	}
	p := Defaults()
	p.Sovereignty.Network.Allow = []AllowRule{{Host: "osv.dev", Purpose: "db"}, {Host: "*.osv.dev", Purpose: "db"}}
	if err := Validate(p); err != nil {
		t.Errorf("valid hosts rejected: %v", err)
	}
}

func TestRiskDefaults(t *testing.T) {
	want := RiskConfig{MajorJump: 40, Breaking: 25, Direct: 10, ManyCallSites: 15, NoTests: 20, CorePackage: 20,
		ManyCallSitesThreshold: 10, AutoFixBelow: 30, HandoffUpTo: 60}
	if got := Defaults().Risk; got != want {
		t.Fatalf("risk defaults = %+v, want %+v", got, want)
	}
}

func TestRiskLoadsFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte("risk:\n  major_jump: 10\n  handoff_up_to: 70\nassistant:\n  lang: fr\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, _, err := Load(path, dir)
	if err != nil || p.Risk.MajorJump != 10 || p.Risk.HandoffUpTo != 70 || p.Risk.Breaking != 25 || p.Assistant.Lang != "fr" {
		t.Fatalf("p=%+v err=%v", p.Risk, err)
	}
}

func TestValidateRejectsBadThresholds(t *testing.T) {
	mustFail(t, func(p *Policy) { p.Risk.AutoFixBelow = 60 }, "risk.auto_fix_below")
	mustFail(t, func(p *Policy) { p.Risk.HandoffUpTo = 101 }, "risk.handoff_up_to")
	mustFail(t, func(p *Policy) { p.Risk.AutoFixBelow = -1 }, "risk.auto_fix_below")
	mustFail(t, func(p *Policy) { p.Risk.MajorJump = 101 }, "risk.major_jump")
	mustFail(t, func(p *Policy) { p.Risk.NoTests = -1 }, "risk.no_tests")
	mustFail(t, func(p *Policy) { p.Risk.ManyCallSitesThreshold = 0 }, "risk.many_call_sites_threshold")
}

func TestAssistantLangDefaultAuto(t *testing.T) {
	if l := Defaults().Assistant.Lang; l != "auto" {
		t.Fatalf("lang = %q", l)
	}
}

func TestValidateAcceptsAutoLang(t *testing.T) {
	for _, l := range []string{"auto", "en", "fr"} {
		p := Defaults()
		p.Assistant.Lang = l
		if err := Validate(p); err != nil {
			t.Errorf("%s rejected: %v", l, err)
		}
	}
}

func TestValidateRejectsUnknownLang(t *testing.T) {
	mustFail(t, func(p *Policy) { p.Assistant.Lang = "de" }, "assistant.lang")
	p := Defaults()
	p.Assistant.Lang = "fr"
	if err := Validate(p); err != nil {
		t.Errorf("fr rejected: %v", err)
	}
}

func boolPtr(b bool) *bool { return &b }

func TestValidateNotifyRules(t *testing.T) {
	email := ChannelConfig{Name: "mail-perso", Type: "email", Host: "smtp.example.org", Port: 587, From: "michel@example.org",
		To: []string{"me@example.org"}, Username: "me", PasswordSecret: "smtp-perso"}
	hook := ChannelConfig{Name: "hook", Type: "webhook", URL: "https://hooks.example.org/michel", Secret: "hook"}
	toast := ChannelConfig{Name: "desk", Type: "toast"}
	rules := []AllowRule{{Host: "smtp.example.org", Purpose: PurposeEmail}, {Host: "*.example.org", Purpose: PurposeWebhook}}
	with := func(c ChannelConfig, f func(*ChannelConfig)) ChannelConfig { f(&c); return c }
	for _, tc := range []struct {
		name     string
		channels []ChannelConfig
		rules    []AllowRule
		want     []string // empty = valid
	}{
		{"valid", []ChannelConfig{email, hook, toast}, rules, nil},
		{"duplicate name", []ChannelConfig{email, with(toast, func(c *ChannelConfig) { c.Name = "mail-perso" })}, rules, []string{`"mail-perso"`, "twice"}},
		{"no name", []ChannelConfig{with(toast, func(c *ChannelConfig) { c.Name = "" })}, rules, []string{"name"}},
		{"unknown type", []ChannelConfig{with(toast, func(c *ChannelConfig) { c.Type = "sms" })}, rules, []string{`"sms"`, "email, webhook or toast"}},
		{"port 25", []ChannelConfig{with(email, func(c *ChannelConfig) { c.Port = 25 })}, rules, []string{"587", "465"}},
		{"empty to", []ChannelConfig{with(email, func(c *ChannelConfig) { c.To = nil })}, rules, []string{"to"}},
		{"bad from", []ChannelConfig{with(email, func(c *ChannelConfig) { c.From = "michel@example.org\r\nBcc: x@example.org" })}, rules, []string{"from"}},
		{"no host", []ChannelConfig{with(email, func(c *ChannelConfig) { c.Host = "" })}, rules, []string{"host"}},
		{"username without password", []ChannelConfig{with(email, func(c *ChannelConfig) { c.PasswordSecret = "" })}, rules, []string{"password_secret"}},
		{"http not loopback", []ChannelConfig{with(hook, func(c *ChannelConfig) { c.URL = "http://hooks.example.org/michel" })}, rules, []string{"https"}},
		{"https without secret", []ChannelConfig{with(hook, func(c *ChannelConfig) { c.Secret = "" })}, rules, []string{"secret"}},
		{"unknown format", []ChannelConfig{with(hook, func(c *ChannelConfig) { c.Format = "teams" })}, rules, []string{`"teams"`}},
		{"loopback http without secret", []ChannelConfig{with(hook, func(c *ChannelConfig) { c.URL = "http://127.0.0.1:8080/x"; c.Secret = "" })},
			[]AllowRule{{Host: "127.0.0.1", Purpose: PurposeWebhook}}, nil},
		{"email without allow rule", []ChannelConfig{email}, nil,
			[]string{`notify channel "mail-perso" needs a network rule`, "sovereignty.network.allow", "host: smtp.example.org", "purpose: notify.email"}},
		{"email rule with wrong purpose", []ChannelConfig{email}, []AllowRule{{Host: "smtp.example.org", Purpose: PurposeWebhook}},
			[]string{"host: smtp.example.org", "purpose: notify.email"}},
		{"webhook without allow rule", []ChannelConfig{hook}, nil, []string{"host: hooks.example.org", "purpose: notify.webhook"}},
		{"disabled email needs no rule", []ChannelConfig{with(email, func(c *ChannelConfig) { c.Enabled = boolPtr(false) })}, nil, nil},
		{"disabled email still checked", []ChannelConfig{with(email, func(c *ChannelConfig) { c.Enabled = boolPtr(false); c.Port = 25 })}, nil, []string{"587"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateNotify(NotifyConfig{PageURL: "http://127.0.0.1:7331/", Channels: tc.channels}, tc.rules)
			if len(tc.want) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("want an error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q lacks %q", err, w)
				}
			}
		})
	}
	// Validate wires ValidateNotify with the policy's allow rules.
	p := Defaults()
	p.Notify.Channels = []ChannelConfig{email}
	if err := Validate(p); err == nil || !strings.Contains(err.Error(), "purpose: notify.email") {
		t.Errorf("Validate: %v", err)
	}
	p.Sovereignty.Network.Allow = rules
	if err := Validate(p); err != nil {
		t.Errorf("Validate with the rule: %v", err)
	}
	// The page link never carries a token.
	mustFail(t, func(p *Policy) { p.Notify.PageURL = "http://127.0.0.1:7331/?token=abc" }, "page_url")
}

func TestExampleConfigStillLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join("..", "..", "config.example.yaml")
	p, src, err := Load(path, dir)
	if err != nil || src != SourceFile {
		t.Fatalf("src=%q err=%v", src, err)
	}
	if err := Validate(p); err != nil {
		t.Fatalf("example invalid: %v", err)
	}
	want := Defaults()
	want.DB.OSVPath = filepath.Join(dir, "osv")
	if p.Notify.PageURL != "http://127.0.0.1:7331/" || len(p.Notify.Channels) != 0 || want.Notify.PageURL != p.Notify.PageURL {
		t.Errorf("notify = %+v", p.Notify)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The channels of the example are commented out; uncommented, they load
	// strictly and validate once their allow rules are added.
	var lines []string
	in := false
	for _, l := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(l, "notify:") {
			in = true
		}
		if in {
			if rest, ok := strings.CutPrefix(l, "  #   "); ok {
				l = "    " + rest
			} else if rest, ok := strings.CutPrefix(l, "  # channels:"); ok {
				l = "  channels:" + rest
			}
		}
		lines = append(lines, l)
	}
	uncommented := strings.Join(lines, "\n")
	if !strings.Contains(uncommented, "type: email") || !strings.Contains(uncommented, "type: webhook") || !strings.Contains(uncommented, "type: toast") {
		t.Fatalf("the example lacks the commented channels:\n%s", uncommented)
	}
	upath := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(upath, []byte(uncommented), 0o600); err != nil {
		t.Fatal(err)
	}
	q, _, err := Load(upath, dir)
	if err != nil {
		t.Fatalf("uncommented example: %v", err)
	}
	if len(q.Notify.Channels) != 3 {
		t.Fatalf("channels = %+v", q.Notify.Channels)
	}
	if err := Validate(q); err == nil || !strings.Contains(err.Error(), "needs a network rule") {
		t.Errorf("uncommented example without rules: %v", err)
	}
	q.Sovereignty.Network.Allow = []AllowRule{{Host: "smtp.example.org", Purpose: PurposeEmail}, {Host: "hooks.example.org", Purpose: PurposeWebhook}}
	if err := Validate(q); err != nil {
		t.Errorf("uncommented example with rules: %v", err)
	}
}
