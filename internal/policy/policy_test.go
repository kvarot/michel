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
