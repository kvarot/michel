package plugin

import (
	"os"
	"testing"
)

func TestParseTrivyJSONMisconfigAndSkipsKnownCVEs(t *testing.T) {
	f, err := os.Open("testdata/trivy-misconfig.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out, skipped, err := ParseTrivyJSON(f, map[string]bool{"CVE-2026-0001": true})
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 {
		t.Errorf("skippedKnown = %d, want 1", skipped)
	}
	if len(out) != 2 {
		t.Fatalf("%d findings, want 2 (the passed check, the target outside the project and the known CVE are left out): %+v", len(out), out)
	}
	m := out[0]
	if m.RuleID != "DS002" || m.Kind != KindMisconfig || m.Severity != "high" || m.Location != "Dockerfile:1" ||
		m.Message != "Image user should not be 'root': Specify at least 1 USER command in Dockerfile with non-root user as argument" {
		t.Errorf("misconfiguration = %+v", m)
	}
	v := out[1]
	if v.RuleID != "CVE-2026-0002" || v.Kind != KindVulnerability || v.Severity != "high" || v.CVSS != 7.5 ||
		v.Location != "package-lock.json" || len(v.Aliases) != 1 || v.Aliases[0] != "CVE-2026-0002" {
		t.Errorf("vulnerability = %+v", v)
	}
}
