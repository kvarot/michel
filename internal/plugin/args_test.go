package plugin

import (
	"slices"
	"strings"
	"testing"
)

func TestTrivyArgsAreMisconfigOnlyAndOffline(t *testing.T) {
	got := TrivyArgs("out.sarif", "/p", "/cache")
	want := []string{"fs", "--scanners", "misconfig", "--format", "sarif", "--output", "out.sarif", "--skip-db-update",
		"--skip-java-db-update", "--skip-check-update", "--offline-scan", "--cache-dir", "/cache", "/p"}
	if !slices.Equal(got, want) {
		t.Errorf("TrivyArgs = %q", got)
	}
	if strings.Contains(strings.Join(got, " "), "vuln") {
		t.Error("Trivy must not scan for vulnerabilities: OSV does")
	}
}

func TestSemgrepArgsDisableMetrics(t *testing.T) {
	got := SemgrepArgs("out.sarif", "/p", "/rules")
	want := []string{"scan", "--sarif", "--output", "out.sarif", "--metrics=off", "--disable-version-check", "--config", "/rules", "/p"}
	if !slices.Equal(got, want) {
		t.Errorf("SemgrepArgs = %q", got)
	}
}

func TestForEntryPicksTheProvider(t *testing.T) {
	for _, tc := range []struct{ tool, format, kind string }{
		{"trivy", "sarif", KindMisconfig}, {"semgrep", "sarif", KindCode}, {"codeql", "sarif", KindCode},
		{"zap", "sarif", KindWeb}, {"generic", "trivy_json", KindCode},
	} {
		p, err := ForEntry(pluginEntry("plugin."+tc.tool, tc.tool, tc.format, false))
		if err != nil || p.Tool() != tc.tool || p.Kind() != tc.kind || p.Key() != "plugin."+tc.tool {
			t.Errorf("%s: %v %v", tc.tool, p, err)
		}
	}
	if _, err := ForEntry(pluginEntry("plugin.x", "nmap", "sarif", false)); err == nil {
		t.Error("unknown tool accepted")
	}
	if _, err := ForEntry(pluginEntry("plugin.x", "trivy", "xml", false)); err == nil {
		t.Error("unknown format accepted")
	}
}
