package digest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
)

// TestSupersededAndDueCarrySeverity checks that decisions to review and due
// deferrals carry the finding's severity, mapped to the known labels, so the
// page can sort them and show it.
func TestSupersededAndDueCarrySeverity(t *testing.T) {
	f := newFixture(t)
	old := now.Add(-9 * 24 * time.Hour)
	changed := f.seed(finding{pkg: "acme/lib", osv: "ACME-1", severity: "critical", status: "pending", firstSeen: old})
	odd := f.seed(finding{pkg: "acme/odd", osv: "ACME-2", severity: "moderate", status: "pending", firstSeen: old})
	due := f.seed(finding{pkg: "vuln-pkg", osv: "ACME-3", severity: "high", status: "decided", firstSeen: old})
	f.decide(decision{finding: changed, action: "defer", due: now.Add(10 * 24 * time.Hour), superAt: now.Add(-time.Hour), reason: "severity_changed"})
	f.decide(decision{finding: odd, action: "fix", superAt: now.Add(-time.Hour), reason: "fixed_version_changed"})
	f.decide(decision{finding: due, action: "defer", due: now.Add(time.Hour)})

	d := f.compute(i18n.EN, Options{})
	p := projectNamed(t, d, "demo")
	got := map[string]string{}
	for _, s := range p.Superseded {
		got[s.FindingID] = s.Severity
	}
	if len(p.Superseded) != 2 || got[changed] != "critical" || got[odd] != "unknown" {
		t.Errorf("superseded severities = %+v", p.Superseded)
	}
	if len(p.Due) != 1 || p.Due[0].FindingID != due || p.Due[0].Severity != "high" {
		t.Errorf("due = %+v", p.Due)
	}

	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"reason":"severity_changed","severity":"critical"`) ||
		!strings.Contains(string(b), `"overdue":false,"severity":"high"`) {
		t.Errorf("json = %s", b)
	}
}
