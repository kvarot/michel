package api

import (
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
)

// A package finding reads in the page's language, whatever English summary
// the scan stored.
func TestServerPackageTitleFollowsTheLanguage(t *testing.T) {
	f := scan.Finding{Kind: scan.KindServerPackage, OSVID: "DEBIAN-CVE-1", Package: "glibc", InstalledVersion: "2.41-1",
		Summary: "glibc 2.41-1 is affected by DEBIAN-CVE-1 (installed: libc6)"}
	fr := targetFindingView(i18n.FR, "michel", f).Title
	if strings.Contains(fr, "is affected") || !strings.Contains(fr, "glibc 2.41-1") || !strings.Contains(fr, "DEBIAN-CVE-1") || !strings.Contains(fr, "faille") {
		t.Errorf("fr title %q", fr)
	}
	en := targetFindingView(i18n.EN, "michel", f).Title
	if !strings.Contains(en, "glibc 2.41-1") || !strings.Contains(en, "DEBIAN-CVE-1") || strings.Contains(en, "faille") {
		t.Errorf("en title %q", en)
	}
	f.FixedVersions = []string{"2.41-2"}
	if got := targetFindingView(i18n.FR, "michel", f).Title; !strings.Contains(got, "2.41-2") {
		t.Errorf("fixed version missing: %q", got)
	}
}
