package api

import (
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
)

// The title of an exposure comes from the catalog: what Michel saw, and the
// firewall stays an "if".
func TestExposureTitleIsInFrench(t *testing.T) {
	for osv, want := range map[string][2]string{
		"exposed_database": {"Une base de données semble ouverte à tous sur ce serveur",
			"Michel le déduit du numéro d'accès qu'il voit sur le serveur, sans se connecter à ce service. Elle est joignable depuis l'extérieur si aucun pare-feu (le filtre qui décide qui peut s'y connecter) ne la bloque. D'habitude, personne dehors n'a besoin d'y accéder : si c'est le cas ici, c'est une porte d'entrée possible vers tes données."},
		"exposed_cache": {"Un cache (une mémoire rapide qu'utilisent souvent les sites) semble ouvert à tous sur ce serveur",
			"Michel le déduit du numéro d'accès qu'il voit sur le serveur, sans se connecter à ce service. Il est joignable depuis l'extérieur si aucun pare-feu (le filtre qui décide qui peut s'y connecter) ne le bloque. D'habitude, personne dehors n'a besoin d'y accéder : si c'est le cas ici, c'est une porte d'entrée possible vers tes données."},
	} {
		f := scan.Finding{Kind: scan.KindServerExposure, OSVID: osv, Package: "5432", ManifestRelPath: "exposure:5432",
			SeverityLabel: "medium", Summary: "english summary"}
		v := targetFindingView(i18n.FR, "michel", f)
		if v.Title != want[0] || v.Explain != want[1] {
			t.Errorf("%s: %q / %q", osv, v.Title, v.Explain)
		}
		en := targetFindingView(i18n.EN, "michel", f)
		if strings.Contains(en.Title, "semble") || en.Title == "english summary" || !strings.Contains(en.Explain, "firewall") {
			t.Errorf("%s en: %q / %q", osv, en.Title, en.Explain)
		}
		if v.Severity != "medium" {
			t.Errorf("%s: severity %q", osv, v.Severity)
		}
	}
}

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
