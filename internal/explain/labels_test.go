package explain

import "testing"

func TestTestsLinePlural(t *testing.T) {
	for _, tc := range []struct {
		l    Lang
		n    int
		want string
	}{
		{EN, 0, "No test covers it"},
		{EN, 1, "1 test file covers the code that uses it"},
		{EN, 2, "2 test files cover the code that uses it"},
		{FR, 0, "Aucun test ne le couvre"},
		{FR, 1, "1 fichier de test couvre le code qui l'utilise"},
		{FR, 2, "2 fichiers de test couvrent le code qui l'utilise"},
	} {
		if got := TestsLine(tc.l, tc.n); got != tc.want {
			t.Errorf("%s/%d: %q, want %q", tc.l, tc.n, got, tc.want)
		}
	}
}

func TestEnumWordsBothLanguages(t *testing.T) {
	for _, l := range []Lang{EN, FR} {
		for kind, values := range map[string][]string{
			"rec":     {"auto_fix", "handoff", "report_only"},
			"jump":    {"patch", "minor", "major", "unknown", "none"},
			"quality": {"psr4", "import", "name", "low"},
			"method":  {"callsite", "reference", "none"},
		} {
			for _, v := range values {
				got := Enum(l, kind, v)
				if got == "" || got == v && v != "unknown" && v != "none" {
					t.Errorf("%s %s/%s: %q is not plain language", l, kind, v, got)
				}
			}
		}
	}
	if Enum(FR, "rec", "auto_fix") != "correction automatique possible" || Enum(EN, "quality", "psr4") != "by namespace" {
		t.Error("pinned wordings changed")
	}
}

func TestShortenStripsControlRunes(t *testing.T) {
	if got := shorten("a\x1b[31mb\x00c\n d"); got != "a[31mbc d" {
		t.Errorf("got %q", got)
	}
}
