package i18n

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"text/template"
)

func TestCatalogsHaveSameKeys(t *testing.T) {
	en, fr := catalogs[EN], catalogs[FR]
	if len(en) == 0 {
		t.Fatal("the English catalog is empty")
	}
	for k, v := range en {
		if strings.TrimSpace(v) == "" {
			t.Errorf("en %s is empty", k)
		}
		if _, ok := fr[k]; !ok {
			t.Errorf("fr lacks %s", k)
		}
	}
	for k, v := range fr {
		if strings.TrimSpace(v) == "" {
			t.Errorf("fr %s is empty", k)
		}
		if _, ok := en[k]; !ok {
			t.Errorf("en lacks %s (present in fr)", k)
		}
	}
}

// A hold speaks of this fix only: an earlier one may have let things out. And
// the answer can be given on the page too; weak lines still reach Anthropic.
func TestTheWordsOfAHold(t *testing.T) {
	for _, k := range []string{"cli.fix.hold.head", "fix.msg.secret_hits.one", "fix.msg.secret_hits.other", "fix.msg.secret_hits_folder.one", "fix.msg.secret_hits_folder.other", "fix.cause.hold_stale", "fix.cause.hold_withdrawn"} {
		if !strings.Contains(catalogs[FR][k], "pour cette correction, rien n'est sorti de ton ordinateur") {
			t.Errorf("fr %s: %q", k, catalogs[FR][k])
		}
		if !strings.Contains(catalogs[EN][k], "for this fix, nothing") {
			t.Errorf("en %s: %q", k, catalogs[EN][k])
		}
	}
	if got := catalogs[FR]["cli.fix.continue.need_terminal"]; got != "Cette réponse se donne à la main, dans un terminal comme PowerShell, ou sur la page. Michel ne l'accepte pas d'un script." {
		t.Errorf("fr need_terminal: %q", got)
	}
	if got := catalogs[EN]["cli.fix.continue.need_terminal"]; !strings.Contains(got, "or on the page") {
		t.Errorf("en need_terminal: %q", got)
	}
	for _, k := range []string{"fix.msg.weak_hits.one", "fix.msg.weak_hits.other"} {
		for _, want := range []string{"sans rien qui ressemble à une vraie clé.", "et ce qu'il lit part chez Anthropic."} {
			if !strings.Contains(catalogs[FR][k], want) {
				t.Errorf("fr %s lacks %q", k, want)
			}
		}
		if !strings.Contains(catalogs[EN][k], "what it reads reaches Anthropic.") {
			t.Errorf("en %s: %q", k, catalogs[EN][k])
		}
	}
}

var verb = regexp.MustCompile(`%(\[\d+\])?[-+# 0]*\d*(\.\d+)?[a-zA-Z%]`)

func TestCatalogsUseSameFormatVerbs(t *testing.T) {
	for k, v := range catalogs[EN] {
		e, f := verb.FindAllString(v, -1), verb.FindAllString(catalogs[FR][k], -1)
		slices.Sort(e)
		slices.Sort(f)
		if !slices.Equal(e, f) {
			t.Errorf("%s: en verbs %v, fr verbs %v", k, e, f)
		}
	}
}

func TestCatalogKeysAreSnakeDotted(t *testing.T) {
	ok := regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)
	for _, k := range Keys() {
		if !ok.MatchString(k) {
			t.Errorf("key %q is not snake.dotted", k)
		}
	}
}

// withEntry adds a catalog entry for one test.
func withEntry(t *testing.T, l Lang, key, text string) {
	t.Helper()
	catalogs[l][key] = text
	t.Cleanup(func() { delete(catalogs[l], key) })
}

func TestTFallsBackToEnglishThenKey(t *testing.T) {
	withEntry(t, EN, "test.only_en", "Only in English, %s")
	if got := T(FR, "test.only_en", "ok"); got != "Only in English, ok" {
		t.Errorf("fallback to English: %q", got)
	}
	if got := T(FR, "test.missing"); got != "!test.missing!" {
		t.Errorf("missing key: %q", got)
	}
	if got := T("de", "explain.label.what"); got != "What" {
		t.Errorf("unknown language: %q", got)
	}
	if got := T(FR, "explain.label.what"); got != "Quoi" {
		t.Errorf("french: %q", got)
	}
	// Without arguments the text is returned as is, verbs included.
	if got := T(EN, "explain.label.hint"); !strings.Contains(got, "%s") {
		t.Errorf("no args must not format: %q", got)
	}
	if !Has("explain.label.what") || Has("test.missing") {
		t.Error("Has")
	}
	if keys := Keys(); !slices.IsSorted(keys) || !slices.Contains(keys, "explain.label.what") {
		t.Error("Keys must be sorted and complete")
	}
}

func TestNPluralRules(t *testing.T) {
	for _, tc := range []struct {
		l    Lang
		n    int
		want string
	}{
		{FR, 0, "!x.one!"}, {FR, 1, "!x.one!"}, {FR, 2, "!x.other!"},
		{EN, 0, "!x.other!"}, {EN, 1, "!x.one!"}, {EN, 2, "!x.other!"},
	} {
		if got := N(tc.l, "x", tc.n); got != tc.want {
			t.Errorf("%s/%d: %q, want %q", tc.l, tc.n, got, tc.want)
		}
	}
	withEntry(t, EN, "test.files.one", "one file in %[2]s")
	withEntry(t, EN, "test.files.other", "%d files in %s")
	if got := N(EN, "test.files", 3, "demo"); got != "3 files in demo" {
		t.Errorf("other: %q", got)
	}
	if got := N(EN, "test.files", 1, "demo"); got != "one file in demo" {
		t.Errorf("one: %q", got)
	}
}

func TestResolveOrder(t *testing.T) {
	for _, tc := range []struct {
		flag, policy, system string
		want                 Lang
	}{
		{"fr", "en", "en", FR},
		{"en", "fr", "fr", EN},
		{" FR ", "", "", FR},
		{"", "fr", "en", FR},
		{"", "en", "fr", EN},
		{"", "auto", "fr", FR},
		{"", "auto", "en", EN},
		{"", "", "fr", FR},
		{"", "de", "fr", FR},
		{"de", "auto", "", EN},
		{"", "", "", EN},
		{"auto", "auto", "de", EN},
	} {
		if got := Resolve(tc.flag, tc.policy, tc.system); got != tc.want {
			t.Errorf("Resolve(%q, %q, %q) = %q, want %q", tc.flag, tc.policy, tc.system, got, tc.want)
		}
	}
}

func TestLocaleFromEnv(t *testing.T) {
	for _, tc := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"LANG": "fr_FR.UTF-8"}, "fr"},
		{map[string]string{"LANG": "FR_CA"}, "fr"},
		{map[string]string{"LANG": "en_US.UTF-8"}, "en"},
		{map[string]string{"LC_ALL": "de_DE", "LANG": "fr_FR"}, "en"},
		{map[string]string{"LC_MESSAGES": "fr_BE", "LANG": "en_US"}, "fr"},
		{map[string]string{"LC_ALL": "", "LANG": "fr"}, "fr"},
		{map[string]string{}, "en"},
	} {
		if got := localeFromEnv(func(k string) string { return tc.env[k] }); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.env, got, tc.want)
		}
	}
}

func TestSystemLocaleHook(t *testing.T) {
	if s := SystemLocale(); s != "en" && s != "fr" {
		t.Errorf("SystemLocale() = %q", s)
	}
	restore := SetSystemLocaleForTest("fr")
	if SystemLocale() != "fr" {
		t.Error("hook not applied")
	}
	restore()
	if s := SystemLocale(); s != "en" && s != "fr" {
		t.Errorf("hook not restored: %q", s)
	}
}

func TestTemplateIsCachedPerLanguage(t *testing.T) {
	fm := template.FuncMap{
		"plural":       func(int, string, string) string { return "" },
		"join":         strings.Join,
		"severityWord": func(string) string { return "" },
		"day":          func(string) string { return "" },
		"pct":          func(float64) int { return 0 },
	}
	for _, l := range []Lang{EN, FR} {
		for _, name := range []string{"what", "impact", "cost"} {
			a, err := Template(l, name, fm)
			if err != nil {
				t.Fatalf("%s/%s: %v", l, name, err)
			}
			b, _ := Template(l, name, fm)
			if a != b {
				t.Errorf("%s/%s parsed twice", l, name)
			}
		}
	}
	if _, err := Template(EN, "nope", fm); err == nil {
		t.Error("missing template must fail")
	}
	if _, err := Template("de", "what", fm); err == nil {
		t.Error("unsupported language must fail")
	}
}

// A key written in code is in the copy: mask.ScanFiles only detects it, and the
// agent reads the file. The consent must not say the secrets stay.
func TestConsentDoesNotPromiseThatSecretsStay(t *testing.T) {
	for lang, want := range map[Lang]struct{ false1, false2, leaves, sensitive string }{
		FR: {"pas les secrets", "secrets sont masqués et", "part avec eux", "pas dans les fichiers que l'agent lit"},
		EN: {"not the secrets", "secrets are masked and", "goes with them", "not in the files the agent reads"},
	} {
		leaves, sensitive := T(lang, "fix.consent.what_leaves"), T(lang, "fix.consent.sensitive")
		if strings.Contains(strings.ToLower(leaves), want.false1) {
			t.Errorf("%s what_leaves still says the secrets stay: %q", lang, leaves)
		}
		if !strings.Contains(leaves, want.leaves) {
			t.Errorf("%s what_leaves does not say a written key leaves: %q", lang, leaves)
		}
		if strings.Contains(sensitive, want.false2) || !strings.Contains(sensitive, want.sensitive) {
			t.Errorf("%s sensitive does not bound the masking: %q", lang, sensitive)
		}
	}
}
