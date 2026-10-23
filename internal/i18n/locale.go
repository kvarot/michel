package i18n

import "strings"

// Resolve picks the language: flag, then policy (only "en" or "fr"; "auto"
// and "" fall through), then system, then EN. Unknown values are skipped.
func Resolve(flag, policy, system string) Lang {
	for _, v := range []string{flag, policy} {
		if l := Lang(strings.ToLower(strings.TrimSpace(v))); l.Valid() {
			return l
		}
	}
	if strings.ToLower(strings.TrimSpace(system)) == string(FR) {
		return FR
	}
	return EN
}

// systemLocale is replaced in tests through SetSystemLocaleForTest.
var systemLocale = detectSystemLocale

// SystemLocale returns "fr" or "en" from the OS (LANG/LC_ALL/LC_MESSAGES;
// GetUserDefaultUILanguage on Windows).
func SystemLocale() string { return systemLocale() }

// SetSystemLocaleForTest makes SystemLocale return v until restore is called.
// Tests only.
func SetSystemLocaleForTest(v string) (restore func()) {
	prev := systemLocale
	systemLocale = func() string { return v }
	return func() { systemLocale = prev }
}

// localeFromEnv reads the POSIX locale variables in their order of
// precedence: the first non-empty one decides, "fr..." means French.
func localeFromEnv(getenv func(string) string) string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			if strings.HasPrefix(strings.ToLower(v), "fr") {
				return "fr"
			}
			return "en"
		}
	}
	return "en"
}
