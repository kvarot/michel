package explain

import "github.com/kvarot/michel/internal/i18n"

// Term returns the one-line definition of a glossary term (catalog entry
// "glossary."+key), "" when unknown.
func Term(lang Lang, key string) string {
	if !i18n.Has("glossary." + key) {
		return ""
	}
	return i18n.T(lang, "glossary."+key)
}

// Terms lists the glossary keys.
func Terms() []string {
	return []string{"cve", "cvss", "kev", "transitive", "lockfile", "breaking", "semver"}
}
