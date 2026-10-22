package explain

var glossary = map[Lang]map[string]string{
	EN: {
		"cve":        "a public identifier for a known security flaw",
		"cvss":       "a 0 to 10 score of how severe a flaw is",
		"kev":        "a list of flaws that attackers are known to exploit in the wild",
		"transitive": "a package your project does not ask for itself, but that another package needs",
		"lockfile":   "the file that records the exact versions installed",
		"breaking":   "a change that can make code written for the old version stop working",
		"semver":     "the major.minor.patch numbering of versions",
	},
	FR: {
		"cve":        "un identifiant public pour une faille de sécurité connue",
		"cvss":       "une note de 0 à 10 qui dit la gravité d'une faille",
		"kev":        "une liste de failles que des attaquants exploitent réellement",
		"transitive": "un paquet que ton projet ne demande pas lui-même, mais dont un autre paquet a besoin",
		"lockfile":   "le fichier qui garde les versions exactes installées",
		"breaking":   "un changement qui peut empêcher le code écrit pour l'ancienne version de fonctionner",
		"semver":     "la numérotation des versions en majeur.mineur.correctif",
	},
}

// Term returns the one-line definition of a glossary term, "" when unknown.
func Term(lang Lang, key string) string {
	if m, ok := glossary[lang]; ok {
		return m[key]
	}
	return glossary[EN][key]
}

// Terms lists the glossary keys.
func Terms() []string {
	return []string{"cve", "cvss", "kev", "transitive", "lockfile", "breaking", "semver"}
}
