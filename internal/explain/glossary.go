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

var labels = map[Lang]map[string]string{
	EN: {
		"what": "What", "impact": "Impact", "cost": "Cost", "facts": "Facts", "path": "Path",
		"versions": "Versions", "constraint": "Constraint", "calls": "Call sites", "tests": "Tests",
		"changelog": "Changelog", "risk": "Risk", "glossary": "Glossary", "project": "project",
		"direct": "direct dependency", "transitive": "transitive, through", "unknown": "unknown",
		"installed": "installed", "fixed": "fixed", "target": "target", "none": "none",
		"hint": `Run "michel analyze --project %s" to complete this view.`,
		"more": "and %d more", "score": "score", "recommendation": "recommendation",
		"nochangelog": "not available offline", "nobreak": "no breaking change found", "breaks": "breaking changes",
		"covering": "covering test files", "term_breaking": "breaking change", "term_transitive": "transitive",
	},
	FR: {
		"what": "Quoi", "impact": "Impact", "cost": "Coût", "facts": "Faits", "path": "Chemin",
		"versions": "Versions", "constraint": "Contrainte", "calls": "Points d'appel", "tests": "Tests",
		"changelog": "Journal des modifications", "risk": "Risque", "glossary": "Glossaire", "project": "projet",
		"direct": "dépendance directe", "transitive": "transitive, via", "unknown": "inconnu",
		"installed": "installée", "fixed": "corrigées", "target": "cible", "none": "aucune",
		"hint": `Lance « michel analyze --project %s » pour compléter cette fiche.`,
		"more": "et %d de plus", "score": "note", "recommendation": "recommandation",
		"nochangelog": "indisponible hors ligne", "nobreak": "aucun changement cassant repéré", "breaks": "changements cassants",
		"covering": "fichiers de test qui couvrent", "term_breaking": "changement cassant", "term_transitive": "transitive",
	},
}

// Label returns a small piece of interface text (a heading, a hint).
func Label(lang Lang, key string) string {
	if m, ok := labels[lang]; ok {
		if s, ok := m[key]; ok {
			return s
		}
	}
	return labels[EN][key]
}
