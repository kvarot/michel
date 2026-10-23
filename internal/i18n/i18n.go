// Package i18n holds every piece of text Michel shows to people, in English
// (the reference) and French (hand-written, tutoiement). Messages live in a
// flat catalog per language; the explanation sentences are templates.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
	"sync"
	"text/template"
)

//go:embed catalog/*.json templates/*/*.tmpl
var files embed.FS

// Lang is a supported language.
type Lang string

const (
	EN Lang = "en"
	FR Lang = "fr"
)

// Valid tells whether l is a supported language.
func (l Lang) Valid() bool { return l == EN || l == FR }

// catalogs maps a language to its messages, loaded once from the embedded
// JSON files. A broken catalog is a build defect, so loading panics.
var catalogs = map[Lang]map[string]string{EN: mustLoad(EN), FR: mustLoad(FR)}

func mustLoad(l Lang) map[string]string {
	raw, err := files.ReadFile("catalog/" + string(l) + ".json")
	if err != nil {
		panic(fmt.Sprintf("i18n: catalog %s is missing: %v", l, err))
	}
	m := map[string]string{}
	if err := json.Unmarshal(raw, &m); err != nil {
		panic(fmt.Sprintf("i18n: catalog %s is invalid: %v", l, err))
	}
	return m
}

func lookup(lang Lang, key string) (string, bool) {
	if s, ok := catalogs[lang][key]; ok {
		return s, true
	}
	s, ok := catalogs[EN][key]
	return s, ok
}

// format applies args only when there are some, so a text with verbs can be
// returned as is for the caller to format.
func format(s string, args []any) string {
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}

// T returns the catalog entry for key in lang, formatted with args
// (fmt.Sprintf). Missing in lang → EN → "!"+key+"!".
func T(lang Lang, key string, args ...any) string {
	s, ok := lookup(lang, key)
	if !ok {
		return "!" + key + "!"
	}
	return format(s, args)
}

// N picks key+".one" when n == 1 (or n == 0 in French), else key+".other",
// and formats with n first then args. A text without any verb is returned as
// is; a text that skips n uses explicit indexes ("%[2]s").
func N(lang Lang, key string, n int, args ...any) string {
	k := key + ".other"
	if n == 1 || (lang == FR && n == 0) {
		k = key + ".one"
	}
	s, ok := lookup(lang, k)
	if !ok {
		return "!" + k + "!"
	}
	if !strings.Contains(s, "%") {
		return s
	}
	return fmt.Sprintf(s, append([]any{n}, args...)...)
}

// Has reports whether key exists in EN.
func Has(key string) bool {
	_, ok := catalogs[EN][key]
	return ok
}

// Keys lists every EN key, sorted.
func Keys() []string {
	keys := make([]string, 0, len(catalogs[EN]))
	for k := range catalogs[EN] {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// templates caches the parsed explanation templates by "lang/name".
var templates sync.Map

// Template returns the parsed explanation template name ("what" | "impact" |
// "cost") for lang (cached). funcs is used on the first parse only.
func Template(lang Lang, name string, funcs template.FuncMap) (*template.Template, error) {
	if !lang.Valid() {
		return nil, fmt.Errorf("language %q is not supported (use en or fr)", lang)
	}
	file := path.Join("templates", string(lang), name+".tmpl")
	if t, ok := templates.Load(file); ok {
		return t.(*template.Template), nil
	}
	raw, err := files.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("explanation template %s is missing: %w", file, err)
	}
	t, err := template.New(name).Funcs(funcs).Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("explanation template %s is invalid: %w", file, err)
	}
	actual, _ := templates.LoadOrStore(file, t)
	return actual.(*template.Template), nil
}
