package brief

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"text/template"

	"github.com/kvarot/michel/internal/explain"
	"github.com/kvarot/michel/internal/i18n"
)

// quote writes s as a JSON string, which is a valid YAML scalar.
func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// funcs are the helpers of brief.tmpl; they do not depend on the language, as
// the parsed template is cached by the i18n package.
func funcs() template.FuncMap {
	return template.FuncMap{
		"join": strings.Join,
		// pct writes a share (0..1) as a whole percentage.
		"pct": func(x float64) int { return int(math.Round(x * 100)) },
		// fence is a code fence longer than any run of backticks in the
		// texts it will wrap (strings, lists of strings, sites, sentences).
		"fence": func(vs ...any) string {
			longest, run := 0, 0
			for _, v := range vs {
				for _, t := range texts(v) {
					for _, r := range t {
						if r == '`' {
							run++
							longest = max(longest, run)
						} else {
							run = 0
						}
					}
					run = 0
				}
			}
			return strings.Repeat("`", max(3, longest+1))
		},
		// sitesLabel says "5 of 12" when only some sites are quoted.
		"sitesLabel": func(shown, total int) string {
			if total > shown {
				return fmt.Sprintf("%d/%d", shown, total)
			}
			return fmt.Sprint(total)
		},
	}
}

// lang falls back to English for a language the templates do not have.
func langOf(l i18n.Lang) i18n.Lang {
	if l.Valid() {
		return l
	}
	return i18n.EN
}

// body renders the sections of the brief (no front matter).
func body(b Brief, l i18n.Lang) string {
	t, err := i18n.Template(langOf(l), "brief", funcs())
	if err != nil {
		return "(brief template unavailable: " + err.Error() + ")\n"
	}
	var out bytes.Buffer
	if err := t.Execute(&out, b); err != nil {
		return "(brief template failed: " + err.Error() + ")\n"
	}
	return strings.TrimSpace(strings.ReplaceAll(out.String(), "\r\n", "\n")) + "\n"
}

// Markdown renders the brief: a YAML front matter (michel_brief: 1) and the
// sections Find, Understand, Fix and Done when, in lang.
func Markdown(b Brief, lang i18n.Lang) []byte {
	return []byte("---\n" + frontMatter(b) + "---\n" + body(b, lang))
}

// footer renders the closing section of the skill (how to report back).
func footer(l i18n.Lang) string {
	t, err := i18n.Template(langOf(l), "brief", funcs())
	if err != nil {
		return ""
	}
	f := t.Lookup("skill_footer")
	if f == nil {
		return ""
	}
	var out bytes.Buffer
	if err := f.Execute(&out, nil); err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(out.String(), "\r\n", "\n")) + "\n"
}

// texts lists the strings inside v, for the fence length.
func texts(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []string:
		return x
	case []Site:
		var out []string
		for _, s := range x {
			out = append(out, s.File, s.Snippet)
		}
		return out
	case explain.Explanation:
		return []string{x.What, x.Impact, x.Cost}
	}
	return nil
}
