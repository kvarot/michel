package digest

import (
	"embed"
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"path"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/i18n"
)

// The templates are hand-written per language with the same structure; the
// sentences shared with other renderings (title, banner, reasons) come from
// the catalog through the template functions.
//
//go:embed templates/*/*.tmpl
var templates embed.FS

// MaxToastBody is the longest toast body, in characters.
const MaxToastBody = 200

// funcs are the template functions for d, in d's language.
func funcs(d Digest) map[string]any {
	lang := d.Lang
	return map[string]any{
		"join": strings.Join,
		"sum": func(m map[string]int) int {
			n := 0
			for _, v := range m {
				n += v
			}
			return n
		},
		// day writes an RFC 3339 date or a YYYY-MM-DD day in lang's layout.
		"day": func(s string) string {
			for _, layout := range []string{time.RFC3339, "2006-01-02"} {
				if t, err := time.Parse(layout, s); err == nil {
					return t.UTC().Format(dateLayout(lang))
				}
			}
			return s
		},
		"reason": func(code string) string {
			if k := "digest.reason." + code; i18n.Has(k) {
				return i18n.T(lang, k)
			}
			return i18n.T(lang, "digest.reason.unknown")
		},
		"empty": func() string { return i18n.N(lang, "digest.empty_projects", d.EmptyProjects) },
		"exploitedDecided": func() string {
			return i18n.N(lang, "digest.exploited_decided", d.ExploitedDecided)
		},
		"catalogLine":  func() string { return CatalogLine(lang, d.Catalog) },
		"previousData": func() string { return i18n.T(lang, "digest.catalog.previous_data") },
		"stale": func() string {
			days := int(d.Until.Sub(d.OSVFetchedAt) / (24 * time.Hour))
			return i18n.T(lang, "digest.osv_stale", days)
		},
	}
}

func source(d Digest, name string) (string, error) {
	if !d.Lang.Valid() {
		return "", fmt.Errorf("language %q is not supported (use en or fr)", d.Lang)
	}
	raw, err := templates.ReadFile(path.Join("templates", string(d.Lang), name))
	if err != nil {
		return "", fmt.Errorf("digest template %s/%s is missing: %w", d.Lang, name, err)
	}
	return string(raw), nil
}

// RenderText writes d as plain text (terminal, email alternative).
func RenderText(d Digest) (string, error) {
	src, err := source(d, "text.tmpl")
	if err != nil {
		return "", err
	}
	t, err := template.New("text").Funcs(funcs(d)).Parse(src)
	if err != nil {
		return "", fmt.Errorf("digest template %s/text.tmpl is invalid: %w", d.Lang, err)
	}
	var sb strings.Builder
	if err := t.Execute(&sb, d); err != nil {
		return "", fmt.Errorf("digest template %s/text.tmpl failed: %w", d.Lang, err)
	}
	return strings.TrimRight(sb.String(), "\n") + "\n", nil
}

// RenderHTML writes d as a simple HTML page (inline CSS only, no <script>, no <img>, no link but PageURL); every value is escaped.
func RenderHTML(d Digest) (string, error) {
	src, err := source(d, "html.tmpl")
	if err != nil {
		return "", err
	}
	t, err := htmltemplate.New("html").Funcs(funcs(d)).Parse(src)
	if err != nil {
		return "", fmt.Errorf("digest template %s/html.tmpl is invalid: %w", d.Lang, err)
	}
	var sb strings.Builder
	if err := t.Execute(&sb, d); err != nil {
		return "", fmt.Errorf("digest template %s/html.tmpl failed: %w", d.Lang, err)
	}
	return sb.String(), nil
}

// RenderJSON writes d as versioned JSON ({"michel_digest": 1, ...}); empty sections are left out.
func RenderJSON(d Digest) ([]byte, error) { return json.Marshal(d) }

// ToastLines returns the toast's title (d.Title) and body: the project that
// needs the most attention (else the one with the most new findings) as
// "<project>: N new, M to review", at most MaxToastBody characters; "" when
// nothing is new nor to review.
func ToastLines(d Digest) (title, body string) {
	best, bestNew, bestReview := -1, 0, 0
	for i, p := range d.Projects {
		news, review := 0, p.Attention
		for _, pkg := range p.New {
			news += len(pkg.FindingIDs)
		}
		if news+review == 0 {
			continue
		}
		if best < 0 || review > bestReview || (review == bestReview && news > bestNew) {
			best, bestNew, bestReview = i, news, review
		}
	}
	if best < 0 {
		return d.Title, ""
	}
	body = i18n.N(d.Lang, "digest.toast.body", bestNew, d.Projects[best].Name, bestReview)
	if utf8.RuneCountInString(body) > MaxToastBody {
		r := []rune(body)
		body = string(r[:MaxToastBody-1]) + "…"
	}
	return d.Title, body
}
