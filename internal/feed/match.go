package feed

import (
	"context"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

// MatchTech compares an item with the declared technologies: matched lists
// the declared tags its title names as whole words, whatever the case;
// toRead is true when a tag of entryTech is declared or matched is not
// empty. matched is sorted, nil when empty.
func MatchTech(title string, entryTech, declared []string) (matched []string, toRead bool) {
	lower := strings.ToLower(title)
	for _, tag := range declared {
		if tag != "" && containsWord(lower, strings.ToLower(tag)) && !slices.Contains(matched, tag) {
			matched = append(matched, tag)
		}
	}
	slices.Sort(matched)
	if len(matched) > 0 {
		return matched, true
	}
	for _, t := range entryTech {
		if slices.Contains(declared, t) {
			return nil, true
		}
	}
	return nil, false
}

// containsWord reports whether word occurs in s with no letter nor digit
// right before or after it.
func containsWord(s, word string) bool {
	for from := 0; from <= len(s)-len(word); {
		i := strings.Index(s[from:], word)
		if i < 0 {
			return false
		}
		i += from
		before, _ := utf8.DecodeLastRuneInString(s[:i])
		after, _ := utf8.DecodeRuneInString(s[i+len(word):])
		if !wordRune(before) && !wordRune(after) {
			return true
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		from = i + size
	}
	return false
}

func wordRune(r rune) bool {
	return r != utf8.RuneError && (unicode.IsLetter(r) || unicode.IsDigit(r))
}

// DeclaredAll is every technology the user declared or Michel detected: the
// tags of the active projects (declared and from their manifests) and the
// global ones, sorted and unique.
func DeclaredAll(ctx context.Context, s *store.Store) ([]string, error) {
	projects, err := project.NewRepo(s).List(ctx)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, p := range projects {
		if p.Active {
			out = append(out, p.Tech...)
			out = append(out, p.TechAuto...)
		}
	}
	global, err := source.ListTech(ctx, s)
	if err != nil {
		return nil, err
	}
	out = append(out, global...)
	slices.Sort(out)
	return slices.Compact(out), nil
}
