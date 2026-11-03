package mask

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The detectors above over-mask on purpose: what they find is hidden. Strength
// is a separate judgement, made on what they found: should this stop an agent?
// It never changes what is masked, and it reads only the value's shape, so a
// real key of an unusual shape can be judged weak. The texts of the page and
// the docs say so.

// minSecretLen is the shortest literal that can look like a secret.
const minSecretLen = 8

var (
	// unicodeEscape is a letter written as \uXXXX in a JSON file.
	unicodeEscape = regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)
	// referenceDefault is "${NAME:-value}": only the value can be a literal.
	referenceDefault = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*:?-(.*)\}$`)
	// templateStart is a value made by a program or a template: $name, ${...},
	// $(...), {{...}}, <...>, %s, [...]. A bcrypt hash ($2y$) is not one.
	templateStart = regexp.MustCompile(`^(?:\$[A-Za-z_{(]|[{<%\[(])`)
	// defaultWord is a word people leave as a default, with digits or not.
	defaultWord = regexp.MustCompile(`(?i)^(?:password|passwd|pass|pwd|secret|admin|root|test|user|demo|token|key|default|guest|qwerty|azerty|letmein|welcome|abc|abcd)[0-9]*[!?.]*$`)
	// wordSeparator splits a value into its words.
	wordSeparator = regexp.MustCompile(`[_\-.|:/]+`)
)

// placeholders are parts of a value that says it is an example.
var placeholders = []string{"your", "example", "changeme", "change_me", "change-me", "changethis", "placeholder", "xxx", "dummy", "sample", "replace", "insert", "todo", "fixme", "redacted"}

// unquotedCode are the characters of an unquoted value that make it code rather
// than a literal: a call, an array, the end of a statement, a member.
const unquotedCode = "()[]{};,<>."

// isStrong judges one match of a detector: a known key format, or a literal
// value that looks like a secret on a sensitive name. unquoted says an
// assignment's value had no quotes.
func isStrong(kind Kind, value string, unquoted bool) bool {
	switch kind {
	case KindPrivateKey, KindGitHubToken:
		return true
	case KindAWSKey:
		// The key AWS itself prints in its documentation.
		return !strings.HasSuffix(value, "EXAMPLE")
	case KindEnvValue, KindURLPassword:
		return looksLikeSecret(value, false)
	case KindAssignment:
		return looksLikeSecret(value, unquoted)
	}
	return false
}

// looksLikeSecret reads the shape of a literal: long enough, no space, not a
// reference, a path, a number, a default or a run of plain words.
func looksLikeSecret(value string, code bool) bool {
	if m := referenceDefault.FindStringSubmatch(value); m != nil {
		value = m[1]
	}
	if code && (strings.ContainsAny(value, unquotedCode) || strings.Contains(value, "->")) {
		return false
	}
	v := strings.TrimRight(unicodeEscape.ReplaceAllString(value, "a"), "!?.,:;`")
	if utf8.RuneCountInString(v) < minSecretLen || strings.ContainsFunc(v, unicode.IsSpace) {
		return false
	}
	if templateStart.MatchString(v) || strings.Contains(v, "://") {
		return false
	}
	for _, prefix := range []string{"/", "./", "../", "~/"} {
		if strings.HasPrefix(v, prefix) {
			return false
		}
	}
	lower := strings.ToLower(v)
	for _, p := range placeholders {
		if strings.Contains(lower, p) {
			return false
		}
	}
	if defaultWord.MatchString(v) || !hasVariety(v) {
		return false
	}
	return !plainWords(v)
}

// hasVariety says the value holds a letter and is not one character repeated
// or nearly: a number, a date, a row of stars or of zeros is not a secret.
func hasVariety(v string) bool {
	seen := map[rune]bool{}
	letter := false
	for _, r := range v {
		seen[r] = true
		letter = letter || unicode.IsLetter(r)
	}
	return letter && len(seen) >= 5
}

// plainWords says every part of the value is a word or a small number: a
// validation rule, a translation key, a region, an identifier.
func plainWords(v string) bool {
	for _, word := range wordSeparator.Split(v, -1) {
		letters, digits := 0, 0
		for _, r := range word {
			switch {
			case unicode.IsLetter(r):
				letters++
			case unicode.IsDigit(r):
				digits++
			default:
				return false
			}
		}
		if (letters > 0 && digits > 0) || digits > 3 {
			return false
		}
	}
	return true
}
