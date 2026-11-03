package mask

import (
	"regexp"
	"slices"
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

// laravelFactoryHash is the bcrypt hash of the word "password" printed in
// Laravel's old UserFactory: public, and the only hash left out.
const laravelFactoryHash = "$2y$10$" + "92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi"

var (
	// unicodeEscape is a letter written as \uXXXX in a JSON file.
	unicodeEscape = regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)
	// referenceDefault is "${NAME:-value}": only the value can be a literal.
	referenceDefault = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*:?-(.*)\}$`)
	// wholeTemplate is a value made by a template from end to end: ${...},
	// {{...}}, <...>, %...%, $(...), [...], {...}. A literal that merely starts
	// with one of these signs is not one.
	wholeTemplate = regexp.MustCompile(`^(?:\$\{.+\}|\{\{.*\}\}|<.*>|%[^%]+%|\$\(.*\)|\[.*\]|\{.*\})$`)
	// variableValue is $name, with digits only at its end: $kP9mW2xQ7vT is not one.
	variableValue = regexp.MustCompile(`^\$([A-Za-z_]+)[0-9]*$`)
	// wordPath is a path whose segments are lowercase words.
	wordPath = regexp.MustCompile(`^(?:/|\./|\.\./|~/)[a-z0-9._-]{1,24}(?:/[a-z0-9._-]{1,24})*/?$`)
	// defaultWord is a word people leave as a default, with digits or not.
	defaultWord = regexp.MustCompile(`(?i)^(?:password|passwd|pass|pwd|secret|admin|root|test|user|demo|token|key|default|guest|qwerty|azerty|letmein|welcome|abc|abcd|changeme)[0-9]*[!?.]*$`)
	// wordSeparator splits a value into its words.
	wordSeparator = regexp.MustCompile(`[_\-.|:/]+`)
	// xRun is a part that hides a value behind x letters.
	xRun = regexp.MustCompile(`^x{3,}$`)
	// joinedChangeMe makes change_me one part, before the split.
	joinedChangeMe = strings.NewReplacer("change_me", "changeme", "change-me", "changeme")
)

// placeholders are whole parts of a value that says it is an example.
var placeholders = []string{"your", "example", "changeme", "changethis", "placeholder", "sample", "replace", "insert", "todo", "fixme", "redacted"}

// testParts are whole parts of a value that says it is not for real use.
var testParts = []string{"test", "fake", "mock", "stub", "dummy"}

// notSecretPrefixes start a value that is a dependency or a version;
// validationPrefixes start a validation rule.
var (
	notSecretPrefixes  = []string{"npm:", "workspace:", "file:", "link:", "^", "~"}
	validationPrefixes = []string{"required|", "nullable|", "string|", "sometimes|"}
)

const (
	// unquotedCode are the characters of an unquoted value that make it code
	// rather than a literal: a call, an array, the end of a statement. A dot or
	// a comma does not: a key can hold them, and a member is told by its words.
	unquotedCode = "()[]{};<>"
	// envCode is the same for a line NAME=value, which is a setting as often as
	// it is code: its value can hold more signs than an assignment's.
	envCode = "();<>'\""
)

// isStrong judges one match of a detector: a known key format, or a literal
// value that looks like a secret on a sensitive name. unquoted says an
// assignment's value had no quotes.
func isStrong(kind Kind, value string, unquoted bool) bool {
	switch kind {
	case KindPrivateKey, KindGitHubToken, KindKnownToken:
		return true
	case KindAWSKey:
		// The key AWS itself prints in its documentation.
		return !strings.HasSuffix(value, "EXAMPLE")
	case KindEnvValue:
		if unquoted && strings.ContainsAny(value, envCode) {
			return false
		}
		return looksLikeSecret(value, false, !unquoted)
	case KindURLPassword:
		return looksLikeSecret(value, false, true)
	case KindAssignment:
		return looksLikeSecret(value, unquoted, !unquoted)
	}
	return false
}

// looksLikeSecret reads the shape of a value: long enough, no space, not a
// reference, a path, a number, a default or a run of plain words. code says an
// unquoted value of an assignment; written says the value is written out, in
// quotes or in an address, where a default word with digits is a real password.
func looksLikeSecret(value string, code, written bool) bool {
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
	if v == laravelFactoryHash || hasAnyPrefix(v, notSecretPrefixes) || hasAnyPrefix(v, validationPrefixes) {
		return false
	}
	if isTemplate(v) || strings.Contains(v, "://") || wordPath.MatchString(v) {
		return false
	}
	parts := wordSeparator.Split(joinedChangeMe.Replace(strings.ToLower(v)), -1)
	if slices.ContainsFunc(parts, func(p string) bool { return slices.Contains(testParts, p) }) || isExample(parts) {
		return false
	}
	if defaultWord.MatchString(v) && !(written && strings.ContainsAny(v, "0123456789")) {
		return false
	}
	return hasVariety(v) && !plainWords(v)
}

func hasAnyPrefix(v string, prefixes []string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(v, p) })
}

// isTemplate says the whole value is filled in by a program or a template.
func isTemplate(v string) bool {
	if wholeTemplate.MatchString(v) {
		return true
	}
	m := variableValue.FindStringSubmatch(v)
	return m != nil && plainWords(m[1])
}

// isExample says the value holds a placeholder and nothing beside it that could
// be a real secret: "your-key-here" is an example, "Fr4nce_xxx_99" is not.
func isExample(lowerParts []string) bool {
	found := false
	for _, part := range lowerParts {
		switch {
		case slices.Contains(placeholders, part) || xRun.MatchString(part):
			found = true
		case strings.Trim(part, "0123456789") != "" && !wordPart(part):
			return false
		}
	}
	return found
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
	return !slices.ContainsFunc(wordSeparator.Split(v, -1), func(part string) bool { return !wordPart(part) })
}

// wordPart says one part of a value is a word or a small number.
func wordPart(part string) bool {
	letters, digits := 0, 0
	for _, r := range part {
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
	return readsLikeAWord(part, letters)
}

// readsLikeAWord looks at the letters of a part: scattered capitals (3 or more,
// at least a quarter of the letters) or 6 consonants in a row make no word.
func readsLikeAWord(part string, letters int) bool {
	runes := []rune(part)
	isolated, consonants := 0, 0
	for i, r := range runes {
		if unicode.IsUpper(r) && (i == 0 || !unicode.IsUpper(runes[i-1])) && (i == len(runes)-1 || !unicode.IsUpper(runes[i+1])) {
			isolated++
		}
		// A letter outside ASCII counts as a vowel: this reads only ASCII words.
		if unicode.IsLetter(r) && r < utf8.RuneSelf && !strings.ContainsRune("aeiouyAEIOUY", r) {
			consonants++
		} else {
			consonants = 0
		}
		if consonants >= 6 {
			return false
		}
	}
	return isolated < 3 || isolated*4 < letters
}
