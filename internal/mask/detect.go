package mask

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Kind names a detector.
type Kind string

// Detector kinds, in priority order: when matches overlap they are merged
// and the merged span takes the earliest kind of this list.
const (
	KindPrivateKey  Kind = "private_key"
	KindAWSKey      Kind = "aws_key"
	KindGitHubToken Kind = "github_token"
	KindKnownToken  Kind = "known_token"
	KindEnvValue    Kind = "env_value"
	KindAssignment  Kind = "assignment"
	KindURLPassword Kind = "url_password"
	KindAbsPath     Kind = "abs_path"
)

// detector finds the secret part of a text. The secret is the first
// capturing group, after skip leading groups, that took part in the match
// (a quoted value is captured without its quotes); with no group it is the
// whole match.
type detector struct {
	kind Kind
	re   *regexp.Regexp
	skip int
	// quotedOnly keeps only a value written in quotes: a wide shape must not
	// hide the code around it. A name in the skipped group is read too.
	quotedOnly bool
	// concat extends a quoted value over the literals joined to it by dots
	// ('abc' . "def"): the whole chain is hidden and judged as one value.
	concat bool
}

const (
	// valueExpr is a quoted value (double, single or backtick quote, with
	// backslash escapes, up to the closing quote on the same line), a value
	// whose quote is never closed (up to the end of the line), or an
	// unquoted value (up to whitespace). Five groups.
	valueExpr = `(?:"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)'|` + "`((?:[^`\\\\\\n]|\\\\.)*)`|[\"'`]([^\\n]*)|([^\\s\"'`]\\S*))"
	// keywordExpr are the names that make an assignment a secret. "pass" must
	// not be inside a word (compass, bypass); "key" only after a qualifier.
	keywordExpr = `(?:password|passwd|pwd|secret_?key|secret|token|api_?key|access_?key|private_?key|app_?key|(?:^|[^A-Za-z0-9])pass)`
)

// phpArg is one argument of a PHP call: quoted strings, parentheses nested up to
// two levels, and any other sign but a comma, a quote, a parenthesis or the end
// of a statement. It may cross lines.
const (
	phpStr    = `'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"`
	phpParen1 = `\((?:[^()'"]|` + phpStr + `)*\)`
	phpParen2 = `\((?:[^()'"]|` + phpStr + `|` + phpParen1 + `)*\)`
	phpArg    = `(?:'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|` + phpParen2 + `|[^,;'"()])+`
)

var detectors = []detector{
	{KindPrivateKey, regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----|.*$)`), 0, false, false},
	{KindAWSKey, regexp.MustCompile(`AKIA[0-9A-Z]{16}`), 0, false, false},
	{KindGitHubToken, regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}`), 0, false, false},
	// Stripe secret keys, JSON Web Tokens, Slack tokens.
	{KindKnownToken, regexp.MustCompile(`[sr]k_live_[A-Za-z0-9]{16,}|eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+|xox[abprs]-[A-Za-z0-9-]{8,}`), 0, false, false},
	// The name holds a keyword, followed only by "_..." (SECRET_KEY_BASE) or
	// nothing; the keyword may stick to what precedes it (DBPASSWORD).
	{KindEnvValue, regexp.MustCompile(`(?im)^[ 	]*(?:export[ 	]+)?([A-Z0-9_]*(?:PASSWORD|PASSWD|PASS|SECRET|TOKEN|KEY)(?:_[A-Z0-9_]*)?)[ 	]*=[ 	]*` + valueExpr), 1, false, false},
	{KindAssignment, regexp.MustCompile(`(?i)` + keywordExpr + `["']?[ 	]*(?:=>|:|=)[ 	]*` + valueExpr), 0, false, false},
	// PHP: define('DB_PASSWORD', '...'), Laravel's 'key' => 'base64:...', and
	// the password, third argument of new PDO, new mysqli and mysqli_connect.
	{KindAssignment, regexp.MustCompile(`\bdefine\([ 	]*['"]([^'"\n]*(?:PASSWORD|KEY|SECRET|SALT|TOKEN)[^'"\n]*)['"][ 	]*,[ 	]*` + valueExpr), 1, true, false},
	{KindAssignment, regexp.MustCompile(`['"]key['"][ 	]*=>[ 	]*['"](base64:[A-Za-z0-9+/=]{16,})['"]`), 0, false, false},
	{KindAssignment, regexp.MustCompile(`\bnew[ 	]+\\?PDO\([^,\n]+,[^,\n]+,[ 	]*` + valueExpr), 0, true, false},
	// The same, read by arguments: strings and one or two levels of parentheses are
	// skipped, so a comma inside them does not shift the password. A call that does
	// not read this way is not matched at all, never matched on the wrong argument.
	{KindAssignment, regexp.MustCompile(`(?i)\b(?:new[ 	]+\\?(?:mysqli|pdo)|mysqli_connect)[ 	]*\(` + phpArg + `,` + phpArg + `,\s*` + valueExpr), 0, true, true},
	// $config['password'] = '...': only a quoted index and a quoted value, so an
	// index by a variable, a comparison or a call is left alone.
	{KindAssignment, regexp.MustCompile(`(?i)` + keywordExpr + `["'][ 	]*\][ 	]*(?:\.=|\?\?=|=)[ 	]*` + valueExpr), 0, true, true},
	// scheme://user:password@host: only the password.
	{KindURLPassword, regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@"'<>]*:([^\s/@"'<>]+)@`), 0, false, false},
	{KindAbsPath, regexp.MustCompile(
		// Windows: directories may hold spaces, the last segment may not.
		`(?m)(?:^|[^A-Za-z0-9])([A-Za-z]:[\\/](?:[^\\/\r\n"'<>|*?:]+[\\/])*[^\s\\/"'<>|*?:]*)` +
			// POSIX: at least two segments, after a separator, so URLs stay out;
			// a ":" separates the entries of a list.
			`|(?:^|[\s"'(=:])(/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._@+-]+)+)`), 0, false, false},
}

// notSecretNames are variable names that hold a keyword by accident or hold a
// public value: monkey, donkey, turkey, hotkey, compass, bypass, surpass, and
// public keys. Keep this list short.
var notSecretNames = regexp.MustCompile(`(?i)^(?:MONKEY|DONKEY|TURKEY|HOTKEY|COMPASS|BYPASS|SURPASS|.*PUBLIC_?KEY.*)$`)

// tokenShape is the exact shape of a token Michel makes,
// "[secret-<8 hex nonce>-<n>]", whatever its nonce. A library file that
// merely says "[secret-key]" is not one.
var tokenShape = regexp.MustCompile(`\[secret-[0-9a-f]{8}-[0-9]+\]`)

// HasToken reports whether s contains a mask token of Michel's shape,
// whichever Masker made it. It is the check that no token lands in a
// commit; it is run on the raw bytes of a change, never on a masked text
// (which holds tokens by design).
func HasToken(s string) bool { return tokenShape.MatchString(s) }

// isPlaceholder reports whether v is exactly "<path>" or exactly one token of
// the Masker whose token prefix is prefix: only those are left alone. A value
// that merely starts with one, or any other token-shaped value, is masked.
func isPlaceholder(v, prefix string) bool {
	if v == pathPlaceholder {
		return true
	}
	if prefix == "" || !strings.HasPrefix(v, prefix) || !strings.HasSuffix(v, "]") {
		return false
	}
	digits := v[len(prefix) : len(v)-1]
	if digits == "" {
		return false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

var (
	braceRef = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`)
	envRef   = regexp.MustCompile(`^%env\([A-Za-z_][A-Za-z0-9_]*\)%$`)
)

// isNonValue reports whether v is not a secret: empty, a literal, or exactly
// one reference to another variable. "${X:-default}" is not a bare reference:
// the default is a value.
func isNonValue(v string) bool {
	switch strings.ToLower(v) {
	case "", "null", "true", "false":
		return true
	}
	return braceRef.MatchString(v) || envRef.MatchString(v)
}

type match struct {
	start, end int
	kind       Kind
	// strong is the judgement of isStrong, true if any match merged here is.
	strong bool
}

func rank(k Kind) int {
	for i, d := range detectors {
		if d.kind == k {
			return i
		}
	}
	return len(detectors)
}

// find returns the secret spans of s, ordered by position. Overlapping or
// touching spans are merged into one, so nothing of a value is left around a
// smaller match inside it.
func find(s, tokenPrefix string) []match {
	var all []match
	for _, d := range detectors {
		for _, loc := range d.re.FindAllStringSubmatchIndex(s, -1) {
			a, b := loc[0], loc[1]
			unquoted := false
			value := ""
			joined := false
			if len(loc) > 2 {
				a, b = -1, -1
				for g := 1 + d.skip; 2*g+1 < len(loc); g++ {
					if loc[2*g] >= 0 {
						a, b = loc[2*g], loc[2*g+1]
						// The last group of valueExpr is the value without quotes.
						unquoted = 2*g+3 >= len(loc)
						if d.concat && g-d.skip <= 3 {
							b, value, joined = joinLiterals(s, a, b)
						}
						break
					}
				}
			}
			if a < 0 || b <= a || isPlaceholder(s[a:b], tokenPrefix) {
				continue
			}
			if d.quotedOnly && unquoted {
				continue
			}
			if d.skip > 0 && notSecretNames.MatchString(s[loc[2]:loc[3]]) {
				continue
			}
			if (d.kind == KindEnvValue || d.kind == KindAssignment) && isNonValue(s[a:b]) {
				continue
			}
			if !joined {
				value = s[a:b]
			}
			all = append(all, match{a, b, d.kind, isStrong(d.kind, value, unquoted)})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].start < all[j].start })
	var merged []match
	for _, m := range all {
		if n := len(merged); n > 0 && m.start <= merged[n-1].end {
			last := &merged[n-1]
			last.end = max(last.end, m.end)
			last.strong = last.strong || m.strong
			if rank(m.kind) < rank(last.kind) {
				last.kind = m.kind
			}
			continue
		}
		merged = append(merged, m)
	}
	return merged
}

// Hit is a place where a secret was found. It never holds the value.
type Hit struct {
	File string
	Line int
	Kind Kind
	// Strong says this should stop an agent (see isStrong); a weak hit is only
	// told. It changes nothing in what is masked.
	Strong bool
}

// maxScanFile caps what ScanFiles reads of one file.
const maxScanFile = 1 << 20

// ScanFiles looks for secrets in the files rel (slash paths relative to
// root) and reports file, line and kind, never the value. Symbolic links
// (the file itself, or a folder on its way that leads outside root), files
// outside root, unreadable, binary or too large files are skipped. Absolute
// paths are not secrets and are not reported.
func ScanFiles(root string, rel []string) []Hit {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil
	}
	var hits []Hit
	for _, r := range rel {
		fp := filepath.FromSlash(r)
		if !filepath.IsLocal(fp) {
			continue
		}
		full := filepath.Join(root, fp)
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxScanFile {
			continue
		}
		if real, err := filepath.EvalSymlinks(full); err != nil || !filepath.IsLocal(mustRel(realRoot, real)) {
			continue
		}
		data, err := os.ReadFile(full)
		if err != nil || strings.IndexByte(string(data), 0) >= 0 {
			continue
		}
		text := string(data)
		for _, m := range find(text, "") {
			if m.kind == KindAbsPath {
				continue
			}
			hits = append(hits, Hit{File: r, Line: 1 + strings.Count(text[:m.start], "\n"), Kind: m.kind, Strong: m.strong})
		}
	}
	return hits
}

// mustRel returns target relative to base, or ".." when it cannot be.
func mustRel(base, target string) string {
	r, err := filepath.Rel(base, target)
	if err != nil {
		return ".."
	}
	return r
}

// literalTail is a dot and a quoted literal that follows a quoted value.
var literalTail = regexp.MustCompile(`^[ 	]*\.[ 	]*(?:"((?:[^"\\n]|\.)*)"|'((?:[^'\\n]|\.)*)')`)

// joinLiterals extends the quoted value s[a:b] over the literals joined to it
// by dots: 'abc' . "def". It returns the end of the chain (before its last
// quote), the literals joined as one text for the judgement of strength, and
// whether there was a chain. What follows a variable or a call is not a literal.
func joinLiterals(s string, a, b int) (end int, value string, joined bool) {
	value = s[a:b]
	end = b
	pos := b + 1 // after the closing quote
	for pos <= len(s) {
		loc := literalTail.FindStringSubmatchIndex(s[pos:])
		if loc == nil {
			break
		}
		ga, gb := loc[2], loc[3]
		if ga < 0 {
			ga, gb = loc[4], loc[5]
		}
		value += s[pos+ga : pos+gb]
		end = pos + gb
		pos = pos + loc[1]
		joined = true
	}
	return end, value, joined
}
