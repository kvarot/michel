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

var detectors = []detector{
	{KindPrivateKey, regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----|.*$)`), 0, false},
	{KindAWSKey, regexp.MustCompile(`AKIA[0-9A-Z]{16}`), 0, false},
	{KindGitHubToken, regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}`), 0, false},
	// Stripe secret keys, JSON Web Tokens, Slack tokens.
	{KindKnownToken, regexp.MustCompile(`[sr]k_live_[A-Za-z0-9]{16,}|eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+|xox[abprs]-[A-Za-z0-9-]{8,}`), 0, false},
	// The name holds a keyword, followed only by "_..." (SECRET_KEY_BASE) or
	// nothing; the keyword may stick to what precedes it (DBPASSWORD).
	{KindEnvValue, regexp.MustCompile(`(?im)^[ 	]*(?:export[ 	]+)?([A-Z0-9_]*(?:PASSWORD|PASSWD|PASS|SECRET|TOKEN|KEY)(?:_[A-Z0-9_]*)?)[ 	]*=[ 	]*` + valueExpr), 1, false},
	{KindAssignment, regexp.MustCompile(`(?i)` + keywordExpr + `["']?\]?[ 	]*(?:=>|:|=)[ 	]*` + valueExpr), 0, false},
	// PHP: define('DB_PASSWORD', '...'), Laravel's 'key' => 'base64:...', and
	// the password, third argument of new PDO, new mysqli and mysqli_connect.
	{KindAssignment, regexp.MustCompile(`\bdefine\([ 	]*['"]([^'"\n]*(?:PASSWORD|KEY|SECRET|SALT|TOKEN)[^'"\n]*)['"][ 	]*,[ 	]*` + valueExpr), 1, true},
	{KindAssignment, regexp.MustCompile(`['"]key['"][ 	]*=>[ 	]*['"](base64:[A-Za-z0-9+/=]{16,})['"]`), 0, false},
	{KindAssignment, regexp.MustCompile(`\bnew[ 	]+\\?PDO\([^,\n]+,[^,\n]+,[ 	]*` + valueExpr), 0, true},
	{KindAssignment, regexp.MustCompile(`\b(?:new[ 	]+\\?mysqli|mysqli_connect)\([^,\n]+,[^,\n]+,[ 	]*` + valueExpr), 0, true},
	// scheme://user:password@host: only the password.
	{KindURLPassword, regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@"'<>]*:([^\s/@"'<>]+)@`), 0, false},
	{KindAbsPath, regexp.MustCompile(
		// Windows: directories may hold spaces, the last segment may not.
		`(?m)(?:^|[^A-Za-z0-9])([A-Za-z]:[\\/](?:[^\\/\r\n"'<>|*?:]+[\\/])*[^\s\\/"'<>|*?:]*)` +
			// POSIX: at least two segments, after a separator, so URLs stay out;
			// a ":" separates the entries of a list.
			`|(?:^|[\s"'(=:])(/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._@+-]+)+)`), 0, false},
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
			if len(loc) > 2 {
				a, b = -1, -1
				for g := 1 + d.skip; 2*g+1 < len(loc); g++ {
					if loc[2*g] >= 0 {
						a, b = loc[2*g], loc[2*g+1]
						// The last group of valueExpr is the value without quotes.
						unquoted = 2*g+3 >= len(loc)
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
			all = append(all, match{a, b, d.kind, isStrong(d.kind, s[a:b], unquoted)})
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
