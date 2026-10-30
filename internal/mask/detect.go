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
	KindEnvValue    Kind = "env_value"
	KindAssignment  Kind = "assignment"
	KindAbsPath     Kind = "abs_path"
)

// detector finds the secret part of a text. When the expression has
// capturing groups, the secret is the first group that took part in the
// match (a quoted value is captured without its quotes); otherwise it is the
// whole match.
type detector struct {
	kind Kind
	re   *regexp.Regexp
}

const (
	// value is a quoted string (up to the closing quote on the same line)
	// or, unquoted, everything up to whitespace.
	valueExpr = `(?:"([^"\n]*)"|'([^'\n]*)'|([^\s]\S*))`
	// keywordExpr are the names that make an assignment a secret.
	keywordExpr = `(?:password|passwd|pwd|secret|token|api_?key|access_?key|private_?key)`
)

var detectors = []detector{
	{KindPrivateKey, regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----|.*$)`)},
	{KindAWSKey, regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{KindGitHubToken, regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}`)},
	{KindEnvValue, regexp.MustCompile(`(?im)^[ \t]*(?:export[ \t]+)?(?:[A-Z0-9_]*_)?(?:PASSWORD|SECRET|TOKEN|KEY)[ \t]*=[ \t]*` + valueExpr)},
	{KindAssignment, regexp.MustCompile(`(?i)` + keywordExpr + `["']?[ \t]*(?:=>|:|=)[ \t]*` + valueExpr)},
	{KindAbsPath, regexp.MustCompile(
		// Windows: directories may hold spaces, the last segment may not.
		`(?m)(?:^|[^A-Za-z0-9])([A-Za-z]:[\\/](?:[^\\/\r\n"'<>|*?:]+[\\/])*[^\s\\/"'<>|*?:]*)` +
			// POSIX: at least two segments, after a separator, so URLs stay out;
			// a ":" separates the entries of a list.
			`|(?:^|[\s"'(=:])(/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._@+-]+)+)`)},
}

// tokenShape is any "[secret-...]" string, whatever its nonce.
var tokenShape = regexp.MustCompile(`\[secret-[0-9A-Za-z-]+\]`)

var wholeTokenShape = regexp.MustCompile(`^\[secret-[0-9A-Za-z-]+\]$`)

// HasToken reports whether s contains anything shaped like a mask token,
// whoever made it. It is the check that no token lands in a commit.
func HasToken(s string) bool { return tokenShape.MatchString(s) }

// isPlaceholder reports whether v is exactly one token or "<path>": only
// those are left alone, a value that merely starts with one is still masked.
func isPlaceholder(v string) bool { return v == pathPlaceholder || wholeTokenShape.MatchString(v) }

// isNonValue reports whether v is not a secret: empty, a literal or a
// reference to another variable.
func isNonValue(v string) bool {
	switch strings.ToLower(v) {
	case "", "null", "true", "false":
		return true
	}
	return strings.HasPrefix(v, "${") || strings.HasPrefix(v, "%env(")
}

type match struct {
	start, end int
	kind       Kind
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
func find(s string) []match {
	var all []match
	for _, d := range detectors {
		for _, loc := range d.re.FindAllStringSubmatchIndex(s, -1) {
			a, b := loc[0], loc[1]
			if len(loc) > 2 {
				a, b = -1, -1
				for g := 1; 2*g+1 < len(loc); g++ {
					if loc[2*g] >= 0 {
						a, b = loc[2*g], loc[2*g+1]
						break
					}
				}
			}
			if a < 0 || b <= a || isPlaceholder(s[a:b]) {
				continue
			}
			if (d.kind == KindEnvValue || d.kind == KindAssignment) && isNonValue(s[a:b]) {
				continue
			}
			all = append(all, match{a, b, d.kind})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].start < all[j].start })
	var merged []match
	for _, m := range all {
		if n := len(merged); n > 0 && m.start <= merged[n-1].end {
			last := &merged[n-1]
			last.end = max(last.end, m.end)
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
		for _, m := range find(text) {
			if m.kind == KindAbsPath {
				continue
			}
			hits = append(hits, Hit{File: r, Line: 1 + strings.Count(text[:m.start], "\n"), Kind: m.kind})
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
