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

// Detector kinds, in priority order: when two matches overlap, the earlier
// kind wins.
const (
	KindPrivateKey  Kind = "private_key"
	KindAWSKey      Kind = "aws_key"
	KindGitHubToken Kind = "github_token"
	KindEnvValue    Kind = "env_value"
	KindAssignment  Kind = "assignment"
	KindAbsPath     Kind = "abs_path"
)

// detector finds the secret part of a text: group is the submatch holding it
// (0 for the whole match).
type detector struct {
	kind  Kind
	re    *regexp.Regexp
	group int
}

var detectors = []detector{
	{KindPrivateKey, regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----|.*$)`), 0},
	{KindAWSKey, regexp.MustCompile(`AKIA[0-9A-Z]{16}`), 0},
	{KindGitHubToken, regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}`), 0},
	{KindEnvValue, regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?[A-Z_][A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|KEY)[ \t]*=[ \t]*["']?([^\s"']+)`), 1},
	{KindAssignment, regexp.MustCompile(`(?i)(?:password|secret|token|api_key)["']?[ \t]*(?:=>|:|=)[ \t]*["']?([^\s"',;]{8,})`), 1},
	{KindAbsPath, regexp.MustCompile(`(?:^|[^A-Za-z0-9])([A-Za-z]:[\\/][^\s"'<>|*?]+)|(?:^|[\s"'(=])(/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._@+-]+)+)`), -1},
}

// tokenPrefix starts every token; values that already are tokens (or paths
// placeholders) are never masked again.
const tokenPrefix = "[secret-"

var tokenRe = regexp.MustCompile(`\[secret-([0-9]+)\]`)

var wholeTokenRe = regexp.MustCompile(`^\[secret-[0-9]+\]$`)

// isPlaceholder reports whether v is exactly one token or "<path>": only
// those are left alone, a value that merely starts with one is still masked.
func isPlaceholder(v string) bool { return v == pathPlaceholder || wholeTokenRe.MatchString(v) }

// HasToken reports whether s contains a mask token.
func HasToken(s string) bool { return tokenRe.MatchString(s) }

type match struct {
	start, end int
	kind       Kind
}

// find returns the non-overlapping secret spans of s, ordered by position.
func find(s string) []match {
	var all []match
	for _, d := range detectors {
		for _, loc := range d.re.FindAllStringSubmatchIndex(s, -1) {
			a, b := loc[0], loc[1]
			switch {
			case d.group > 0:
				a, b = loc[2*d.group], loc[2*d.group+1]
			case d.group < 0: // abs_path: first non-empty group
				a, b = -1, -1
				for g := 1; g*2+1 < len(loc); g++ {
					if loc[2*g] >= 0 {
						a, b = loc[2*g], loc[2*g+1]
						break
					}
				}
			}
			if a < 0 || b <= a || isPlaceholder(s[a:b]) {
				continue
			}
			all = append(all, match{a, b, d.kind})
		}
	}
	// Priority: detector order, then position. Keep what does not overlap.
	rank := func(k Kind) int {
		for i, d := range detectors {
			if d.kind == k {
				return i
			}
		}
		return len(detectors)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if ri, rj := rank(all[i].kind), rank(all[j].kind); ri != rj {
			return ri < rj
		}
		return all[i].start < all[j].start
	})
	var kept []match
	for _, m := range all {
		clash := false
		for _, k := range kept {
			if m.start < k.end && k.start < m.end {
				clash = true
				break
			}
		}
		if !clash {
			kept = append(kept, m)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].start < kept[j].start })
	return kept
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
// root) and reports file, line and kind, never the value. Files outside root,
// unreadable, binary or too large are skipped. Absolute paths are not secrets
// and are not reported.
func ScanFiles(root string, rel []string) []Hit {
	var hits []Hit
	for _, r := range rel {
		fp := filepath.FromSlash(r)
		if !filepath.IsLocal(fp) {
			continue
		}
		info, err := os.Stat(filepath.Join(root, fp))
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxScanFile {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, fp))
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
