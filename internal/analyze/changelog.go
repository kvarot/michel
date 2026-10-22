package analyze

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	maxExcerptBytes   = 4096
	maxBreakingLines  = 20
	maxChangelogBytes = 2 << 20
)

// Changelog is the part of an installed package's changelog that lies between
// the installed and the target version. It is read from the local vendor/ or
// node_modules/ copy only; nothing is fetched.
type Changelog struct {
	// Source is the changelog file read, relative to the project root with
	// forward slashes, or "".
	Source string
	// Excerpt holds the sections in ]installed, target], at most 4096 bytes.
	Excerpt string
	// Available is true when a changelog file was read.
	Available bool
	Breaking  bool
	// BreakingLines are the trimmed excerpt lines that look like breaking
	// changes, at most 20, in order.
	BreakingLines []string
	// Note explains why the result is empty or degraded, "" otherwise.
	Note string
}

var (
	// Release headings are level 1 or 2 only; level 3 is a sub-heading.
	headingRe = regexp.MustCompile(`^ {0,3}#{1,2}[ \t]+(.*)$`)
	fenceRe   = regexp.MustCompile("^ {0,3}(```|~~~)")
	versionRe = regexp.MustCompile(`^\[?[vV]?(\d+\.\d+(?:\.\d+)*(?:-[0-9A-Za-z.]+)?(?:\+[0-9A-Za-z.]+)?)`)
	unrelRe   = regexp.MustCompile(`(?i)^\[?(unreleased|next)\]?$`)
	breakHead = regexp.MustCompile(`(?i)^ {0,3}#{1,6}[ \t]*(breaking|removed)\b`)
	breakText = regexp.MustCompile(`(?i)\b(breaking|bc break|removed|dropped support|no longer)\b`)
)

// ReadChangelog extracts the changelog sections newer than installed and up to
// target for pkg, from <manifestDir>/vendor (Packagist) or
// <manifestDir>/node_modules (npm). Limitation: only ATX headings (# and ##)
// are recognised as section titles; Setext headings (underlined with === or
// ---) are treated as plain text. When installed does not parse, there is no
// lower bound.
func ReadChangelog(projectRoot, manifestRelPath, ecosystem, pkg, installed, target string) Changelog {
	eco := ecosystem
	if strings.EqualFold(eco, "composer") {
		eco = "Packagist"
	}
	var modules string
	switch eco {
	case "Packagist":
		modules = "vendor"
	case "npm":
		modules = "node_modules"
	default:
		return Changelog{Note: "unsupported ecosystem"}
	}
	if pkg == "" || filepath.IsAbs(pkg) || strings.Contains(pkg, "..") || strings.Contains(pkg, `\`) {
		return Changelog{Note: "invalid package name"}
	}
	manifestDir := filepath.Dir(filepath.FromSlash(manifestRelPath))
	pkgDirRel := filepath.Join(manifestDir, modules, filepath.FromSlash(pkg))
	pkgDir := filepath.Join(projectRoot, pkgDirRel)
	if fi, err := os.Stat(pkgDir); err != nil || !fi.IsDir() {
		return Changelog{Note: "not installed locally"}
	}
	name := findChangelogFile(pkgDir)
	if name == "" {
		return Changelog{Note: "no changelog file"}
	}
	source := filepath.ToSlash(filepath.Join(pkgDirRel, name))
	full := filepath.Join(pkgDir, name)
	fi, err := os.Stat(full)
	if err != nil {
		return Changelog{Source: source, Note: "changelog unreadable"}
	}
	if fi.Size() > maxChangelogBytes {
		return Changelog{Source: source, Note: "changelog too large"}
	}
	raw, err := os.ReadFile(full)
	if err != nil {
		return Changelog{Source: source, Note: "changelog unreadable"}
	}
	text := strings.TrimPrefix(string(raw), string([]byte{0xEF, 0xBB, 0xBF}))
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")

	cl := Changelog{Source: source, Available: true}
	if target == "" {
		cl.Note = "no target version"
		return cl
	}
	sys, _ := systemFor(eco)
	tgt, err := sys.Parse(NormalizeVersion(eco, target))
	if err != nil {
		cl.Note = "no target version"
		return cl
	}
	inst, instErr := sys.Parse(NormalizeVersion(eco, installed))

	lines := strings.Split(text, "\n")
	var kept []string
	keeping, sawVersion := false, false
	fence := ""
	for _, line := range lines {
		if fm := fenceRe.FindStringSubmatch(line); fm != nil {
			if fence == "" {
				fence = fm[1]
			} else if fence == fm[1] {
				fence = ""
			}
		} else if m := headingRe.FindStringSubmatch(line); m != nil && fence == "" {
			title := strings.TrimSpace(m[1])
			if unrelRe.MatchString(title) {
				keeping = false
				continue
			}
			if vm := versionRe.FindStringSubmatch(title); vm != nil {
				if canon := NormalizeVersion(eco, vm[1]); canon != "" {
					if v, perr := sys.Parse(canon); perr == nil {
						sawVersion = true
						keeping = v.Compare(tgt) <= 0 && (instErr != nil || v.Compare(inst) > 0)
					}
				}
			}
		}
		if keeping {
			kept = append(kept, line)
		}
	}
	var trunc bool
	if !sawVersion {
		cl.Note = "no version headings"
		cl.Excerpt, trunc = cutExcerpt(text)
	} else {
		cl.Excerpt, trunc = cutExcerpt(strings.Join(kept, "\n"))
		if strings.TrimSpace(cl.Excerpt) == "" {
			cl.Excerpt = ""
			cl.Note = "no matching sections"
		}
	}
	if trunc {
		if cl.Note != "" {
			cl.Note += "; "
		}
		cl.Note += "excerpt truncated"
	}
	cl.BreakingLines = breakingLines(cl.Excerpt)
	cl.Breaking = len(cl.BreakingLines) > 0
	return cl
}

// findChangelogFile returns the best changelog file name in dir following the
// documented priority, ties broken lexically ("" when none).
func findChangelogFile(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	tests := []func(l string) bool{
		func(l string) bool { return strings.HasPrefix(l, "changelog") && strings.HasSuffix(l, ".md") },
		func(l string) bool { return strings.HasPrefix(l, "changes") && strings.HasSuffix(l, ".md") },
		func(l string) bool { return strings.HasPrefix(l, "history") && strings.HasSuffix(l, ".md") },
		func(l string) bool { return strings.HasPrefix(l, "changelog") },
	}
	for _, t := range tests {
		for _, n := range names {
			if t(strings.ToLower(n)) {
				return n
			}
		}
	}
	return ""
}

// cutExcerpt trims s to at most maxExcerptBytes, on a line boundary when
// possible and never inside a rune. The bool reports whether it cut.
func cutExcerpt(s string) (string, bool) {
	s = strings.TrimRight(s, "\n ")
	s = strings.TrimLeft(s, "\n")
	if len(s) <= maxExcerptBytes {
		return s, false
	}
	cut := s[:maxExcerptBytes]
	if s[maxExcerptBytes] == '\n' {
		return strings.TrimRight(cut, "\n "), true
	}
	if i := strings.LastIndex(cut, "\n"); i > 0 {
		return strings.TrimRight(cut[:i], "\n "), true
	}
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut, true
}

func breakingLines(excerpt string) []string {
	var out []string
	for _, l := range strings.Split(excerpt, "\n") {
		if breakHead.MatchString(l) || breakText.MatchString(l) {
			out = append(out, strings.TrimSpace(l))
			if len(out) == maxBreakingLines {
				break
			}
		}
	}
	return out
}
