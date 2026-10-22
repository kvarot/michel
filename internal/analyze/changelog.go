package analyze

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"deps.dev/util/semver"

	"github.com/kvarot/michel/internal/scan"
)

const (
	maxExcerptBytes   = 4096
	maxBreakingLines  = 20
	maxChangelogBytes = 2 << 20
)

// NoteNoVersionHeadings starts the note of a changelog whose versions could
// not be read: the excerpt is the start of the file and breaking changes are
// not assessed.
const NoteNoVersionHeadings = "no version headings; breaking changes not assessed"

// Changelog is the part of an installed package's changelog that lies between
// the installed and the target version. It is read from the local vendor/ or
// node_modules/ copy only; nothing is fetched.
type Changelog struct {
	// Source is the changelog file read, relative to the project root with
	// forward slashes, or "".
	Source string `json:"source"`
	// Excerpt holds the sections in ]installed, target], at most 4096 bytes.
	Excerpt string `json:"excerpt"`
	// Available is true when a changelog file was read.
	Available bool `json:"available"`
	Breaking  bool `json:"breaking"`
	// BreakingLines are the trimmed excerpt lines that look like breaking
	// changes, at most 20, in order.
	BreakingLines []string `json:"breaking_lines"`
	// Note explains why the result is empty or degraded, "" otherwise.
	Note string `json:"note"`
}

// VersionsUnread tells whether the changelog was read but its version
// headings were not, so breaking changes were not assessed.
func (c Changelog) VersionsUnread() bool {
	return c.Available && strings.HasPrefix(c.Note, NoteNoVersionHeadings)
}

var (
	// Release headings are level 1 or 2 first; level 3 counts only when the
	// file has no level 1-2 version heading at all.
	headingRe  = regexp.MustCompile(`^ {0,3}#{1,2}[ \t]+(.*)$`)
	heading3Re = regexp.MustCompile(`^ {0,3}#{1,3}[ \t]+(.*)$`)
	// leadWordRe is the optional word before the version in the retry pass:
	// "## Version 2.0.0", "### Release 1.4", "## v. 3.0".
	leadWordRe = regexp.MustCompile(`(?i)^(version|release|v\.)[ \t]*`)
	fenceRe    = regexp.MustCompile("^ {0,3}(```|~~~)")
	versionRe  = regexp.MustCompile(`^\[?[vV]?(\d+\.\d+(?:\.\d+)*(?:-[0-9A-Za-z.]+)?(?:\+[0-9A-Za-z.]+)?)`)
	unrelRe    = regexp.MustCompile(`(?i)^\[?(unreleased|next)\]?$`)
	breakHead  = regexp.MustCompile(`(?i)^ {0,3}#{1,6}[ \t]*(breaking|removed)\b`)
	breakText  = regexp.MustCompile(`(?i)\b(breaking|bc break|removed|dropped support|no longer)\b`)
)

// ReadChangelog extracts the changelog sections newer than installed and up to
// target for pkg, from <manifestDir>/vendor (Packagist) or
// <manifestDir>/node_modules (npm). Section titles are ATX headings: # and ##
// first; when the file has none with a version, ### too, with an optional
// leading "Version", "Release" or "v." word. Setext headings (underlined with
// === or ---) are plain text: such a file has no readable versions, so its
// breaking changes are not assessed. When installed does not parse, there is
// no lower bound. Links are refused and control characters are removed.
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
	if !validPackageName(pkg) {
		return Changelog{Note: "invalid package name"}
	}
	manifestRel := filepath.Dir(filepath.FromSlash(manifestRelPath))
	manifestDir := filepath.Join(projectRoot, manifestRel)
	pkgDirRel := filepath.Join(manifestRel, modules, filepath.FromSlash(pkg))
	pkgDir, err := installedPackageDir(manifestDir, modules, pkg)
	switch {
	case errors.Is(err, errSymlink), errors.Is(err, errOutside):
		return Changelog{Note: "dependency folder refused: symbolic link or outside the project"}
	case err != nil:
		return Changelog{Note: "not installed locally"}
	}
	name := findChangelogFile(pkgDir)
	if name == "" {
		return Changelog{Note: "no changelog file"}
	}
	source := filepath.ToSlash(filepath.Join(pkgDirRel, name))
	f, fi, err := openRegular(manifestDir, pkgDir, name)
	if err != nil {
		if errors.Is(err, errSymlink) || errors.Is(err, errOutside) {
			return Changelog{Source: source, Note: "changelog refused: symbolic link or outside the project"}
		}
		return Changelog{Source: source, Note: "changelog unreadable"}
	}
	if fi.Size() > maxChangelogBytes {
		f.Close()
		return Changelog{Source: source, Note: "changelog too large"}
	}
	raw, err := readLimited(f, maxChangelogBytes)
	if err != nil {
		return Changelog{Source: source, Note: "changelog unreadable"}
	}
	text := strings.TrimPrefix(string(raw), string([]byte{0xEF, 0xBB, 0xBF}))
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = scan.SanitizeText(text)

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
	inRange := func(v *semver.Version) bool {
		return v.Compare(tgt) <= 0 && (instErr != nil || v.Compare(inst) > 0)
	}

	lines := strings.Split(text, "\n")
	kept, sawVersion := keepSections(lines, eco, sys, inRange, headingRe, false)
	if !sawVersion {
		kept, sawVersion = keepSections(lines, eco, sys, inRange, heading3Re, true)
	}
	var trunc bool
	if !sawVersion {
		// The start of the file is still shown, but without versions Michel
		// cannot tell which changes lie between installed and target.
		cl.Note = NoteNoVersionHeadings
		cl.Excerpt, trunc = cutExcerpt(text)
		if trunc {
			cl.Note += "; excerpt truncated"
		}
		return cl
	}
	cl.Excerpt, trunc = cutExcerpt(strings.Join(kept, "\n"))
	if strings.TrimSpace(cl.Excerpt) == "" {
		cl.Excerpt = ""
		cl.Note = "no matching sections"
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

// keepSections returns the lines of the sections whose version heading is in
// range, and whether any version heading was seen. head matches a heading and
// captures its title; leadWord allows "Version 2.0.0"-style titles.
func keepSections(lines []string, eco string, sys semver.System, inRange func(*semver.Version) bool,
	head *regexp.Regexp, leadWord bool) ([]string, bool) {
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
		} else if m := head.FindStringSubmatch(line); m != nil && fence == "" {
			title := strings.TrimSpace(m[1])
			if unrelRe.MatchString(title) {
				keeping = false
				continue
			}
			if leadWord {
				title = leadWordRe.ReplaceAllString(title, "")
			}
			if vm := versionRe.FindStringSubmatch(title); vm != nil {
				if canon := NormalizeVersion(eco, vm[1]); canon != "" {
					if v, perr := sys.Parse(canon); perr == nil {
						sawVersion = true
						keeping = inRange(v)
					}
				}
			}
		}
		if keeping {
			kept = append(kept, line)
		}
	}
	return kept, sawVersion
}

// findChangelogFile returns the best changelog file name in dir following the
// documented priority, ties broken lexically ("" when none). Only regular
// files count: a link is never read as a changelog.
func findChangelogFile(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() {
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
