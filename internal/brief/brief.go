// Package brief assembles the fix brief of a finding, without any AI, from
// what Michel already knows: the finding, its enrichments, the offline
// analysis, the plain-language explanation, the advisory links and the
// articles to read. The brief has three parts (find, understand, fix) and a
// closing line, in caveman style: short lines, no prose. It never holds a
// secret (every free text goes through a mask.Masker) nor an absolute path.
package brief

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/explain"
	"github.com/kvarot/michel/internal/feed"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/store"
)

// Bounds of a brief.
const (
	// SnippetLines is the longest excerpt around a call site.
	SnippetLines = 6
	// MaxSites is the number of call sites quoted.
	MaxSites = 5
	// MaxReading is the number of articles quoted.
	MaxReading = 3
	// MaxBreaking is the number of breaking-change lines quoted.
	MaxBreaking = 5
	// MaxTests is the number of covering test files quoted.
	MaxTests = 5

	maxReferences = 4
	maxLineLen    = 200
	maxSourceSize = 1 << 20
)

// Deps are the collaborators of Build. Lang is the language of the generated
// sentences (the explanation and the closing line).
type Deps struct {
	Store   *store.Store
	DataDir string
	Policy  policy.Policy
	Lang    i18n.Lang
}

// Site is one place of the user's code that uses the package, with at most
// SnippetLines lines around it (masked).
type Site struct {
	File    string `json:"file"` // relative to the project, forward slashes
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

// Brief is the content of the fix brief of one finding.
type Brief struct {
	FindingID string  `json:"finding_id"`
	ProjectID string  `json:"project_id"`
	Project   string  `json:"project"`
	Severity  string  `json:"severity"`
	CVSS      float64 `json:"cvss"`
	OSVID     string  `json:"osv_id"`
	Package   string  `json:"package"`
	Installed string  `json:"installed"`
	Fixed     string  `json:"fixed"`
	Jump      string  `json:"jump"`
	// Directness is "direct", "transitive" or "unknown"; Via lists the
	// packages that pull the vulnerable one in.
	Directness string   `json:"directness"`
	Via        []string `json:"via"`
	KEV        bool     `json:"kev"`
	EPSS       float64  `json:"epss"`
	// Risk is the remediation risk score (0 to 100) when an analysis exists.
	Risk      int      `json:"risk"`
	HasRisk   bool     `json:"has_risk"`
	Lockfiles []string `json:"lockfiles"`
	// CallSiteCount is the total number of places; CallSites are the first
	// MaxSites ones outside the tests.
	CallSiteCount int                 `json:"call_site_count"`
	CallSites     []Site              `json:"call_sites"`
	Explanation   explain.Explanation `json:"explanation"`
	References    []string            `json:"references"`
	// Reading lists at most MaxReading articles as "title - url".
	Reading        []string `json:"reading"`
	UpdateCommands []string `json:"update_commands"`
	// ChangelogRead is true when a changelog between the two versions was
	// read; Breaking are its lines that look like breaking changes.
	ChangelogRead bool     `json:"changelog_read"`
	Breaking      []string `json:"breaking"`
	CoveringTests []string `json:"covering_tests"`
	TestCmd       string   `json:"test_cmd"`
	DoneWhen      string   `json:"done_when"`
}

// Path is where the brief file of a finding lives.
func Path(dataDir, projectID, findingID string) string {
	return filepath.Join(dataDir, "briefs", projectID, findingID+".md")
}

var (
	idRe       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	pkgRe      = regexp.MustCompile(`^[@A-Za-z0-9._/~+-]{1,214}$`)
	versionRe  = regexp.MustCompile(`^[0-9A-Za-z.+_-]{1,64}$`)
	relDirRe   = regexp.MustCompile(`^[A-Za-z0-9._/ -]{1,200}$`)
	osvIDRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$`)
	cveRe      = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,10}$`)
	ghsaRe     = regexp.MustCompile(`^GHSA(-[0-9a-z]{4}){3}$`)
	bulletRe   = regexp.MustCompile(`^\s*(#{1,6}\s*|[-*+]\s+)+`)
	drivePfxRe = regexp.MustCompile(`^[A-Za-z]:`)
)

// Build assembles the brief of the finding findingID (exact id or unique
// prefix). Everything free in it goes through m (nil: a fresh Masker). It
// reads the project's files (call sites, changelog) and writes nothing.
func Build(ctx context.Context, d Deps, findingID string, m *mask.Masker) (Brief, error) {
	if m == nil {
		m = mask.New()
	}
	lang := d.Lang
	if !lang.Valid() {
		lang = i18n.EN
	}
	fi, err := findFinding(ctx, d.Store, findingID)
	if err != nil {
		return Brief{}, err
	}
	p, err := project.NewRepo(d.Store).Get(ctx, fi.ProjectID)
	if err != nil {
		return Brief{}, fmt.Errorf("cannot read the project of finding %s: %w", fi.ID, err)
	}
	a, hasA, err := analyze.NewRepo(d.Store).Get(ctx, fi.ID)
	if err != nil {
		return Brief{}, err
	}
	facts := explain.FactsFrom(fi, a, hasA)
	facts.FixLevel = p.FixLevel
	ex, err := explain.Render(lang, facts)
	if err != nil {
		return Brief{}, err
	}
	b := Brief{
		FindingID: fi.ID, ProjectID: p.ID, Project: clean(p.Name), Severity: facts.SeverityLabel, CVSS: facts.CVSS,
		OSVID: facts.OSVID, Package: facts.Package, Installed: facts.Installed, Fixed: facts.Target,
		Jump: string(facts.Jump), Directness: string(facts.Directness), Via: facts.Via,
		KEV: fi.KEV, EPSS: fi.EPSS, Lockfiles: []string{}, CallSites: []Site{}, References: []string{},
		Reading: []string{}, UpdateCommands: []string{}, Breaking: []string{}, CoveringTests: []string{},
		Explanation: explain.Explanation{What: m.Mask(ex.What), Impact: m.Mask(ex.Impact), Cost: m.Mask(ex.Cost)},
	}
	if b.Fixed == "" && len(fi.FixedVersions) > 0 {
		b.Fixed = clean(fi.FixedVersions[0])
	}
	if b.Via == nil {
		b.Via = []string{}
	}
	if b.Directness == "" {
		b.Directness = string(analyze.Unknown)
	}
	if rel := relOnly(fi.ManifestRelPath); rel != "" {
		b.Lockfiles = append(b.Lockfiles, rel)
	}
	if hasA {
		b.Risk, b.HasRisk = a.Risk.Score, true
		b.CallSiteCount = a.Calls.Count
		if a.Coverage.Count > 0 {
			for _, f := range a.Coverage.TestFiles {
				if r := relOnly(f); r != "" && len(b.CoveringTests) < MaxTests {
					b.CoveringTests = append(b.CoveringTests, r)
				}
			}
		}
	}
	if fi.Kind == "" || fi.Kind == scan.KindDependency {
		b.CallSites, b.CallSiteCount = callSites(p, fi, a, hasA, m, b.CallSiteCount)
		if b.Fixed != "" {
			cl := analyze.ReadChangelog(p.Path, fi.ManifestRelPath, fi.Ecosystem, fi.Package, fi.InstalledVersion, b.Fixed)
			b.ChangelogRead = cl.Available && !cl.VersionsUnread()
			for _, l := range cl.BreakingLines {
				if len(b.Breaking) == MaxBreaking {
					break
				}
				if l = shorten(bulletRe.ReplaceAllString(l, "")); l != "" && !slices.Contains(b.Breaking, m.Mask(l)) {
					b.Breaking = append(b.Breaking, m.Mask(l))
				}
			}
		}
		b.UpdateCommands = updateCommands(fi, b.Directness, b.Fixed)
	}
	b.References = references(fi)
	b.Reading = reading(ctx, d.Store, p, fi, lang, m)
	b.TestCmd = m.Mask(clean(p.TestCmd))
	b.DoneWhen = i18n.T(lang, "brief.done_when", b.OSVID, b.Package)
	return b, nil
}

// findFinding resolves an exact id, else a unique prefix.
func findFinding(ctx context.Context, s *store.Store, id string) (scan.Finding, error) {
	id = strings.TrimSpace(id)
	list, err := scan.NewRepo(s).FindByIDPrefix(ctx, id)
	if err != nil {
		return scan.Finding{}, err
	}
	for _, f := range list {
		if f.ID == id {
			return f, nil
		}
	}
	switch len(list) {
	case 0:
		return scan.Finding{}, fmt.Errorf("no finding has the id %q", id)
	case 1:
		return list[0], nil
	}
	return scan.Finding{}, fmt.Errorf("the id prefix %q matches %d findings", id, len(list))
}

// clean strips control characters and line breaks of one line of text.
func clean(s string) string {
	return strings.Join(strings.Fields(scan.SanitizeText(s)), " ")
}

// shorten keeps the first maxLineLen characters of a line.
func shorten(s string) string {
	s = clean(s)
	if utf8.RuneCountInString(s) <= maxLineLen {
		return s
	}
	return strings.TrimSpace(string([]rune(s)[:maxLineLen])) + "..."
}

// relOnly keeps a project-relative path with forward slashes; an absolute
// path, a drive path or one leaving the project gives "".
func relOnly(p string) string {
	p = strings.ReplaceAll(clean(p), "\\", "/")
	if p == "" || strings.HasPrefix(p, "/") || drivePfxRe.MatchString(p) {
		return ""
	}
	p = path.Clean(p)
	if p == "." || p == ".." || strings.HasPrefix(p, "../") {
		return ""
	}
	return p
}

// callSites finds the places that use the package now (the stored ones
// have no text), keeps the first MaxSites outside the tests, and quotes
// SnippetLines lines around each, masked. It returns the sites and the total.
func callSites(p project.Project, fi scan.Finding, a analyze.Analysis, hasA bool, m *mask.Masker, storedCount int) ([]Site, int) {
	var found []analyze.CallSite
	total := storedCount
	if cs, err := analyze.FindCallSites(p.Path, fi.ManifestRelPath, fi.Ecosystem, fi.Package, scan.EffectiveExclude(p)); err == nil {
		found, total = cs.Sites, cs.Count
	} else if hasA {
		found = a.Calls.Sites
	}
	sort.SliceStable(found, func(i, j int) bool { return !found[i].IsTest && found[j].IsTest })
	out := []Site{}
	for _, s := range found {
		if len(out) == MaxSites {
			break
		}
		rel := relOnly(s.File)
		if rel == "" || s.Line < 1 || s.IsTest {
			continue
		}
		snip := readSnippet(p.Path, rel, s.Line)
		if snip == "" {
			snip = s.Snippet
		}
		out = append(out, Site{File: rel, Line: s.Line, Snippet: m.Mask(strings.TrimRight(snip, "\n"))})
	}
	return out, total
}

// readSnippet reads the SnippetLines lines around line (2 before, 3 after)
// of the project's file rel. A link, a file outside the project or a file
// over maxSourceSize gives "". Lines are cut at maxLineLen.
func readSnippet(root, rel string, line int) string {
	full := filepath.Join(root, filepath.FromSlash(rel))
	fi, err := os.Lstat(full)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxSourceSize {
		return ""
	}
	rr, err1 := filepath.EvalSymlinks(root)
	rf, err2 := filepath.EvalSymlinks(full)
	if err1 != nil || err2 != nil {
		return ""
	}
	if r, err := filepath.Rel(rr, rf); err != nil || !filepath.IsLocal(r) {
		return ""
	}
	f, err := os.Open(full)
	if err != nil {
		return ""
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxSourceSize))
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	from, to := max(line-3, 0), min(line+3, len(lines)) // 0-based, to exclusive
	if from >= to {
		return ""
	}
	var sb strings.Builder
	for _, l := range lines[from:to] {
		l = strings.Map(func(r rune) rune {
			if r == '\t' {
				return ' '
			}
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, l)
		if utf8.RuneCountInString(l) > maxLineLen {
			l = string([]rune(l)[:maxLineLen])
		}
		sb.WriteString(strings.TrimRight(l, " "))
		sb.WriteByte('\n')
	}
	return sb.String()
}

// updateCommands are the commands that bring the package to the fixed
// version, from a closed list per package manager (never from free text:
// names and versions are checked first). A manifest below the project root
// gets a "cd" first.
func updateCommands(fi scan.Finding, directness, target string) []string {
	if target == "" || !pkgRe.MatchString(fi.Package) || strings.Contains(fi.Package, "..") || !versionRe.MatchString(target) {
		return []string{}
	}
	var cmds []string
	switch base := path.Base(strings.ReplaceAll(fi.ManifestRelPath, "\\", "/")); {
	case fi.Ecosystem == "Packagist":
		if directness == string(analyze.Transitive) {
			cmds = []string{"composer update " + fi.Package + " --with-dependencies"}
		} else {
			cmds = []string{"composer update " + fi.Package + ":^" + target + " --with-all-dependencies"}
		}
	case fi.Ecosystem == "npm" && base == "yarn.lock":
		cmds = []string{"yarn upgrade " + fi.Package + "@" + target}
	case fi.Ecosystem == "npm" && base == "pnpm-lock.yaml":
		cmds = []string{"pnpm update " + fi.Package + "@" + target}
	case fi.Ecosystem == "npm" && directness == string(analyze.Transitive):
		cmds = []string{"npm update " + fi.Package}
	case fi.Ecosystem == "npm":
		cmds = []string{"npm install " + fi.Package + "@" + target}
	default:
		return []string{}
	}
	if dir := path.Dir(strings.ReplaceAll(fi.ManifestRelPath, "\\", "/")); dir != "." {
		if relOnly(dir) == "" || !relDirRe.MatchString(dir) {
			return []string{}
		}
		cmds = append([]string{"cd " + dir}, cmds...)
	}
	return cmds
}

// references are the links of the advisory, built from the ids the finding
// carries (Michel keeps no copy of the advisory's own reference list).
func references(fi scan.Finding) []string {
	out := []string{}
	add := func(u string) {
		if len(out) < maxReferences {
			out = append(out, u)
		}
	}
	if osvIDRe.MatchString(fi.OSVID) {
		add("https://osv.dev/vulnerability/" + fi.OSVID)
	}
	for _, id := range append([]string{fi.OSVID}, fi.Aliases...) {
		switch {
		case cveRe.MatchString(id):
			add("https://nvd.nist.gov/vuln/detail/" + id)
		case ghsaRe.MatchString(id):
			add("https://github.com/advisories/" + id)
		}
	}
	return out
}

// reading lists at most MaxReading articles to read about the project's
// technologies, those that name the package first.
func reading(ctx context.Context, s *store.Store, p project.Project, fi scan.Finding, lang i18n.Lang, m *mask.Masker) []string {
	tech := append(append([]string{}, p.Tech...), p.TechAuto...)
	items, err := feed.NewRepo(s).ListToRead(ctx, time.Time{}, false, tech)
	if err != nil || len(items) == 0 {
		return []string{}
	}
	short := strings.ToLower(path.Base(fi.Package))
	named := func(it feed.Item) bool { return short != "" && strings.Contains(strings.ToLower(it.Title), short) }
	sort.SliceStable(items, func(i, j int) bool { return named(items[i]) && !named(items[j]) })
	out := []string{}
	for _, it := range items {
		if len(out) == MaxReading {
			break
		}
		u := strings.TrimSpace(it.URL)
		if !(strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")) || strings.ContainsAny(u, " \t\r\n") {
			continue
		}
		title := shorten(feed.Title(lang, it))
		if title == "" {
			continue
		}
		out = append(out, m.Mask(title)+" - "+u)
	}
	return out
}

var errBadID = errors.New("the finding id is not a plain identifier")

// shortID is the first 8 characters of a finding id.
func shortID(id string) (string, error) {
	if !idRe.MatchString(id) {
		return "", errBadID
	}
	if len(id) > 8 {
		id = id[:8]
	}
	return id, nil
}

// frontMatter is the structured head of the brief (YAML, keys in English).
func frontMatter(b Brief) string {
	var sb bytes.Buffer
	kv := func(k, v string) { fmt.Fprintf(&sb, "%s: %s\n", k, v) }
	kv("michel_brief", "1")
	kv("finding", yamlStr(b.FindingID))
	kv("severity", yamlStr(b.Severity))
	kv("cvss", fmt.Sprintf("%g", b.CVSS))
	kv("kev", map[bool]string{true: "yes", false: "no"}[b.KEV])
	kv("epss", fmt.Sprintf("%g", b.EPSS))
	kv("package", yamlStr(b.Package))
	kv("installed", yamlStr(b.Installed))
	kv("fixed", yamlStr(b.Fixed))
	kv("jump", yamlStr(b.Jump))
	kv("path", yamlStr(b.Directness))
	if b.HasRisk {
		kv("risk", fmt.Sprint(b.Risk))
	} else {
		kv("risk", "unknown")
	}
	return sb.String()
}

var plainYAML = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._@/+~-]*$`)

// yamlStr writes s as a YAML scalar: plain when it is simple, else as a
// JSON string (which YAML reads).
func yamlStr(s string) string {
	if s == "" {
		return `""`
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return quote(s) // 1.10 would be read as a number
	}
	if plainYAML.MatchString(s) {
		switch strings.ToLower(s) {
		case "yes", "no", "true", "false", "null", "on", "off", "y", "n":
		default:
			return s
		}
	}
	return quote(s)
}
