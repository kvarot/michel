// Package gitrepo handles the sources that live in a GitHub repository:
// skills and MCP servers (kinds skill and mcp) and the repository status of
// the plugins. It downloads a pinned commit's archive from codeload, extracts
// it as untrusted data under the data folder (traversal, links and special
// files refused, sizes and counts capped, nothing executable), shows what an
// installation would do, installs a skill into the user's skills folder with
// a marker file, reads the repository's public status for the daily update,
// and finds new repositories by GitHub topic ("to discover").
//
// Nothing from an archive is ever run or imported by Michel. Every request
// goes through a client built by the egress gateway (purpose source.repo,
// or source.discover for the search) and carries only owner/name (and the
// topics); the GitHub token, when set, is never followed by a redirect,
// never written in an error, an audit event or a JSON answer.
package gitrepo

import (
	"errors"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/source"
)

// Bounds of an archive: its compressed size, the bytes and files written.
const (
	MaxArchiveBytes   int64 = 50 << 20
	MaxExtractedBytes int64 = 200 << 20
	MaxFiles                = 5000
)

// Bounds of what is read through without being written (the members outside
// a skill's folder): a gzip bomb cannot keep Michel busy for ever.
const (
	maxScannedBytes   int64 = 1 << 30
	maxScannedMembers       = 100000
)

// MarkerFile is the file Michel writes in an installed skill's folder; a
// folder without it (or with another source's key) is never touched.
const MarkerFile = ".michel-source"

// GitHubTokenSecret is the secret whose value, when set, goes with the
// GitHub API requests.
const GitHubTokenSecret = "github-token"

var (
	ErrTraversal     = errors.New("the archive holds a path that leaves its folder")
	ErrSymlink       = errors.New("the archive holds a link: Michel refuses links in a repository it installs")
	ErrSpecialFile   = errors.New("the archive holds a device or another special file")
	ErrTooLarge      = errors.New("the archive is too large")
	ErrTooManyFiles  = fmt.Errorf("the archive holds too many files: Michel extracts at most %d", MaxFiles)
	ErrForeignDir    = errors.New("the target folder exists and was not installed by Michel for this source")
	ErrInsideProject = errors.New("the skills folder is inside a project Michel scans")
	ErrBadName       = errors.New("the skill's name cannot be a folder name")
	ErrOldFolderKept = errors.New("the skill moved to its new folder, but the previous folder could not be removed")
	ErrBadRepo       = errors.New("the repository setting is not owner/name")
	ErrBadSHA        = errors.New("the commit is not a full 40-character sha")
	ErrBadPath       = errors.New("the path setting leaves the repository")
	ErrNoFolder      = errors.New("the skill's folder is not in the archive")
	ErrNotInstalled  = errors.New("this source is not installed")
	ErrWrongKind     = errors.New("only a skill or an MCP server can be installed")
	ErrBudget        = errors.New("the GitHub request budget is spent")
	ErrRateLimited   = errors.New("GitHub asked to slow down")
)

// Endpoints; tests point them at a local server.
var (
	apiBase      = "https://api.github.com"
	codeloadBase = "https://codeload.github.com"
)

// SetBaseURLsForTest points the GitHub API and the archive downloads at
// local servers and returns the function that restores them. Tests only.
func SetBaseURLsForTest(api, codeload string) (restore func()) {
	oldAPI, oldLoad := apiBase, codeloadBase
	apiBase, codeloadBase = api, codeload
	return func() { apiBase, codeloadBase = oldAPI, oldLoad }
}

// limits are the caps applied by extract; tests lower them.
var limits = struct {
	archive, extracted int64
	files              int
}{MaxArchiveBytes, MaxExtractedBytes, MaxFiles}

// setLimitsForTest lowers the caps; it returns the restore function.
func setLimitsForTest(archive, extracted int64, files int) func() {
	old := limits
	limits.archive, limits.extracted, limits.files = archive, extracted, files
	return func() { limits = old }
}

var (
	ownerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
	namePattern  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	shaPattern   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// skillName is a folder name on every system: one segment, no dots
	// only, no separator, no drive or stream colon.
	skillName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// validSkillName reports whether name can be a skill's folder on every
// system: one plain segment, not dots only, not ending in a dot or a space,
// and not a Windows reserved device name (CON, PRN, AUX, NUL, COM1-9,
// LPT1-9, any case, with or without an extension).
func validSkillName(name string) bool {
	if !skillName.MatchString(name) || strings.Trim(name, ".") == "" || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	base := strings.ToUpper(name)
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	switch base {
	case "CON", "PRN", "AUX", "NUL":
		return false
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return false
	}
	return true
}

// SplitRepo checks an owner/name setting and returns its parts.
func SplitRepo(repo string) (owner, name string, err error) {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || !ownerPattern.MatchString(owner) || !namePattern.MatchString(name) || strings.Trim(name, ".") == "" {
		return "", "", fmt.Errorf("%w: %q", ErrBadRepo, repo)
	}
	return owner, name, nil
}

// ValidSHA reports whether sha is a full lowercase commit sha.
func ValidSHA(sha string) bool { return shaPattern.MatchString(sha) }

// ArchiveURL is the address of the archive of a commit.
func ArchiveURL(owner, repo, sha string) string {
	return codeloadBase + "/" + owner + "/" + repo + "/tar.gz/" + sha
}

// cleanSub checks the path setting of an entry: "" (the whole repository)
// or a relative folder inside it, in slash form.
func cleanSub(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "." {
		return "", nil
	}
	if strings.ContainsAny(p, "\\:\x00") || strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("%w: %q", ErrBadPath, p)
	}
	c := path.Clean(p)
	if c == ".." || strings.HasPrefix(c, "../") || c == "." {
		return "", fmt.Errorf("%w: %q", ErrBadPath, p)
	}
	return c, nil
}

// FileInfo is one extracted file, its path in slash form.
type FileInfo struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// License is the licence found in a repository: SPDX is "unknown" when no
// file is found or none of the known texts matches.
type License struct {
	SPDX string `json:"spdx"`
	File string `json:"file"`
}

// Trust is what the last daily status says about a repository. Archived is
// "yes", "no", or "" when the repository was never checked.
type Trust struct {
	Stars     int    `json:"stars"`
	PushedAt  string `json:"pushed_at"`
	Archived  string `json:"archived"`
	InCatalog bool   `json:"in_catalog"`
}

// Preview is what an installation would bring and do, shown before consent.
type Preview struct {
	Key   string     `json:"key"`
	Repo  string     `json:"repo"`
	SHA   string     `json:"sha"`
	Files []FileInfo `json:"files"`
	// License is the licence detected in the archive; Declared the one the
	// catalog or the user wrote ("" or "unknown" when none).
	License  License `json:"license"`
	Declared string  `json:"declared_license"`
	// Head is the first lines of SKILL.md (or README.md), cleaned.
	Head  []string `json:"head"`
	Trust Trust    `json:"trust"`
	// WillWrite is the folder a skill is copied to; "" for an MCP server,
	// which writes nothing outside the data folder.
	WillWrite string `json:"will_write"`
	// OldDir is the installed skill folder that the installation replaces
	// and removes when this version has another name; "" otherwise.
	OldDir string `json:"old_dir"`
	// Launch is the line to run to add an MCP server to Claude Code; ""
	// when the launch command is not known.
	Launch string `json:"launch"`
	// Downloads tells that the launch command fetches code when it starts
	// (npx, uvx, docker...), out of Michel's control.
	Downloads bool `json:"downloads"`
}

// Diff is what an upgrade changes, paths relative to the skill's folder.
type Diff struct {
	From string `json:"from"`
	To   string `json:"to"`
	// OldDir and NewDir are the installed skill folder and the one the new
	// version goes to (they differ when its name changed; "" for an MCP
	// server).
	OldDir      string   `json:"old_dir"`
	NewDir      string   `json:"new_dir"`
	Added       []string `json:"added"`
	Changed     []string `json:"changed"`
	Removed     []string `json:"removed"`
	SkillMDDiff string   `json:"skill_md_diff"`
}

// Deps are what the installation needs. Client must come from
// egress.Gateway.Client(policy.PurposeRepo). SkillsDir is the user's skills
// folder (~/.claude/skills by default, DefaultSkillsDir); Forbidden lists the
// folders Michel must never write under (the scanned projects).
type Deps struct {
	Repo      *source.Repo
	Audit     *audit.Logger
	Client    *http.Client
	DataDir   string
	SkillsDir string
	Forbidden []string
	Now       func() time.Time
	// Actor is the audit actor ("cli" when empty).
	Actor string
}

func (d Deps) now() time.Time {
	if d.Now == nil {
		return time.Now()
	}
	return d.Now()
}

func (d Deps) actor() string {
	if d.Actor == "" {
		return "cli"
	}
	return d.Actor
}
