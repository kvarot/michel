package source

import (
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
)

// UserEntryRequest is what a user gives to add a source of theirs (michel
// source add, the Sources page, a discovery to add).
type UserEntryRequest struct {
	Kind      Kind
	Name      string
	URL       string
	Format    string
	Repo      string
	Ecosystem string
	// Input is the full path of a plugin's fixed report ("" for none); the
	// command line makes a relative one absolute before.
	Input string
	Tool  string
	Path  string
	Pin   string
	Tech  []string
}

// Refusal says why a user entry is refused: Code names the reason (each
// caller has its own sentence for it, with or without its flags) and Args
// are the values the sentence quotes. Code is one of RefusalCodes.
type Refusal struct {
	Code string
	Args []any
}

// RefusalCodes are the codes of a Refusal. A caller maps each one to its
// sentence; the tests of the command line and of the API check that none
// is missing.
var RefusalCodes = []string{"bad_tag", "bad_url", "bad_format", "bad_repo", "feed_target", "no_ecosystem", "bad_ecosystem",
	"no_format", "bad_tool", "no_name", "bad_input", "no_repo", "bad_pin", "bad_path", "bad_kind"}

var (
	repoName  = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	commitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// RepoHosts are the hosts of a pinned repository: its state and its archive.
var RepoHosts = []string{"api.github.com", "codeload.github.com"}

// CleanRepoPath checks a folder inside a repository and returns it in slash
// form: relative, no "..", no backslash or drive.
func CleanRepoPath(p string) (string, bool) {
	if strings.ContainsAny(p, `\:`) || filepath.IsAbs(p) || strings.HasPrefix(p, "/") {
		return "", false
	}
	clean := filepath.ToSlash(filepath.Clean(p))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}

// cleanTech trims and deduplicates the technology tags.
func cleanTech(in []string) []string {
	out := []string{}
	for _, t := range in {
		if t = strings.TrimSpace(t); t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

func refuse(code string, args ...any) *Refusal { return &Refusal{Code: code, Args: args} }

// NewUserEntry checks req and builds the user entry it describes (off, with
// its hosts, purpose and settings). It does not look at the registry: the
// caller refuses a key already used.
func NewUserEntry(req UserEntryRequest) (Entry, *Refusal) {
	kind, format := req.Kind, strings.TrimSpace(req.Format)
	e := Entry{Kind: kind, Origin: OriginUser, Name: strings.TrimSpace(req.Name), Tech: cleanTech(req.Tech)}
	for _, t := range e.Tech {
		if !project.ValidTech(t) {
			return e, refuse("bad_tag", t)
		}
	}
	user := map[string]any{}
	switch kind {
	case KindFeed:
		switch {
		case req.URL != "":
			u, err := url.Parse(req.URL)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
				return e, refuse("bad_url", req.URL)
			}
			if format == "" {
				format = "auto"
			}
			if !slices.Contains([]string{"auto", "rss", "atom", "page"}, format) {
				return e, refuse("bad_format", format, string(kind), "auto, rss, atom, page")
			}
			e.URL, e.Hosts = req.URL, []string{u.Hostname()}
			if e.Name == "" {
				e.Name = u.Hostname()
			}
		case req.Repo != "" && format == "github_advisories":
			if !repoName.MatchString(req.Repo) {
				return e, refuse("bad_repo", req.Repo)
			}
			e.URL, e.Hosts = "https://github.com/"+req.Repo+"/security/advisories", []string{"api.github.com"}
			user["repo"] = req.Repo
			if e.Name == "" {
				e.Name = req.Repo
			}
		default:
			return e, refuse("feed_target")
		}
		e.Purpose = policy.PurposeFeed
		user["format"] = format
	case KindOSV:
		eco := strings.TrimSpace(req.Ecosystem)
		if eco == "" {
			return e, refuse("no_ecosystem")
		}
		if strings.ContainsAny(eco, `/\`) || strings.Contains(eco, "..") || len(eco) > 64 {
			return e, refuse("bad_ecosystem", eco)
		}
		e.Name, e.URL = "OSV "+eco, "https://osv.dev/list?ecosystem="+url.QueryEscape(eco)
		e.Hosts, e.Purpose = []string{"osv-vulnerabilities.storage.googleapis.com"}, policy.PurposeOSV
		user["ecosystem"] = eco
		e.Key = KeyFor(KindOSV, eco)
	case KindPlugin:
		if format == "" {
			return e, refuse("no_format")
		}
		if format != "sarif" && format != "trivy_json" {
			return e, refuse("bad_format", format, string(kind), "sarif, trivy_json")
		}
		tool := strings.TrimSpace(req.Tool)
		if tool == "" {
			tool = "generic"
		}
		if !slices.Contains([]string{"generic", "trivy", "semgrep", "codeql", "zap"}, tool) {
			return e, refuse("bad_tool", tool)
		}
		if e.Name == "" {
			return e, refuse("no_name")
		}
		user["format"], user["tool"], user["run"] = format, tool, false
		if in := strings.TrimSpace(req.Input); in != "" {
			if !filepath.IsAbs(in) {
				return e, refuse("bad_input")
			}
			user["input"] = filepath.Clean(in)
		}
	case KindSkill, KindMCP:
		if req.Repo == "" || req.Pin == "" {
			return e, refuse("no_repo", string(kind))
		}
		if !repoName.MatchString(req.Repo) {
			return e, refuse("bad_repo", req.Repo)
		}
		if !commitSHA.MatchString(req.Pin) {
			return e, refuse("bad_pin", req.Pin)
		}
		user["repo"], user["pinned"] = req.Repo, req.Pin
		if req.Path != "" {
			clean, ok := CleanRepoPath(req.Path)
			if !ok {
				return e, refuse("bad_path", req.Path)
			}
			user["path"] = clean
		}
		if e.Name == "" {
			e.Name = req.Repo[strings.Index(req.Repo, "/")+1:]
		}
		e.URL, e.Hosts, e.Purpose = "https://github.com/"+req.Repo, RepoHosts, policy.PurposeRepo
	default:
		return e, refuse("bad_kind", string(kind))
	}
	if e.Key == "" {
		e.Key = KeyFor(e.Kind, e.Name)
	}
	if !ValidKey(e.Key) {
		return e, refuse("no_name")
	}
	e.Config = Config{Catalog: map[string]any{}, User: user}
	return e, nil
}
