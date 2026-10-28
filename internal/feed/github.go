package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/source"
)

// githubAPI is the GitHub REST API; tests point it at a local server.
var githubAPI = "https://api.github.com"

// GitHubTokenSecret is the secret whose value, when set, goes with the
// GitHub requests (Authorization: Bearer).
const GitHubTokenSecret = "github-token"

// repoPattern is an owner/name pair of GitHub.
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)

// fetchGitHub reads the published security advisories of the entry's repo
// setting. The request carries only owner/name, spends one request of the
// budget, and never follows a redirect (it may carry the token).
func fetchGitHub(ctx context.Context, deps Deps, e source.Entry) (body []byte, etag string, err error) {
	repo := e.Config.Str("repo")
	if !repoPattern.MatchString(repo) || strings.Contains(repo, "..") {
		return nil, "", fmt.Errorf("source %s has no valid repo setting (owner/name), got %q", e.Key, scan.SanitizeText(repo))
	}
	headers := map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
	if deps.Secrets != nil {
		tok, err := deps.Secrets.Get(GitHubTokenSecret)
		switch {
		case err == nil:
			if t := strings.TrimSpace(string(tok)); t != "" {
				headers["Authorization"] = "Bearer " + t
			}
		case !errors.Is(err, secret.ErrNotFound):
			return nil, "", fmt.Errorf("cannot read the secret %s: %w", GitHubTokenSecret, err)
		}
	}
	if deps.TakeGitHub != nil && !deps.TakeGitHub() {
		return nil, "", ErrRateBudget
	}
	url := githubAPI + "/repos/" + repo + "/security-advisories?state=published&per_page=50"
	body, _, etag, err = fetch(ctx, deps.Client, url, e.LastReadETag, headers, false)
	if err != nil {
		return nil, "", fmt.Errorf("GitHub advisories of %s: %w", repo, err)
	}
	return body, etag, nil
}

// GitHubAdvisories reads the answer of the repository security advisories
// API: one item per advisory, its severity and packages in the summary.
type GitHubAdvisories struct{}

type ghAdvisory struct {
	GHSAID          string `json:"ghsa_id"`
	Summary         string `json:"summary"`
	HTMLURL         string `json:"html_url"`
	PublishedAt     string `json:"published_at"`
	Severity        string `json:"severity"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
	} `json:"vulnerabilities"`
}

// Parse reads at most MaxItemsPerRead advisories.
func (GitHubAdvisories) Parse(body []byte, e source.Entry) ([]Item, error) {
	var list []ghAdvisory
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("not a list of GitHub advisories: %w", err)
	}
	out := []Item{}
	for _, a := range list {
		if len(out) == MaxItemsPerRead {
			break
		}
		guid := cleanGUID(a.GHSAID)
		if guid == "" {
			continue
		}
		parts := []string{}
		if s := cleanText(a.Severity, 20); s != "" {
			parts = append(parts, s)
		}
		pkgs := []string{}
		for _, v := range a.Vulnerabilities {
			if n := cleanText(v.Package.Name, 100); n != "" && len(pkgs) < 10 {
				pkgs = append(pkgs, n)
			}
		}
		if len(pkgs) > 0 {
			parts = append(parts, strings.Join(pkgs, ", "))
		}
		out = append(out, Item{GUID: guid, Title: cleanText(a.Summary, maxTitle), URL: cleanURL(a.HTMLURL, ""),
			PublishedAt: parseDate(a.PublishedAt), Summary: truncate(strings.Join(parts, " · "), MaxSummary)})
	}
	return out, nil
}
