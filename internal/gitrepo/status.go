package gitrepo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/sourceupdate"
)

// maxAPIBytes bounds one GitHub API answer.
const maxAPIBytes = 2 << 20

// RepoStatus is the public state of a repository, read by the daily update.
// NewVersion is HeadSHA != the pinned commit (set by StatusMap).
type RepoStatus struct {
	Stars         int    `json:"stars"`
	PushedAt      string `json:"pushed_at"`
	Archived      bool   `json:"archived"`
	DefaultBranch string `json:"default_branch"`
	HeadSHA       string `json:"head_sha"`
	LatestRelease string `json:"latest_release"`
	CheckedAt     string `json:"checked_at"`
	NewVersion    bool   `json:"new_version_available"`
}

// getJSON reads one GitHub API answer into out. The token, when not "",
// goes in the Authorization header; no redirect is followed, so it never
// reaches another address. notFound is true on a 404 (out untouched). A
// 403 or 429 is ErrRateLimited.
func getJSON(ctx context.Context, client *http.Client, rawURL, token string, out any) (notFound bool, err error) {
	if client == nil {
		return false, errors.New("no HTTP client: build it with the egress gateway")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false, errors.New("cannot build the request")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	c := *client // the caller's client is copied, not changed
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL wrapper: it may carry a query
		}
		return false, fmt.Errorf("the request to GitHub failed: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return true, nil
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
		return false, ErrRateLimited
	case resp.StatusCode != http.StatusOK:
		return false, fmt.Errorf("GitHub answered %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIBytes+1))
	if err != nil {
		return false, fmt.Errorf("cannot read the answer of GitHub: %w", err)
	}
	if len(b) > maxAPIBytes {
		return false, fmt.Errorf("%w: GitHub's answer is over %d bytes", ErrTooLarge, maxAPIBytes)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return false, fmt.Errorf("cannot read the answer of GitHub: %w", err)
		}
	}
	return false, nil
}

// Status reads the public state of owner/repo in three requests: the
// repository, the head commit of its default branch and its latest release
// (a repository without release is fine). The three requests are taken from
// budget at once: when it holds fewer, nothing is sent and the error is
// ErrBudget.
func Status(ctx context.Context, client *http.Client, token, owner, repo string, budget *sourceupdate.Budget) (RepoStatus, error) {
	if _, _, err := SplitRepo(owner + "/" + repo); err != nil {
		return RepoStatus{}, err
	}
	if !budget.Take(3) {
		return RepoStatus{}, ErrBudget
	}
	base := apiBase + "/repos/" + owner + "/" + repo
	var r struct {
		Stars         int    `json:"stargazers_count"`
		PushedAt      string `json:"pushed_at"`
		Archived      bool   `json:"archived"`
		DefaultBranch string `json:"default_branch"`
	}
	nf, err := getJSON(ctx, client, base, token, &r)
	if err != nil {
		return RepoStatus{}, err
	}
	if nf {
		return RepoStatus{}, fmt.Errorf("GitHub does not know the repository %s/%s", owner, repo)
	}
	st := RepoStatus{Stars: r.Stars, PushedAt: scan.SanitizeText(r.PushedAt), Archived: r.Archived,
		DefaultBranch: scan.SanitizeText(r.DefaultBranch), CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	if st.DefaultBranch == "" || len(st.DefaultBranch) > 255 {
		return RepoStatus{}, fmt.Errorf("GitHub gave no usable default branch for %s/%s", owner, repo)
	}
	var c struct {
		SHA string `json:"sha"`
	}
	if nf, err := getJSON(ctx, client, base+"/commits/"+url.PathEscape(st.DefaultBranch), token, &c); err != nil {
		return RepoStatus{}, err
	} else if nf || !ValidSHA(c.SHA) {
		return RepoStatus{}, fmt.Errorf("GitHub gave no head commit for %s/%s", owner, repo)
	}
	st.HeadSHA = c.SHA
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if _, err := getJSON(ctx, client, base+"/releases/latest", token, &rel); err != nil {
		return RepoStatus{}, err
	}
	if t := scan.SanitizeText(rel.TagName); len(t) <= 100 {
		st.LatestRelease = t
	}
	return st, nil
}

// StatusMap is the status stored on an entry: the fields of st, and
// new_version {from, to} when a commit is pinned and the head differs (the
// mark read by the digest and source.Entry.NewVersion). A plugin has no
// pinned commit and is never marked.
func StatusMap(st RepoStatus, pinned string) map[string]any {
	st.NewVersion = pinned != "" && st.HeadSHA != "" && st.HeadSHA != pinned
	m := map[string]any{
		"stars": st.Stars, "pushed_at": st.PushedAt, "archived": st.Archived, "default_branch": st.DefaultBranch,
		"head_sha": st.HeadSHA, "latest_release": st.LatestRelease, "checked_at": st.CheckedAt,
		"new_version_available": st.NewVersion,
	}
	if st.NewVersion {
		m["new_version"] = map[string]any{"from": pinned, "to": st.HeadSHA}
	}
	return m
}
