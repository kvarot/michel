package gitrepo

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/kvarot/michel/internal/source"
)

// reposDir is the folder of the extracted archives of a source.
func reposDir(dataDir, key string) string {
	return filepath.Join(dataDir, "sources", "repos", key)
}

// Fetch downloads the archive of the commit sha of owner/repo and extracts
// it into <dataDir>/sources/repos/<key>/<sha>/, which it returns. A folder
// already there is used as is, without any request. The archive is
// extracted into a temporary folder renamed into place at the end: a bad
// archive leaves nothing behind. No token goes with the download (the
// archives are public) and no redirect is followed.
func Fetch(ctx context.Context, client *http.Client, dataDir, key, owner, repo, sha string) (string, error) {
	return fetchPath(ctx, client, dataDir, key, owner, repo, sha, "")
}

// fetchPath is Fetch limited to the folder sub of the repository (see
// extract). The cached folder belongs to the source key, whose path setting
// is the same from one call to the next.
func fetchPath(ctx context.Context, client *http.Client, dataDir, key, owner, repo, sha, sub string) (string, error) {
	if !source.ValidKey(key) {
		return "", fmt.Errorf("%w: %q", source.ErrInvalidKey, key)
	}
	if _, _, err := SplitRepo(owner + "/" + repo); err != nil {
		return "", err
	}
	if !ValidSHA(sha) {
		return "", fmt.Errorf("%w: %q", ErrBadSHA, clip(sha))
	}
	if dataDir == "" {
		return "", errors.New("no data folder to keep the archive in")
	}
	if client == nil {
		return "", errors.New("no HTTP client: build it with the egress gateway")
	}
	base := reposDir(dataDir, key)
	dir := filepath.Join(base, sha)
	if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
		return dir, nil
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", fmt.Errorf("cannot create the folder of the archives: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ArchiveURL(owner, repo, sha), nil)
	if err != nil {
		return "", errors.New("cannot build the request")
	}
	c := *client // the caller's client is copied, not changed
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return "", fmt.Errorf("the download of %s/%s failed: %w", owner, repo, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode != http.StatusOK:
		return "", fmt.Errorf("the download of %s/%s at %s: the server answered %d %s", owner, repo, sha[:7], resp.StatusCode, http.StatusText(resp.StatusCode))
	case resp.ContentLength > limits.archive:
		return "", fmt.Errorf("%w: more than %d bytes compressed", ErrTooLarge, limits.archive)
	}
	tmp, err := os.MkdirTemp(base, ".fetch-")
	if err != nil {
		return "", fmt.Errorf("cannot create the folder of the archive: %w", err)
	}
	if _, err := extract(resp.Body, tmp, sub); err != nil {
		os.RemoveAll(tmp)
		return "", fmt.Errorf("the archive of %s/%s at %s: %w", owner, repo, sha[:7], err)
	}
	if err := os.Rename(tmp, dir); err != nil {
		os.RemoveAll(tmp)
		if fi, serr := os.Stat(dir); serr == nil && fi.IsDir() {
			return dir, nil // another run got there first
		}
		return "", fmt.Errorf("cannot keep the archive: %w", err)
	}
	return dir, nil
}
