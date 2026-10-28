package readers

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kvarot/michel/internal/gitrepo"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sourceupdate"
)

func init() { sourceupdate.Register(repoReader{}) }

// githubAPIHost is the host of the repository status requests.
const githubAPIHost = "api.github.com"

// repoReader reads the GitHub status of the skills, MCP servers and plugins
// that name a repository, and runs the discovery of discover.github (a
// reference entry). The other references are not read. Every request spends
// the update's GitHub budget. A plugin has no host of its own: its status
// is read only when a consent already allows api.github.com for
// source.repo, never on its own.
type repoReader struct{}

func (repoReader) Kinds() []source.Kind {
	return []source.Kind{source.KindSkill, source.KindMCP, source.KindPlugin, source.KindReference}
}

func (repoReader) Read(ctx context.Context, e source.Entry, deps sourceupdate.Deps) (sourceupdate.Result, error) {
	if e.Kind == source.KindReference {
		if strings.HasPrefix(e.Key, "discover.") {
			return discover(ctx, e, deps)
		}
		return sourceupdate.Result{Skipped: sourceupdate.SkipNoReader}, nil
	}
	repo := e.Config.Str("repo")
	if repo == "" {
		return sourceupdate.Result{Skipped: sourceupdate.SkipNoReader}, nil
	}
	if e.Kind == source.KindPlugin {
		if ok, _ := deps.Gateway.Allowed(githubAPIHost, policy.PurposeRepo); !ok {
			return sourceupdate.Result{Skipped: sourceupdate.SkipNoRepoConsent}, nil
		}
	}
	owner, name, err := gitrepo.SplitRepo(repo)
	if err != nil {
		return sourceupdate.Result{}, fmt.Errorf("source %s: %w", e.Key, err)
	}
	token, err := githubToken(deps.Secrets)
	if err != nil {
		return sourceupdate.Result{}, err
	}
	st, err := gitrepo.Status(ctx, deps.Gateway.Client(policy.PurposeRepo), token, owner, name, deps.Budget)
	if res, done := budgetOrLimit(err); done {
		return res, nil
	}
	if err != nil {
		return sourceupdate.Result{}, err
	}
	if deps.Now != nil {
		st.CheckedAt = deps.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	pinned := ""
	if e.Kind != source.KindPlugin {
		pinned = e.Config.Str("pinned")
	}
	return sourceupdate.Result{Items: 1, Status: gitrepo.StatusMap(st, pinned)}, nil
}

// discover searches the entry's topics and keeps the repositories the
// registry does not have yet. Its status counts the new ones (discover_new).
func discover(ctx context.Context, e source.Entry, deps sourceupdate.Deps) (sourceupdate.Result, error) {
	token, err := githubToken(deps.Secrets)
	if err != nil {
		return sourceupdate.Result{}, err
	}
	found, derr := gitrepo.Discover(ctx, deps.Gateway.Client(policy.PurposeDiscover), token, e.Config.List("topics"), deps.Budget)
	if derr != nil && !errors.Is(derr, gitrepo.ErrBudget) && !errors.Is(derr, gitrepo.ErrRateLimited) {
		return sourceupdate.Result{}, derr
	}
	known, err := gitrepo.KnownRepos(ctx, deps.Repo)
	if err != nil {
		return sourceupdate.Result{}, err
	}
	n, err := gitrepo.NewDiscoveryRepo(deps.Store).Save(ctx, found, known, deps.Now())
	if err != nil {
		return sourceupdate.Result{}, err
	}
	res := sourceupdate.Result{Items: len(found), Status: map[string]any{"discover_new": n, "found": len(found),
		"checked_at": deps.Now().UTC().Format("2006-01-02T15:04:05Z")}}
	if r, done := budgetOrLimit(derr); done {
		res.Skipped = r.Skipped
	}
	return res, nil
}

// budgetOrLimit turns a spent budget or a GitHub rate limit into a skipped
// read.
func budgetOrLimit(err error) (sourceupdate.Result, bool) {
	switch {
	case errors.Is(err, gitrepo.ErrBudget):
		return sourceupdate.Result{Skipped: sourceupdate.SkipRateBudget}, true
	case errors.Is(err, gitrepo.ErrRateLimited):
		return sourceupdate.Result{Skipped: sourceupdate.SkipRateLimited}, true
	}
	return sourceupdate.Result{}, false
}

// githubToken reads the GitHub token; none set means public requests. The
// value never reaches an error.
func githubToken(secrets secret.Store) (string, error) {
	if secrets == nil {
		return "", nil
	}
	v, err := secrets.Get(gitrepo.GitHubTokenSecret)
	if errors.Is(err, secret.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("cannot read the secret %s: %w", gitrepo.GitHubTokenSecret, err)
	}
	return strings.TrimSpace(string(v)), nil
}
