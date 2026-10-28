package readers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kvarot/michel/internal/gitrepo"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sourceupdate"
)

const headSHA = "3333333333333333333333333333333333333333"

func fakeGitHubAPI(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/example/skill":
			w.Write([]byte(`{"stargazers_count": 3, "pushed_at": "2026-10-20T10:00:00Z", "archived": false, "default_branch": "main"}`))
		case "/repos/example/skill/commits/main":
			w.Write([]byte(`{"sha": "` + headSHA + `"}`))
		case "/repos/example/skill/releases/latest":
			w.Write([]byte(`{"tag_name": "v1.2.0"}`))
		case "/search/repositories":
			w.Write([]byte(`{"items": [{"full_name": "example/skill", "stargazers_count": 3}, {"full_name": "example/mcp", "stargazers_count": 9}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(gitrepo.SetBaseURLsForTest(srv.URL, srv.URL))
}

func TestRepoReaderMarksNewVersionThenDiscovers(t *testing.T) {
	fakeGitHubAPI(t)
	d := deps(t,
		policy.AllowRule{Host: "api.github.com", Purpose: policy.PurposeRepo}, policy.AllowRule{Host: "codeload.github.com", Purpose: policy.PurposeRepo},
		policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeRepo},
		policy.AllowRule{Host: "api.github.com", Purpose: policy.PurposeDiscover}, policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeDiscover})
	d.Budget = &sourceupdate.Budget{Remaining: 50}
	ctx := context.Background()
	if _, err := d.Repo.Upsert(ctx, source.Entry{Key: "skill.example", Kind: source.KindSkill, Origin: source.OriginUser, Name: "Example",
		Hosts: []string{"api.github.com", "codeload.github.com"}, Purpose: policy.PurposeRepo, Enabled: true,
		Config: source.Config{User: map[string]any{"repo": "example/skill", "pinned": "1111111111111111111111111111111111111111"}}}); err != nil {
		t.Fatal(err)
	}
	if err := d.Repo.SetEnabled(ctx, "discover.github", true); err != nil {
		t.Fatal(err)
	}
	rep, err := sourceupdate.Run(ctx, d, nil, "")
	if err != nil {
		t.Fatalf("%v %+v", err, rep)
	}
	if len(rep.NewVersions) != 1 || rep.NewVersions[0].Key != "skill.example" || rep.NewVersions[0].To != headSHA {
		t.Errorf("new versions = %+v", rep.NewVersions)
	}
	e, _ := d.Repo.Get(ctx, "skill.example")
	if e.Status["latest_release"] != "v1.2.0" || e.Status["head_sha"] != headSHA {
		t.Errorf("status = %v", e.Status)
	}
	if rep.DiscoverNew != 1 {
		t.Errorf("discover new = %d (%+v)", rep.DiscoverNew, rep)
	}
	list, _ := gitrepo.NewDiscoveryRepo(d.Store).List(ctx, "new")
	if len(list) != 1 || list[0].Repo != "example/mcp" {
		t.Errorf("discoveries = %+v", list)
	}
	if d.Budget.Remaining != 50-3-2 {
		t.Errorf("budget left = %d", d.Budget.Remaining)
	}
}

func TestRepoReaderSkipsAPluginWithoutRepoConsent(t *testing.T) {
	d := deps(t)
	ctx := context.Background()
	e, err := d.Repo.Get(ctx, "plugin.trivy")
	if err != nil {
		t.Fatal(err)
	}
	res, err := (repoReader{}).Read(ctx, e, d)
	if err != nil || res.Skipped != sourceupdate.SkipNoRepoConsent {
		t.Errorf("res = %+v err %v", res, err)
	}
}
