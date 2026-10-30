package source

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/kvarot/michel/internal/policy"
)

func TestNewUserEntryValidatesLikeSourceAdd(t *testing.T) {
	pin := "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
	for _, c := range []struct {
		req  UserEntryRequest
		code string
	}{
		{UserEntryRequest{Kind: KindFeed, URL: "http://example.org/feed"}, "bad_url"},
		{UserEntryRequest{Kind: KindFeed, URL: "https://example.org/feed", Format: "json"}, "bad_format"},
		{UserEntryRequest{Kind: KindFeed}, "feed_target"},
		{UserEntryRequest{Kind: KindFeed, Repo: "not a repo", Format: "github_advisories"}, "bad_repo"},
		{UserEntryRequest{Kind: KindFeed, URL: "https://example.org/feed", Tech: []string{"Not A Tag"}}, "bad_tag"},
		{UserEntryRequest{Kind: KindOSV}, "no_ecosystem"},
		{UserEntryRequest{Kind: KindOSV, Ecosystem: "../etc"}, "bad_ecosystem"},
		{UserEntryRequest{Kind: KindPlugin, Name: "Demo"}, "no_format"},
		{UserEntryRequest{Kind: KindPlugin, Name: "Demo", Format: "xml"}, "bad_format"},
		{UserEntryRequest{Kind: KindPlugin, Format: "sarif"}, "no_name"},
		{UserEntryRequest{Kind: KindPlugin, Name: "Demo", Format: "sarif", Tool: "nmap"}, "bad_tool"},
		{UserEntryRequest{Kind: KindPlugin, Name: "Demo", Format: "sarif", Input: "report.sarif"}, "bad_input"},
		{UserEntryRequest{Kind: KindSkill, Repo: "example/skill"}, "no_repo"},
		{UserEntryRequest{Kind: KindSkill, Repo: "example/skill", Pin: "main"}, "bad_pin"},
		{UserEntryRequest{Kind: KindSkill, Repo: "example/skill", Pin: pin, Path: "../up"}, "bad_path"},
		{UserEntryRequest{Kind: KindReference, Name: "Demo"}, "bad_kind"},
		{UserEntryRequest{Kind: KindFeed, Name: "---", URL: "https://example.org/feed"}, "no_name"},
	} {
		if _, r := NewUserEntry(c.req); r == nil || r.Code != c.code {
			t.Errorf("%+v: refusal %+v, want %s", c.req, r, c.code)
		}
	}

	e, r := NewUserEntry(UserEntryRequest{Kind: KindFeed, Name: "Demo feed", URL: "https://example.org/feed.xml", Tech: []string{" nginx ", "nginx"}})
	if r != nil || e.Key != "feed.demo-feed" || e.Origin != OriginUser || e.Purpose != policy.PurposeFeed || !slices.Equal(e.Hosts, []string{"example.org"}) ||
		e.Config.Str("format") != "auto" || !slices.Equal(e.Tech, []string{"nginx"}) || e.Enabled {
		t.Errorf("feed = %+v %+v", e, r)
	}
	e, r = NewUserEntry(UserEntryRequest{Kind: KindSkill, Repo: "example/skill", Pin: pin, Path: "skills/demo"})
	if r != nil || e.Key != "skill.skill" || e.Config.Str("path") != "skills/demo" || e.Purpose != policy.PurposeRepo || !slices.Equal(e.Hosts, RepoHosts) {
		t.Errorf("skill = %+v %+v", e, r)
	}
	abs := filepath.Join(t.TempDir(), "report.sarif")
	e, r = NewUserEntry(UserEntryRequest{Kind: KindPlugin, Name: "Demo SARIF", Format: "sarif", Input: abs})
	if r != nil || e.Key != "plugin.demo-sarif" || e.Config.Str("input") != abs || e.Config.Str("tool") != "generic" || len(e.Hosts) != 0 {
		t.Errorf("plugin = %+v %+v", e, r)
	}
	e, r = NewUserEntry(UserEntryRequest{Kind: KindOSV, Ecosystem: "Hackage"})
	if r != nil || e.Key != "osv.hackage" || e.Name != "OSV Hackage" {
		t.Errorf("osv = %+v %+v", e, r)
	}
}

// TestRefusalCodesListsEveryCode keeps RefusalCodes in step with the codes
// NewUserEntry gives: the callers' tests map every code of the list.
func TestRefusalCodesListsEveryCode(t *testing.T) {
	src, err := os.ReadFile("useradd.go")
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, m := range regexp.MustCompile(`refuse\("([a-z_]+)"`).FindAllStringSubmatch(string(src), -1) {
		used[m[1]] = true
	}
	if len(used) == 0 {
		t.Fatal("no refuse call found")
	}
	for c := range used {
		if !slices.Contains(RefusalCodes, c) {
			t.Errorf("code %s is not in RefusalCodes", c)
		}
	}
	for _, c := range RefusalCodes {
		if !used[c] {
			t.Errorf("RefusalCodes lists %s, which no refusal gives", c)
		}
	}
}
