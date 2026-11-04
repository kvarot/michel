package gitremote

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	canary = "canari-git-7391"
	branch = "michel/fix-01jabc23"
)

// accepted is the table of addresses Parse reads (spec, R21). An empty clean
// means the address comes back unchanged.
var accepted = []struct {
	raw, clean string
	provider   Provider
	scheme     string
	host       string
	port       int
	path       string
	credential bool
	link       string
}{
	{raw: "https://github.com/demo/app.git", provider: GitHub, scheme: "https", host: "github.com", path: "demo/app.git",
		link: "https://github.com/demo/app/pull/new/" + branch},
	{raw: "git@bitbucket.org:demo/app.git", provider: Bitbucket, scheme: "scp", host: "bitbucket.org", path: "demo/app.git",
		link: "https://bitbucket.org/demo/app/pull-requests/new?source=" + branch + "&t=1"},
	{raw: "ssh://git@gitlab.com/group/sub/app.git", provider: GitLab, scheme: "ssh", host: "gitlab.com", path: "group/sub/app.git",
		link: "https://gitlab.com/group/sub/app/-/merge_requests/new?merge_request%5Bsource_branch%5D=" + branch},
	{raw: "ssh://git@ssh.github.com:443/demo/app.git", provider: GitHub, scheme: "ssh", host: "ssh.github.com", port: 443, path: "demo/app.git",
		link: "https://github.com/demo/app/pull/new/" + branch},
	{raw: "ssh://git@altssh.gitlab.com:443/demo/app.git", provider: GitLab, scheme: "ssh", host: "altssh.gitlab.com", port: 443, path: "demo/app.git",
		link: "https://gitlab.com/demo/app/-/merge_requests/new?merge_request%5Bsource_branch%5D=" + branch},
	{raw: "ssh://git@altssh.bitbucket.org:443/demo/app.git", provider: Bitbucket, scheme: "ssh", host: "altssh.bitbucket.org", port: 443, path: "demo/app.git",
		link: "https://bitbucket.org/demo/app/pull-requests/new?source=" + branch + "&t=1"},
	{raw: "https://user:" + canary + "@github.com/demo/app.git", clean: "https://github.com/demo/app.git", provider: GitHub, scheme: "https", host: "github.com", path: "demo/app.git", credential: true,
		link: "https://github.com/demo/app/pull/new/" + branch},
	{raw: "https://" + canary + "@github.com/demo/app.git", clean: "https://github.com/demo/app.git", provider: GitHub, scheme: "https", host: "github.com", path: "demo/app.git", credential: true,
		link: "https://github.com/demo/app/pull/new/" + branch},
	{raw: "ssh://git:" + canary + "@example.test/demo/app.git", clean: "ssh://git@example.test/demo/app.git", provider: Other, scheme: "ssh", host: "example.test", path: "demo/app.git", credential: true},
	{raw: "https://GitHub.com/demo/app", clean: "https://github.com/demo/app", provider: GitHub, scheme: "https", host: "github.com", path: "demo/app",
		link: "https://github.com/demo/app/pull/new/" + branch},
	{raw: "https://git.example.test/demo/app.git", provider: Other, scheme: "https", host: "git.example.test", path: "demo/app.git"},
	{raw: "git@gitlab.example.test:demo/app.git", provider: Other, scheme: "scp", host: "gitlab.example.test", path: "demo/app.git"},
	{raw: "https://github.com.example.test/demo/app", provider: Other, scheme: "https", host: "github.com.example.test", path: "demo/app"},
	{raw: "https://examplegithub.com/demo/app", provider: Other, scheme: "https", host: "examplegithub.com", path: "demo/app"},
	{raw: "https://github.com:443@example.test/demo/app", clean: "https://example.test/demo/app", provider: Other, scheme: "https", host: "example.test", path: "demo/app", credential: true},
	// One final slash is dropped, as pasted from a browser; the link is the same.
	{raw: "https://github.com/demo/app/", clean: "https://github.com/demo/app", provider: GitHub, scheme: "https", host: "github.com", path: "demo/app",
		link: "https://github.com/demo/app/pull/new/" + branch},
	{raw: "git@github.com:demo/app.git/", clean: "git@github.com:demo/app.git", provider: GitHub, scheme: "scp", host: "github.com", path: "demo/app.git",
		link: "https://github.com/demo/app/pull/new/" + branch},
	{raw: "ssh://git@h.example.test/a/b/", clean: "ssh://git@h.example.test/a/b", provider: Other, scheme: "ssh", host: "h.example.test", path: "a/b"},
	// The absolute scp path of a self-hosted server: Clean keeps the slash.
	{raw: "git@server.example.test:/srv/git/app.git", provider: Other, scheme: "scp", host: "server.example.test", path: "srv/git/app.git"},
	{raw: "https://github.com/demo", provider: GitHub, scheme: "https", host: "github.com", path: "demo"},
	{raw: "https://github.com/a/b/c", provider: GitHub, scheme: "https", host: "github.com", path: "a/b/c"},
	{raw: "https://bitbucket.org/a/b/c", provider: Bitbucket, scheme: "https", host: "bitbucket.org", path: "a/b/c"},
	// The port in the address, unchanged; 443 is the only one HTTPS takes.
	{raw: "https://github.com:443/demo/app", provider: GitHub, scheme: "https", host: "github.com", port: 443, path: "demo/app",
		link: "https://github.com/demo/app/pull/new/" + branch},
	{raw: "ssh://example.test:2222/demo/app", provider: Other, scheme: "ssh", host: "example.test", port: 2222, path: "demo/app"},
	// scp stays scp, with or without a user; an IPv4 host is a host.
	{raw: "example.test:demo/app.git", provider: Other, scheme: "scp", host: "example.test", path: "demo/app.git"},
	{raw: "git@192.0.2.10:demo/app.git", provider: Other, scheme: "scp", host: "192.0.2.10", path: "demo/app.git"},
	{raw: "GIT@GitHub.com:demo/app", clean: "GIT@github.com:demo/app", provider: GitHub, scheme: "scp", host: "github.com", path: "demo/app",
		link: "https://github.com/demo/app/pull/new/" + branch},
	// A password may hold an @: all of it goes, the user stays.
	{raw: "ssh://git:" + canary + "@x@example.test/demo/app.git", clean: "ssh://git@example.test/demo/app.git", provider: Other, scheme: "ssh", host: "example.test", path: "demo/app.git", credential: true},
	{raw: "https://a:" + canary + "@b@example.test/demo/app", clean: "https://example.test/demo/app", provider: Other, scheme: "https", host: "example.test", path: "demo/app", credential: true},
}

var refused = []string{
	"",
	"javascript:alert(1)",
	"javascript:alert",
	"JavaScript:alert",
	"javascript:a/b",
	"data:text/html,x",
	"data:text/html",
	"vbscript:a/b",
	"http:demo/app",
	"file:demo/app",
	"http://github.com/demo/app",
	"git://github.com/demo/app",
	"ftp://github.com/demo/app",
	"HTTPS://github.com/demo/app",
	"ext::sh -c id",
	"ext::sh",
	"fd::3",
	"https://github.com./demo/app",
	"https://example.test:8443/demo/app",
	"https://github.com:0443/demo/app",
	"ssh://git@example.test:0/demo/app",
	"ssh://git@example.test:70000/demo/app",
	"ssh://git@example.test:x/demo/app",
	"ssh://git@example.test:/demo/app",
	"-oProxyCommand=id:demo/app",
	"git@-oProxyCommand=id:demo/app",
	"ssh://-oProxyCommand=id/demo/app",
	"ssh://-git@example.test/demo/app",
	"ssh://@example.test/demo/app",
	"ssh://:" + canary + "@example.test/demo/app",
	"ssh://a b@example.test/demo/app",
	"-x@example.test:demo/app",
	"https://github.com/demo/%2e%2e/app",
	"https://github.com/demo/app?x=1",
	"https://github.com/demo/app#y",
	"https://github.com/demo/app\\x",
	"https://github.com/demo/../app",
	"https://github.com/demo/a..b",
	"https://github.com/demo/./app",
	"https://github.com/a/b//",
	"ssh://git@h.example.test/a/b//",
	"git@h.example.test:a/b//",
	"git@h.example.test://a/b",
	"git@h.example.test:/",
	"https://github.com//demo/app",
	// Option or transport look-alikes stay refused.
	"--upload-pack=x:demo/app",
	"git@github.com:--upload-pack=x/app",
	"https://github.com/--upload-pack=x/app",
	"foo::bar/baz",
	"hg::https://x/y",
	"git-remote-foo::x",
	// A hexadecimal IPv4 address is not a name.
	"https://0x7f000001/a/b",
	"https://127.0.0.0x1/a/b",
	"https://github.com/.git",
	"https://github.com/-x/app",
	"https://github.com/demo/a b",
	"https://github.com/demo/a\tb",
	"https://github.com/demo/a\nb",
	"https://github.com/demo/app\n",
	"https://github.com/demo/a\x7fb",
	"https://github.com",
	"https://github.com/",
	"https://",
	"https://@/demo/app",
	"https://[2001:db8::1]/demo/app",
	"ssh://git@[2001:db8::1]/demo/app",
	"git@[2001:db8::1]:demo/app",
	"https://a_b.example.test/demo/app",
	"https://-a.example.test/demo/app",
	"https://a-.example.test/demo/app",
	"https://a..example.test/demo/app",
	"https://999.1.1.1/demo/app",
	"https://192.0.2/demo/app",
	"https://2130706433/demo/app",
	"https://192.0.2.010/demo/app",
	// Letters that a Unicode lower-casing folds onto ASCII: never github.com.
	"https://g\u0130thub.com/demo/app",
	"https://GİTHUB.COM/demo/app",
	"https://\u212Aexample.test/demo/app",
	"https://github.com/d\u00e9mo/app",
	"https://github.com/demo/\xff",
	// A password without an @ after it, or cut by a slash, never becomes a host.
	"https://u:" + canary + "/x@github.com/demo/app",
	"https://u:" + canary + "?x@github.com/demo/app",
	"git:" + canary + "@example.test:demo/app",
	// Relative paths, Windows paths and shares.
	"demo/app.git",
	"./demo/app.git",
	"../demo/app.git",
	"demo",
	"c:demo/app",
	"C:demo/app",
	"git@c:demo/app",
	"\\\\server\\share\\demo.git",
	"//server/share/demo.git",
	"file://server/srv/demo.git",
	"file:/srv/demo.git",
	"file:///",
	"/",
	"C:\\",
	"https://github.com/" + strings.Repeat("a", 101) + "/app",
	"https://example.test/" + strings.Repeat("a/", 20) + "b",
	"https://" + strings.Repeat("a", 254) + "/demo/app",
	"https://example.test/" + strings.Repeat("a", 5000),
}

func TestParseTable(t *testing.T) {
	for _, c := range accepted {
		t.Run(c.raw, func(t *testing.T) {
			r, err := Parse(c.raw, false)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			want := c.clean
			if want == "" {
				want = c.raw
			}
			if r.Clean != want {
				t.Errorf("Clean = %q, want %q", r.Clean, want)
			}
			if r.Provider != c.provider {
				t.Errorf("Provider = %q, want %q", r.Provider, c.provider)
			}
			if r.Scheme != c.scheme {
				t.Errorf("Scheme = %q, want %q", r.Scheme, c.scheme)
			}
			if r.Host != c.host {
				t.Errorf("Host = %q, want %q", r.Host, c.host)
			}
			if r.Port != c.port {
				t.Errorf("Port = %d, want %d", r.Port, c.port)
			}
			if r.Path != c.path {
				t.Errorf("Path = %q, want %q", r.Path, c.path)
			}
			if r.HadCredential != c.credential {
				t.Errorf("HadCredential = %v, want %v", r.HadCredential, c.credential)
			}
			if got := MergeURL(r, branch); got != c.link {
				t.Errorf("MergeURL = %q, want %q", got, c.link)
			}
		})
	}
	for _, raw := range refused {
		t.Run("refused "+raw, func(t *testing.T) {
			for _, allowLocal := range []bool{false, true} {
				r, err := Parse(raw, allowLocal)
				if !errors.Is(err, ErrUnsupported) {
					t.Errorf("allowLocal=%v: err = %v, want ErrUnsupported", allowLocal, err)
				}
				if r != (Remote{}) {
					t.Errorf("allowLocal=%v: Remote = %+v, want empty", allowLocal, r)
				}
			}
		})
	}
}

func TestParseKeepsTwentyParts(t *testing.T) {
	raw := "https://gitlab.com/" + strings.TrimSuffix(strings.Repeat("a/", 20), "/")
	if _, err := Parse(raw, false); err != nil {
		t.Fatalf("twenty parts: %v", err)
	}
}

func TestNoSecretInAnyField(t *testing.T) {
	for _, c := range accepted {
		if !strings.Contains(c.raw, canary) {
			continue
		}
		r, err := Parse(c.raw, false)
		if err != nil {
			t.Fatalf("%s: %v", c.raw, err)
		}
		if !r.HadCredential {
			t.Errorf("%s: HadCredential is false", c.raw)
		}
		all := fmt.Sprintf("%+v %s %s %s", r, r.Display(), r.ID(), MergeURL(r, branch))
		if strings.Contains(all, canary) {
			t.Errorf("%s: the secret is kept: %s", c.raw, all)
		}
	}
}

func TestSameRemoteWithOrWithoutSecretHasOneID(t *testing.T) {
	a, _ := Parse("https://user:"+canary+"@github.com/demo/app.git", false)
	b, _ := Parse("https://github.com/demo/app.git", false)
	if a.ID() != b.ID() {
		t.Errorf("IDs differ: %s, %s", a.ID(), b.ID())
	}
	sum := sha256.Sum256([]byte("https://github.com/demo/app.git"))
	if b.ID() != hex.EncodeToString(sum[:]) {
		t.Errorf("ID = %s, not the SHA-256 of Address", b.ID())
	}
}

func TestIDIgnoresTheSSHUser(t *testing.T) {
	a, _ := Parse("git@example.test:demo/app.git", false)
	b, _ := Parse("deploy@example.test:demo/app.git", false)
	if a.ID() != b.ID() {
		t.Errorf("scp IDs differ: %s, %s", a.ID(), b.ID())
	}
	c, _ := Parse("ssh://git@example.test:2222/demo/app.git", false)
	d, _ := Parse("ssh://deploy@example.test:2222/demo/app.git", false)
	if c.ID() != d.ID() {
		t.Errorf("ssh IDs differ: %s, %s", c.ID(), d.ID())
	}
	e, _ := Parse("ssh://example.test:2222/demo/app.git", false)
	if c.ID() != e.ID() {
		t.Errorf("a missing user changes the ID")
	}
	if got := c.Address(); got != "ssh://example.test:2222/demo/app.git" {
		t.Errorf("Address = %q: the port must stay", got)
	}
	f, _ := Parse("ssh://example.test:2223/demo/app.git", false)
	if c.ID() == f.ID() {
		t.Errorf("another port gives the same ID")
	}
	sum := sha256.Sum256([]byte(c.Address()))
	if c.ID() != hex.EncodeToString(sum[:]) {
		t.Errorf("ID is not the SHA-256 of Address")
	}
}

func TestAddressHoldsNoUser(t *testing.T) {
	for raw, want := range map[string]string{
		"ssh://" + canary + "@example.test/demo/app":       "ssh://example.test/demo/app",
		canary + "@example.test:demo/app":                  "example.test:demo/app",
		canary + "@example.test:/srv/app.git":              "example.test:/srv/app.git",
		"ssh://" + canary + ":pw@example.test:22/demo/app": "ssh://example.test:22/demo/app",
		"https://github.com/demo/app":                      "https://github.com/demo/app",
		"example.test:demo/app":                            "example.test:demo/app",
	} {
		r, err := Parse(raw, false)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got := r.Address(); got != want || strings.Contains(got, canary) {
			t.Errorf("%s: Address = %q, want %q", raw, got, want)
		}
	}
}

func TestMergeURLNeedsHostOfProvider(t *testing.T) {
	for _, r := range []Remote{
		{Provider: GitHub, Host: "evil.example.test", Path: "demo/app"},
		{Provider: GitHub, Host: "", Path: "demo/app"},
		{Provider: GitHub, Host: "gitlab.com", Path: "demo/app"},
		{Provider: GitHub, Scheme: "file", Path: "demo/app"},
	} {
		if got := MergeURL(r, branch); got != "" {
			t.Errorf("%+v: MergeURL = %q, want none", r, got)
		}
	}
}

func TestErrorsCarryNoInput(t *testing.T) {
	for _, raw := range refused {
		for _, allowLocal := range []bool{false, true} {
			_, err := Parse(raw+canary, allowLocal)
			if err != nil && strings.Contains(err.Error(), canary) {
				t.Errorf("%q: error carries the input: %v", raw, err)
			}
			_, err = Parse(raw, allowLocal)
			if err == nil {
				t.Fatalf("%q: no error", raw)
			}
			if err != ErrUnsupported {
				t.Errorf("%q: error is not the fixed value: %v", raw, err)
			}
		}
	}
}

func TestProviderIsExactHost(t *testing.T) {
	exact := map[string]Provider{
		"github.com":           GitHub,
		"ssh.github.com":       GitHub,
		"bitbucket.org":        Bitbucket,
		"altssh.bitbucket.org": Bitbucket,
		"gitlab.com":           GitLab,
		"altssh.gitlab.com":    GitLab,
	}
	for host, want := range exact {
		r, err := Parse("ssh://git@"+host+"/demo/app.git", false)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if r.Provider != want {
			t.Errorf("%s: Provider = %q, want %q", host, r.Provider, want)
		}
	}
	for _, host := range []string{
		"www.github.com", "gist.github.com", "github.com.example.test", "examplegithub.com",
		"github.co", "github.org", "gitlab.example.test", "gitlab.org", "bitbucket.com",
		"altssh.github.com", "ssh.gitlab.com", "ssh.bitbucket.org", "example.test",
	} {
		r, err := Parse("ssh://git@"+host+"/demo/app.git", false)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if r.Provider != Other {
			t.Errorf("%s: Provider = %q, want other", host, r.Provider)
		}
		if got := MergeURL(r, branch); got != "" {
			t.Errorf("%s: MergeURL = %q, want none", host, got)
		}
	}
}

func TestMergeURLTable(t *testing.T) {
	cases := []struct {
		name, raw, branch, want string
	}{
		{"github", "git@github.com:demo/app.git", branch, "https://github.com/demo/app/pull/new/" + branch},
		{"bitbucket", "https://bitbucket.org/demo/app.git", branch, "https://bitbucket.org/demo/app/pull-requests/new?source=" + branch + "&t=1"},
		{"gitlab two", "https://gitlab.com/demo/app.git", branch, "https://gitlab.com/demo/app/-/merge_requests/new?merge_request%5Bsource_branch%5D=" + branch},
		{"gitlab twenty", "https://gitlab.com/" + strings.TrimSuffix(strings.Repeat("a/", 20), "/"), branch,
			"https://gitlab.com/" + strings.TrimSuffix(strings.Repeat("a/", 20), "/") + "/-/merge_requests/new?merge_request%5Bsource_branch%5D=" + branch},
		{".git goes once", "https://github.com/demo/app.git.git", branch, "https://github.com/demo/app.git/pull/new/" + branch},
		{"gitlab one part", "https://gitlab.com/app", branch, ""},
		{"github one part", "https://github.com/demo", branch, ""},
		{"github three parts", "https://github.com/a/b/c", branch, ""},
		{"bitbucket three parts", "https://bitbucket.org/a/b/c", branch, ""},
		{"other", "https://example.test/demo/app", branch, ""},
		{"empty branch", "https://github.com/demo/app", "", ""},
		{"main", "https://github.com/demo/app", "main", ""},
		{"other prefix", "https://github.com/demo/app", "fix-01jabc23", ""},
		{"short", "https://github.com/demo/app", "michel/fix-0123456", ""},
		{"long", "https://github.com/demo/app", "michel/fix-" + strings.Repeat("a", 27), ""},
		{"upper case", "https://github.com/demo/app", "michel/fix-01JABC23", ""},
		{"newline", "https://github.com/demo/app", branch + "\n", ""},
		{"query", "https://github.com/demo/app", branch + "?x=1", ""},
		{"climb", "https://github.com/demo/app", "michel/fix-01jabc23/../../x", ""},
		{"script", "https://github.com/demo/app", "javascript:alert(1)", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := Parse(c.raw, false)
			if err != nil {
				t.Fatal(err)
			}
			if got := MergeURL(r, c.branch); got != c.want {
				t.Errorf("MergeURL = %q, want %q", got, c.want)
			}
		})
	}
	// A Remote built by hand gets no link from an invalid part either.
	for _, path := range []string{"", "a", "../b", "a/../b", "a/b/", "/a/b", "a//b", "a/b?x", "a/b#y", "a b/c", "a/%2e", "a/b\n", "a\\b/c", "-a/b", "a/.git"} {
		if got := MergeURL(Remote{Provider: GitHub, Host: "github.com", Path: path}, branch); got != "" {
			t.Errorf("path %q: MergeURL = %q, want none", path, got)
		}
	}
	for _, p := range []Provider{Other, Local, "", "github.com"} {
		if got := MergeURL(Remote{Provider: p, Host: "github.com", Path: "demo/app"}, branch); got != "" {
			t.Errorf("provider %q: MergeURL = %q, want none", p, got)
		}
	}
}

func TestMergeURLOnlyOnThreeOrigins(t *testing.T) {
	origins := []string{"https://github.com/", "https://bitbucket.org/", "https://gitlab.com/"}
	check := func(raw string, allowLocal bool) {
		t.Helper()
		r, err := Parse(raw, allowLocal)
		if err != nil {
			return
		}
		got := MergeURL(r, branch)
		if got == "" {
			return
		}
		for _, o := range origins {
			if strings.HasPrefix(got, o) {
				return
			}
		}
		t.Errorf("%q: link on a foreign origin: %q", raw, got)
	}
	for _, c := range accepted {
		check(c.raw, false)
	}
	for _, raw := range refused {
		check(raw, true)
	}
	check("file:///srv/demo.git", true)
	check("/srv/github.com/demo/app.git", true)
}

func TestDisplayHasNoAbsolutePath(t *testing.T) {
	r, err := Parse("https://user:"+canary+"@github.com/demo/app.git", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Display(); got != "github.com/demo/app" {
		t.Errorf("Display = %q", got)
	}
	r, err = Parse("git@gitlab.example.test:group/sub/app.git", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Display(); got != "gitlab.example.test/group/sub/app" {
		t.Errorf("Display = %q", got)
	}
	for _, raw := range []string{"file:///srv/demo.git", "/srv/demo.git", `C:\srv\demo.git`, "C:/srv/demo.git"} {
		r, err := Parse(raw, true)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got := r.Display(); got != "dépôt local" {
			t.Errorf("%s: Display = %q", raw, got)
		}
	}
}

func TestLocalNeedsAllowLocal(t *testing.T) {
	for _, raw := range []string{"file:///srv/demo.git", "/srv/demo.git", `C:\srv\demo.git`, "C:/srv/demo.git", "file:///C:/srv/demo.git", `C:\srv\dépôt\demo.git`} {
		if _, err := Parse(raw, false); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s, allowLocal false: err = %v", raw, err)
		}
		r, err := Parse(raw, true)
		if err != nil {
			t.Fatalf("%s, allowLocal true: %v", raw, err)
		}
		if r.Provider != Local || r.Scheme != "file" || r.Clean != raw || r.Host != "" || r.Port != 0 {
			t.Errorf("%s: %+v", raw, r)
		}
		if got := MergeURL(r, branch); got != "" {
			t.Errorf("%s: MergeURL = %q", raw, got)
		}
	}
	for _, raw := range []string{"/srv/../demo.git", "file:///srv/../demo.git", `C:\srv\..\demo.git`, "/srv/a b.git", "/srv/a\nb.git", "/srv/a?b.git", "/srv/a#b.git", "file:///srv/%2e%2e/demo.git", "file:////server/share/a.git", `/\server\share\a.git`} {
		if _, err := Parse(raw, true); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%q, allowLocal true: err = %v, want ErrUnsupported", raw, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, c := range accepted {
		f.Add(c.raw)
	}
	for _, raw := range refused {
		f.Add(raw)
	}
	f.Add("file:///srv/demo.git")
	f.Add("user:pw@host:a/b")
	f.Fuzz(func(t *testing.T, raw string) {
		for _, allowLocal := range []bool{false, true} {
			r, err := Parse(raw, allowLocal)
			if err != nil {
				if err != ErrUnsupported {
					t.Fatalf("error is not fixed: %v", err)
				}
				if r != (Remote{}) {
					t.Fatalf("refused with a value: %+v", r)
				}
				continue
			}
			if strings.HasPrefix(r.Clean, "-") {
				t.Fatalf("%q gave Clean %q", raw, r.Clean)
			}
			if r.Scheme == "https" && strings.Contains(r.Clean, "@") {
				t.Fatalf("%q gave Clean %q", raw, r.Clean)
			}
			if r.Provider != Local && (!validPath(r.Path) || r.Provider != providerOf(r.Host)) {
				t.Fatalf("%q gave %+v", raw, r)
			}
			clean := strings.ToLower(r.Clean)
			for _, bad := range []string{"javascript:", "data:", "vbscript:"} {
				if strings.HasPrefix(clean, bad) {
					t.Fatalf("%q gave Clean %q", raw, r.Clean)
				}
			}
			if strings.Contains(r.Host, "@") {
				t.Fatalf("%q gave Host %q", raw, r.Host)
			}
			if r.Provider != Local && !allowLocal {
				again, err := Parse(r.Clean, false)
				if err != nil {
					t.Fatalf("Clean %q does not parse: %v", r.Clean, err)
				}
				if again.Clean != r.Clean || again.HadCredential {
					t.Fatalf("Clean %q parses as %+v", r.Clean, again)
				}
			}
			link := MergeURL(r, branch)
			if strings.ContainsAny(link, " \\\n\r\t") {
				t.Fatalf("%q gave link %q", raw, link)
			}
			if link != "" && !strings.HasPrefix(link, "https://github.com/") &&
				!strings.HasPrefix(link, "https://bitbucket.org/") &&
				!strings.HasPrefix(link, "https://gitlab.com/") {
				t.Fatalf("%q gave link %q", raw, link)
			}
			if r.Provider == Local && (strings.Contains(r.Display(), "/") || strings.Contains(r.Display(), "\\")) {
				t.Fatalf("%q gave Display %q", raw, r.Display())
			}
		}
	})
}
