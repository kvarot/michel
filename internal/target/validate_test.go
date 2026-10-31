package target

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/policy"
)

func TestParseIntervalAndText(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 0, "manual": ManualOnly, " Manual ": ManualOnly, "12h": 12 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := ParseInterval(in); err != nil || got != want {
			t.Errorf("ParseInterval(%q) = %v %v, want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"soon", "1m", "0", "-5h", "9999h"} {
		if _, err := ParseInterval(in); !errors.Is(err, ErrInvalidInterval) {
			t.Errorf("ParseInterval(%q) = %v", in, err)
		}
	}
	for in, want := range map[time.Duration]string{0: "24h", ManualOnly: "manual", 12 * time.Hour: "12h", 90 * time.Minute: "1h30m", 5 * time.Minute: "5m"} {
		if got := IntervalText(in); got != want {
			t.Errorf("IntervalText(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateSiteURL(t *testing.T) {
	for in, ok := range map[string]bool{"": true, "https://www.example.test/": true, "http://192.0.2.1:8080": true, "ftp://example.test": false,
		"example.test": false, "https://user:pw@example.test": false, "https://": false} {
		if err := ValidateSiteURL(in); (err == nil) != ok {
			t.Errorf("ValidateSiteURL(%q) = %v", in, err)
		}
	}
}

func TestResolvePreprod(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()
	mk := func(name string, env Env) Target {
		x, err := r.Add(ctx, Target{Name: name, Host: name + ".example.test", User: "d", Kind: KindVPS, Env: env})
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	prod, pre, other := mk("prod", EnvProd), mk("pre", EnvPreprod), mk("other", EnvDev)
	if id, err := r.ResolvePreprod(ctx, prod, ""); id != "" || err != nil {
		t.Errorf("none = %q %v", id, err)
	}
	if id, err := r.ResolvePreprod(ctx, prod, "pre"); id != pre.ID || err != nil {
		t.Errorf("by name = %q %v", id, err)
	}
	if id, err := r.ResolvePreprod(ctx, prod, pre.ID); id != pre.ID || err != nil {
		t.Errorf("by id = %q %v", id, err)
	}
	if _, err := r.ResolvePreprod(ctx, prod, "ghost"); !errors.Is(err, ErrPreprodNotFound) {
		t.Errorf("unknown = %v", err)
	}
	if _, err := r.ResolvePreprod(ctx, prod, prod.ID); !errors.Is(err, ErrPreprodSelf) {
		t.Errorf("self = %v", err)
	}
	if _, err := r.ResolvePreprod(ctx, Target{Name: "new"}, "new"); err == nil {
		t.Log("a server not stored yet is not itself")
	}
	if _, err := r.ResolvePreprod(ctx, other, "prod"); !errors.Is(err, ErrPreprodRole) {
		t.Errorf("a production server as preprod = %v", err)
	}
	prod.PreprodID = pre.ID
	if err := r.Update(ctx, prod); err != nil {
		t.Fatal(err)
	}
	pre2 := mk("pre2", EnvPreprod)
	pre2.PreprodID = pre.ID
	if err := r.Update(ctx, pre2); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolvePreprod(ctx, other, "pre2"); !errors.Is(err, ErrPreprodChain) {
		t.Errorf("preprod that has a preprod = %v", err)
	}
	if _, err := r.ResolvePreprod(ctx, pre, "other"); !errors.Is(err, ErrPreprodChain) {
		t.Errorf("server that is a preprod gets one = %v", err)
	}
	if id, err := r.ResolvePreprod(ctx, prod, "pre"); id != pre.ID || err != nil {
		t.Errorf("unchanged = %q %v", id, err)
	}
}

func TestAllowRules(t *testing.T) {
	got := AllowRules(Target{Host: "192.0.2.5", SiteURL: "https://www.example.test/x"})
	if len(got) != 2 || got[0].Host != "192.0.2.5" || got[0].Purpose != "target.ssh" || got[1].Host != "www.example.test" || got[1].Purpose != "target.http" {
		t.Errorf("rules = %+v", got)
	}
	if got := AllowRules(Target{Host: "192.0.2.5"}); len(got) != 1 {
		t.Errorf("no site = %+v", got)
	}
}

func TestValidateHostAndRemoteDir(t *testing.T) {
	for in, ok := range map[string]bool{"example.test": true, "192.0.2.10": true, "srv-1.example.test": true, "*.example.test": false,
		"a@b": false, "a b": false, "a/b": false, "a:22": false, "::1": false, "": false, "-x.test": false} {
		if err := ValidateHost(in); (err == nil) != ok {
			t.Errorf("ValidateHost(%q) = %v", in, err)
		}
	}
	for in, ok := range map[string]bool{"/var/www/site": true, "/var/www/site/": true, "/home/deploy/site": true, "/srv": true,
		"/": false, "/home": false, "/home/": false, "/root": false, "/root/": false, "/home/deploy": false, "/home/deploy/": false,
		"var/www": false, "": false, "/var/../etc": false, "/var//www": false, "/a/./b": false, "/x y": true, "/x	y": false} {
		if err := ValidateRemoteDir(in); (err == nil) != ok {
			t.Errorf("ValidateRemoteDir(%q) = %v", in, err)
		}
	}
	if ValidateSiteURL("https://*.example.test/") == nil {
		t.Error("a wildcard site host was accepted")
	}
}

func TestLinkRefusesAFolderThatIsNotBelow(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()
	x, err := r.Add(ctx, Target{Name: "a", Host: "a.example.test", User: "d", Kind: KindVPS})
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"/", "/home", "/root", "/home/d", "relative", "/a/../b", ""} {
		if err := r.Link(ctx, Link{TargetID: x.ID, ProjectID: "P", RemoteDir: dir}); !errors.Is(err, ErrInvalidRemoteDir) {
			t.Errorf("Link(%q) = %v", dir, err)
		}
	}
	if err := r.Link(ctx, Link{TargetID: x.ID, ProjectID: "P", RemoteDir: "/home/d/site"}); err != nil {
		t.Errorf("Link below a home folder = %v", err)
	}
}

func TestReleasedRulesKeepWhatAnotherServerUses(t *testing.T) {
	a := Target{Host: "h.example.test", SiteURL: "https://www.example.test/"}
	b := Target{Host: "h.example.test", SiteURL: "https://other.example.test/"}
	c := Target{Host: "c.example.test", SiteURL: "https://www.example.test/"}
	got := ReleasedRules(a, []Target{b})
	if len(got) != 1 || got[0].Host != "www.example.test" {
		t.Errorf("shared ssh host kept, own site released: %+v", got)
	}
	if got := ReleasedRules(a, []Target{b, c}); len(got) != 0 {
		t.Errorf("everything shared: %+v", got)
	}
	if got := ReleasedRules(a, nil); len(got) != 2 {
		t.Errorf("alone: %+v", got)
	}
}

func TestUpdateClearsThePinWhenTheServerMovesAndRemoveClearsPreprod(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()
	x, _ := r.Add(ctx, Target{Name: "x", Host: "x.example.test", User: "d", Kind: KindVPS})
	pre, _ := r.Add(ctx, Target{Name: "pre", Host: "p.example.test", User: "d", Kind: KindVPS, Env: EnvPreprod})
	if err := r.SetHostKey(ctx, x.ID, "SHA256:abc"); err != nil {
		t.Fatal(err)
	}
	x, _ = r.Get(ctx, x.ID)
	x.FixLevel = 2
	if err := r.Update(ctx, x); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Get(ctx, x.ID); got.HostKey != "SHA256:abc" {
		t.Errorf("the pin went with a setting change: %q", got.HostKey)
	}
	x.Host = "y.example.test"
	x.PreprodID = pre.ID
	if err := r.Update(ctx, x); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Get(ctx, x.ID); got.HostKey != "" || got.PreprodID != pre.ID {
		t.Errorf("after a move: %+v", got)
	}
	if err := r.Remove(ctx, pre.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Get(ctx, x.ID); got.PreprodID != "" {
		t.Errorf("dangling preprod: %q", got.PreprodID)
	}
}

func TestReleasedRulesIgnoreHostCase(t *testing.T) {
	gone := Target{Host: "Example.TEST", SiteURL: "https://WWW.Example.test/"}
	stays := Target{Host: "example.test", SiteURL: "https://www.example.test/"}
	if got := ReleasedRules(gone, []Target{stays}); len(got) != 0 {
		t.Errorf("released %+v while another server uses the same hosts", got)
	}
	for _, r := range AllowRules(gone) {
		if r.Host != strings.ToLower(r.Host) {
			t.Errorf("rule host not lowercase: %+v", r)
		}
	}
}

func TestHostIsStoredInLowerCase(t *testing.T) {
	r, _ := newRepo(t)
	x, err := r.Add(context.Background(), Target{Name: "x", Host: "Example.TEST", User: "d", Kind: KindVPS})
	if err != nil || x.Host != "example.test" {
		t.Fatalf("add = %+v %v", x, err)
	}
	x.Host = "Other.Test"
	if err := r.Update(context.Background(), x); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Get(context.Background(), x.ID); got.Host != "other.test" {
		t.Errorf("updated host = %q", got.Host)
	}
}

func TestOnlyTheRulesMichelWroteAreOwned(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()
	mine := policy.AllowRule{Host: "Mine.example.test", Purpose: policy.PurposeTargetSSH}
	hand := policy.AllowRule{Host: "hand.example.test", Purpose: policy.PurposeTargetSSH}
	if err := r.RecordRules(ctx, []policy.AllowRule{mine}); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordRules(ctx, []policy.AllowRule{mine}); err != nil {
		t.Fatalf("recording twice: %v", err)
	}
	got, err := r.OwnedOnly(ctx, []policy.AllowRule{mine, hand})
	if err != nil || len(got) != 1 || !strings.EqualFold(got[0].Host, "mine.example.test") {
		t.Fatalf("owned = %+v %v", got, err)
	}
	if err := r.ForgetRules(ctx, []policy.AllowRule{mine}); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.OwnedOnly(ctx, []policy.AllowRule{mine}); len(got) != 0 {
		t.Errorf("after forget = %+v", got)
	}
}
