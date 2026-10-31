package target

import (
	"context"
	"errors"
	"testing"
	"time"
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
	mk := func(name string) Target {
		x, err := r.Add(ctx, Target{Name: name, Host: name + ".example.test", User: "d", Kind: KindVPS})
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	prod, pre, other := mk("prod"), mk("pre"), mk("other")
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
	prod.PreprodID = pre.ID
	if err := r.Update(ctx, prod); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolvePreprod(ctx, other, "prod"); !errors.Is(err, ErrPreprodChain) {
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
