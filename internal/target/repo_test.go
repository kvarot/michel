package target

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/store"
)

func newRepo(t *testing.T) (*Repo, *store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return NewRepo(s), s
}

func base(name string) Target {
	return Target{Name: name, Host: "192.0.2.10", User: "deploy", Kind: KindVPS, Env: EnvProd, CheckInterval: DefaultCheckInterval}
}

func TestTargetHDSForcesHealth(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()
	bad := base("srv-demo")
	bad.Kind, bad.Classification = KindHDS, policy.ClassSensitive
	if _, err := r.Add(ctx, bad); !errors.Is(err, ErrHDSIsHealth) {
		t.Fatalf("hds + sensitive: err = %v", err)
	}
	ok := base("srv-demo")
	ok.Kind = KindHDS
	got, err := r.Add(ctx, ok)
	if err != nil || got.Classification != policy.ClassHealth {
		t.Fatalf("hds default = %+v, %v", got, err)
	}
	// Update cannot move an hds server away from health either.
	got.Classification = policy.ClassPublic
	if err := r.Update(ctx, got); !errors.Is(err, ErrHDSIsHealth) {
		t.Fatalf("update: err = %v", err)
	}
	plain, err := r.Add(ctx, base("two"))
	if err != nil || plain.Classification != policy.ClassSensitive || plain.Port != 22 || !plain.Active || plain.ID == "" {
		t.Fatalf("defaults = %+v, %v", plain, err)
	}
}

func TestTargetFixLevelRange(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()
	x := base("a")
	x.FixLevel = 4
	if _, err := r.Add(ctx, x); !errors.Is(err, ErrInvalidFixLevel) {
		t.Fatalf("add 4: %v", err)
	}
	x.FixLevel = 3
	got, err := r.Add(ctx, x)
	if err != nil {
		t.Fatal(err)
	}
	got.FixLevel = -1
	if err := r.Update(ctx, got); !errors.Is(err, ErrInvalidFixLevel) {
		t.Fatalf("update -1: %v", err)
	}
}

func TestLinkTargetProject(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()
	a, _ := r.Add(ctx, base("a"))
	b, _ := r.Add(ctx, base("b"))
	if err := r.Link(ctx, Link{TargetID: a.ID, ProjectID: "P1", RemoteDir: "/var/www/demo"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Link(ctx, Link{TargetID: a.ID, ProjectID: "P1", RemoteDir: "/srv/demo"}); err != nil {
		t.Fatal(err) // same pair: the directory is replaced
	}
	if err := r.Link(ctx, Link{TargetID: b.ID, ProjectID: "P1", RemoteDir: "/srv/other"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Link(ctx, Link{TargetID: "nope", ProjectID: "P1", RemoteDir: "/srv/x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown target: %v", err)
	}
	links, err := r.Links(ctx, a.ID)
	if err != nil || len(links) != 1 || links[0].RemoteDir != "/srv/demo" {
		t.Fatalf("links = %+v, %v", links, err)
	}
	ts, err := r.TargetsOfProject(ctx, "P1")
	if err != nil || len(ts) != 2 || ts[0].Name != "a" || ts[1].Name != "b" {
		t.Fatalf("targets = %+v, %v", ts, err)
	}
	if err := r.Unlink(ctx, a.ID, "P1"); err != nil {
		t.Fatal(err)
	}
	if ts, _ = r.TargetsOfProject(ctx, "P1"); len(ts) != 1 {
		t.Fatalf("after unlink = %+v", ts)
	}
	if err := r.Remove(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if ts, _ = r.TargetsOfProject(ctx, "P1"); len(ts) != 0 {
		t.Fatalf("after remove = %+v", ts)
	}
	if _, err := r.Get(ctx, "b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get removed: %v", err)
	}
}

func TestInventoryRoundTrip(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()
	a, _ := r.Add(ctx, base("a"))
	if _, ok, err := r.LatestInventory(ctx, a.ID); ok || err != nil {
		t.Fatalf("empty: %v %v", ok, err)
	}
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	inv := Inventory{
		TargetID: a.ID, At: at,
		OS:         OSInfo{ID: "debian", VersionID: "12", Pretty: "Debian GNU/Linux 12"},
		PHP:        []PHPRuntime{{SAPI: "fpm", Binary: "/usr/sbin/php-fpm8.2", Version: "8.2.7", FromPackage: "php8.2-fpm", Modules: []string{"curl"}, LoadedIni: "/etc/php/8.2/fpm/php.ini", ScannedFiles: []string{"a.ini"}, PoolFiles: []string{"www.conf"}}},
		Web:        []WebServer{{Name: "nginx", Version: "1.22.1"}},
		Packages:   []Package{{Name: "openssl", Source: "openssl", Version: "3.0.9-1", Arch: "amd64"}},
		Directives: []Directive{{SAPI: "fpm", Name: "expose_php", Value: "On", File: "/etc/php/8.2/fpm/php.ini", Line: 12}, {Name: "db.password", Value: "", Secret: true}},
		Files:      []FileSeen{{Path: "/etc/php/8.2/fpm/php.ini", SHA256: "ab", Size: 10}},
		Unseen:     []Unseen{{What: "/etc/shadow", Reason: "denied"}},
	}
	if err := r.SaveInventory(ctx, inv); err != nil {
		t.Fatal(err)
	}
	newer := inv
	newer.At = at.Add(time.Hour)
	newer.OS.VersionID = "13"
	if err := r.SaveInventory(ctx, newer); err != nil {
		t.Fatal(err)
	}
	got, ok, err := r.LatestInventory(ctx, a.ID)
	if err != nil || !ok || !reflect.DeepEqual(got, newer) {
		t.Fatalf("latest = %+v, %v, %v", got, ok, err)
	}
	if err := r.SaveInventory(ctx, newer); err != nil { // same instant: replaced
		t.Fatal(err)
	}
	if err := r.SaveInventory(ctx, Inventory{TargetID: "nope", At: at}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown target: %v", err)
	}
}

func TestDueRespectsInterval(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	mk := func(name string, interval time.Duration, last time.Time, active bool) {
		x := base(name)
		x.CheckInterval = interval
		got, err := r.Add(ctx, x)
		if err != nil {
			t.Fatal(err)
		}
		got.LastCheckAt, got.Active = last, active
		if err := r.Update(ctx, got); err != nil {
			t.Fatal(err)
		}
	}
	mk("never-checked", 24*time.Hour, time.Time{}, true)
	mk("due", 24*time.Hour, now.Add(-24*time.Hour), true)
	mk("fresh", 24*time.Hour, now.Add(-23*time.Hour), true)
	// A zero interval counts as the default 24 h.
	mk("zero-due", 0, now.Add(-25*time.Hour), true)
	mk("zero-fresh", 0, now.Add(-1*time.Hour), true)
	// A negative interval means by hand only: never due, stored as -1 s.
	mk("manual", -time.Second, time.Time{}, true)
	mk("manual-old", -48*time.Hour, now.Add(-72*time.Hour), true)
	mk("inactive", 24*time.Hour, time.Time{}, false)
	due, err := r.Due(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range due {
		names = append(names, d.Name)
	}
	if !reflect.DeepEqual(names, []string{"due", "never-checked", "zero-due"}) {
		t.Fatalf("due = %v", names)
	}
	m, err := r.Get(ctx, "manual-old")
	if err != nil || m.CheckInterval != ManualOnly {
		t.Fatalf("manual interval stored as %v (%v)", m.CheckInterval, err)
	}
}

func TestIsTargetIDAndGet(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()
	a, _ := r.Add(ctx, base("a"))
	if !r.IsTargetID(ctx, a.ID) || r.IsTargetID(ctx, "01PROJECT") || r.IsTargetID(ctx, "") {
		t.Fatal("IsTargetID wrong")
	}
	if _, err := r.Add(ctx, base("a")); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("duplicate: %v", err)
	}
	g, err := r.Get(ctx, "a")
	if err != nil || g.ID != a.ID {
		t.Fatalf("by name: %+v %v", g, err)
	}
	g, err = r.Get(ctx, a.ID)
	if err != nil || g.Name != "a" {
		t.Fatalf("by id: %+v %v", g, err)
	}
}

func TestSetHostKey(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()
	a, _ := r.Add(ctx, base("a"))
	if err := r.SetHostKey(ctx, a.ID, "SHA256:abc"); err != nil {
		t.Fatal(err)
	}
	if g, _ := r.Get(ctx, "a"); g.HostKey != "SHA256:abc" {
		t.Fatalf("host key = %q", g.HostKey)
	}
	if err := r.SetHostKey(ctx, "nope", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
}
