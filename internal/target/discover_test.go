package target

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/project"
)

// treeDigest is the SHA-256 of every path, size and modification time under
// root: equal digests mean nothing was created, removed or written there.
func treeDigest(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		fmt.Fprintf(h, "%s\x00%d\x00%d\n", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// fixture builds a fake HOME with ~/.ssh/config and a project with .idea files.
func fixture(t *testing.T) (home string, proj project.Project) {
	t.Helper()
	home = t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	copyFile(t, "testdata/conf.d/extra.conf", filepath.Join(ssh, "conf.d", "extra.conf"))
	copyFile(t, "testdata/ssh_config", filepath.Join(ssh, "config"))
	root := filepath.Join(t.TempDir(), "demo")
	for _, f := range []string{"webServers.xml", "deployment.xml"} {
		copyFile(t, filepath.Join("testdata", f), filepath.Join(root, ".idea", f))
	}
	return home, project.Project{ID: "01PROJDEMO", Name: "demo", Path: root}
}

func byAlias(cs []Candidate, alias string) *Candidate {
	for i := range cs {
		if cs[i].Alias == alias {
			return &cs[i]
		}
	}
	return nil
}

func TestParseSSHConfigSkipsWildcards(t *testing.T) {
	f, err := os.Open("testdata/ssh_config")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cs, err := ParseSSHConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 2 {
		t.Fatalf("want 2 candidates (include not followed from a reader), got %+v", cs)
	}
	s := byAlias(cs, "srv-demo")
	if s == nil || s.Host != "example.test" || s.Port != 2222 || s.User != "deploy" || s.IdentityFile != "~/.ssh/id_ed25519" {
		t.Fatalf("srv-demo = %+v", s)
	}
	ip := byAlias(cs, "ip-demo")
	if ip == nil || ip.Host != "192.0.2.10" || ip.Port != 22 {
		t.Fatalf("ip-demo = %+v", ip)
	}
	for _, c := range cs {
		if strings.ContainsAny(c.Alias, "*?!") {
			t.Fatalf("wildcard kept: %+v", c)
		}
		if len(c.From) != 1 || c.From[0] != "ssh_config" {
			t.Fatalf("from = %v", c.From)
		}
	}
}

func TestParseSSHConfigInclude(t *testing.T) {
	home, _ := fixture(t)
	cs, err := Discover(context.Background(), home, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := byAlias(cs, "extra-demo")
	if e == nil || e.Host != "198.51.100.7" {
		t.Fatalf("include not followed: %+v", cs)
	}
	if e.IdentityFile != "other_key" {
		t.Fatalf("identity outside HOME must be a base name, got %q", e.IdentityFile)
	}
	// A self-including file must terminate.
	ssh := filepath.Join(home, ".ssh")
	if err := os.WriteFile(filepath.Join(ssh, "loop"), []byte("Include loop\nHost l\n  HostName example.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ssh, "config"), []byte("Include loop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(context.Background(), home, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestParsePhpStormSFTPAndMappings(t *testing.T) {
	_, p := fixture(t)
	cs, err := ParsePhpStorm(p.Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 2 {
		t.Fatalf("want 2 SFTP servers (FTP skipped), got %+v", cs)
	}
	a := byAlias(cs, "prod-demo")
	if a == nil || a.Host != "example.test" || a.Port != 2222 || a.User != "deploy" || a.From[0] != "phpstorm" {
		t.Fatalf("prod-demo = %+v", a)
	}
	if len(a.Projects) != 1 || a.Projects[0].RemoteDir != "/var/www/app" {
		t.Fatalf("remote dir should be the mapping of the project root: %+v", a.Projects)
	}
	n := byAlias(cs, "nested-demo")
	if n == nil || n.Host != "192.0.2.10" || n.Port != 22 || n.Projects[0].RemoteDir != "/srv/demo" {
		t.Fatalf("nested-demo = %+v", n)
	}
	empty, err := ParsePhpStorm(t.TempDir())
	if err != nil || len(empty) != 0 {
		t.Fatalf("absent files: %v %v", empty, err)
	}
}

func TestDiscoverMergesSources(t *testing.T) {
	home, p := fixture(t)
	cs, err := Discover(context.Background(), home, []project.Project{p}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// srv-demo (ssh_config) and prod-demo (phpstorm) share example.test:2222:deploy.
	var merged *Candidate
	count := 0
	for i := range cs {
		if cs[i].Host == "example.test" && cs[i].Port == 2222 {
			merged = &cs[i]
			count++
		}
	}
	if count != 1 {
		t.Fatalf("want one merged candidate, got %d in %+v", count, cs)
	}
	if len(merged.From) != 2 {
		t.Fatalf("sources not accumulated: %+v", merged)
	}
	if len(merged.Projects) != 1 || merged.Projects[0].ProjectID != p.ID || merged.Projects[0].RemoteDir != "/var/www/app" {
		t.Fatalf("links = %+v", merged.Projects)
	}
	if merged.Alias != "srv-demo" || merged.IdentityFile != "~/.ssh/id_ed25519" {
		t.Fatalf("ssh_config alias and identity should win: %+v", merged)
	}
	for i := 1; i < len(cs); i++ {
		if cs[i-1].Alias > cs[i].Alias {
			t.Fatalf("not sorted: %+v", cs)
		}
	}
}

func TestDiscoverMarksKnown(t *testing.T) {
	home, p := fixture(t)
	cs, err := Discover(context.Background(), home, []project.Project{p}, []Target{{Host: "192.0.2.10", Port: 0, User: "deploy"}})
	if err != nil {
		t.Fatal(err)
	}
	known := 0
	for _, c := range cs {
		if c.Known {
			known++
			if c.Host != "192.0.2.10" {
				t.Fatalf("wrong known: %+v", c)
			}
		}
	}
	if known != 1 {
		t.Fatalf("known = %d, %+v", known, cs)
	}
}

func TestDiscoverNeverWrites(t *testing.T) {
	home, p := fixture(t)
	h0, p0 := treeDigest(t, home), treeDigest(t, p.Path)
	if _, err := Discover(context.Background(), home, []project.Project{p}, nil); err != nil {
		t.Fatal(err)
	}
	if treeDigest(t, home) != h0 || treeDigest(t, p.Path) != p0 {
		t.Fatal("discovery wrote to HOME or a project")
	}
}

func TestDiscoverIgnoresPasswordFields(t *testing.T) {
	home, p := fixture(t)
	cs, err := Discover(context.Background(), home, []project.Project{p}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dump := fmt.Sprintf("%#v", cs)
	for _, secret := range []string{"hunter2-secret", "p4ss-secret", "nested-secret", home, p.Path} {
		if strings.Contains(dump, secret) {
			t.Fatalf("result leaks %q", secret)
		}
	}
}
