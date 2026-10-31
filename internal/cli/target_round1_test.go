package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

// ideProject registers a project whose PhpStorm files name a server through a
// saved SSH configuration of the IDE (in the fake HOME), mapped to deploy.
func ideProject(t *testing.T, e *targetEnv, deploy string) {
	t.Helper()
	proj := t.TempDir()
	idea := filepath.Join(proj, ".idea")
	opts := filepath.Join(e.home, ".config", "JetBrains", "PhpStorm2026.1", "options")
	files := map[string]string{
		filepath.Join(idea, "webServers.xml"): `<project><component name="WebServers"><option name="servers"><webServer name="web-demo">` +
			`<fileTransfer accessType="SFTP" sshConfigId="cfg-1"/></webServer></option></component></project>`,
		filepath.Join(idea, "deployment.xml"): `<project><component name="PublishConfigData"><serverData><paths name="web-demo"><serverdata><mappings>` +
			`<mapping deploy="` + deploy + `" local="$PROJECT_DIR$"/></mappings></serverdata></paths></serverData></component></project>`,
		filepath.Join(opts, "sshConfigs.xml"): `<application><component name="SshConfigManager"><configs>` +
			`<sshConfig id="cfg-1" host="192.0.2.60" port="2200" username="deploy"/></configs></component></application>`,
	}
	for p, c := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := run(t, e.dir, "project", "add", proj, "--name", "demo"); err != nil {
		t.Fatal(err)
	}
}

func TestTargetAddLinksOnlyAFolderBelow(t *testing.T) {
	e := newTargetEnv(t)
	ideProject(t, e, "/home/deploy")
	// The server is found through the IDE's saved SSH configuration.
	_, out, _, err := run(t, e.dir, "target", "discover")
	if err != nil || !strings.Contains(out, "web-demo") || !strings.Contains(out, "192.0.2.60") {
		t.Fatalf("discover: %q %v", out, err)
	}
	// A project mapped to a home folder itself is not linked, and Michel says so.
	_, _, stderr, err := run(t, e.dir, "target", "add", "web-demo")
	if err != nil || !strings.Contains(stderr, "/home/deploy") || !strings.Contains(stderr, "not linked") {
		t.Fatalf("add: stderr %q %v", stderr, err)
	}
	tg, err := targetByName(t, e.dir, "web-demo")
	if err != nil {
		t.Fatal(err)
	}
	if links := linksOf(t, e.dir, tg.ID); len(links) != 0 {
		t.Errorf("links = %+v", links)
	}
	// A folder below is linked.
	e2 := newTargetEnv(t)
	ideProject(t, e2, "/home/deploy/site")
	if _, _, _, err := run(t, e2.dir, "target", "add", "web-demo"); err != nil {
		t.Fatal(err)
	}
	tg2, _ := targetByName(t, e2.dir, "web-demo")
	if links := linksOf(t, e2.dir, tg2.ID); len(links) != 1 || links[0].RemoteDir != "/home/deploy/site" {
		t.Errorf("links = %+v", links)
	}
}

func TestTargetAddRefusesBadHostsAndNames(t *testing.T) {
	e := newTargetEnv(t)
	for _, tc := range [][]string{
		{"add", "*.example.test", "--user", "d"},
		{"add", "192.0.2.5", "--user", "d", "--site-url", "https://*.example.test/"},
		{"add", "192.0.2.5", "--user", "d", "--name", strings.Repeat("x", 65)},
		{"add", "192.0.2.5", "--user", "d", "--name", "a​b"},
	} {
		if _, _, _, err := run(t, e.dir, append([]string{"target"}, tc...)...); err == nil {
			t.Errorf("%v was accepted", tc)
		}
	}
	if list := listTargets(t, e.dir); len(list) != 0 {
		t.Errorf("servers = %+v", list)
	}
}

func TestTargetRemoveReleasesRulesButKeepsSharedOnes(t *testing.T) {
	e := newTargetEnv(t)
	for _, n := range []string{"one", "two"} {
		if _, _, _, err := run(t, e.dir, "target", "add", "192.0.2.70", "--user", "deploy", "--name", n); err != nil {
			t.Fatal(err)
		}
	}
	policyOf := func() string { b, _ := os.ReadFile(filepath.Join(e.dir, "config.yaml")); return string(b) }
	if _, _, _, err := run(t, e.dir, "target", "remove", "one"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(policyOf(), "192.0.2.70") {
		t.Error("the rule of a server that stays was removed")
	}
	if _, _, _, err := run(t, e.dir, "target", "remove", "two"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(policyOf(), "192.0.2.70") {
		t.Errorf("rule left:\n%s", policyOf())
	}
	if ev := auditRows(t, e.dir, "target.remove"); len(ev) != 2 || ev[1].evidence["rules_removed"] != float64(1) || ev[0].evidence["rules_removed"] != float64(0) {
		t.Errorf("audit = %+v", ev)
	}
}

func TestTargetTrustReplaceNeedsTheFlag(t *testing.T) {
	e := newTargetEnv(t)
	if _, _, _, err := run(t, e.dir, "target", "add", "srv-demo"); err != nil {
		t.Fatal(err)
	}
	fp := e.ssh.HostKeyFingerprint()
	if _, _, _, err := run(t, e.dir, "target", "trust", "srv-demo", "--fingerprint", fp); err != nil {
		t.Fatal(err)
	}
	setPin(t, e.dir, "srv-demo", "SHA256:other")
	_, _, _, err := run(t, e.dir, "target", "trust", "srv-demo", "--fingerprint", fp)
	if err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("without --replace: %v", err)
	}
	if tg, _ := targetByName(t, e.dir, "srv-demo"); tg.HostKey != "SHA256:other" {
		t.Errorf("pin = %q", tg.HostKey)
	}
	if _, _, _, err := run(t, e.dir, "target", "trust", "srv-demo", "--fingerprint", fp, "--replace"); err != nil {
		t.Fatal(err)
	}
	if tg, _ := targetByName(t, e.dir, "srv-demo"); tg.HostKey != fp {
		t.Errorf("pin = %q", tg.HostKey)
	}
}

func linksOf(t *testing.T, dir, id string) []target.Link {
	t.Helper()
	return withRepo(t, dir, func(r *target.Repo) any {
		l, _ := r.Links(t.Context(), id)
		return l
	}).([]target.Link)
}

func listTargets(t *testing.T, dir string) []target.Target {
	t.Helper()
	return withRepo(t, dir, func(r *target.Repo) any {
		l, _ := r.List(t.Context())
		return l
	}).([]target.Target)
}

func setPin(t *testing.T, dir, name, fp string) {
	t.Helper()
	withRepo(t, dir, func(r *target.Repo) any {
		tg, err := r.Get(t.Context(), name)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.SetHostKey(t.Context(), tg.ID, fp); err != nil {
			t.Fatal(err)
		}
		return nil
	})
}

func withRepo(t *testing.T, dir string, f func(r *target.Repo) any) any {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	return f(target.NewRepo(s))
}
