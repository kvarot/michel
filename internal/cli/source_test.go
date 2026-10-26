package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

// sourceEntry reads one registry entry of the data folder dir.
func sourceEntry(t *testing.T, dir, key string) (source.Entry, error) {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	return source.NewRepo(s).Get(context.Background(), key)
}

// lineOf returns the first line of out that starts with key.
func lineOf(out, key string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, key+" ") {
			return l
		}
	}
	return ""
}

func TestSourceListShowsStateAndKind(t *testing.T) {
	dir := t.TempDir()
	_, out, _, err := run(t, dir, "source", "list")
	if err != nil {
		t.Fatal(err)
	}
	if l := lineOf(out, "osv.packagist"); !strings.Contains(l, "OSV database") || !strings.Contains(l, "waiting for your consent") {
		t.Errorf("osv.packagist line = %q", l)
	}
	if l := lineOf(out, "enrich.kev"); !strings.Contains(l, "enrichment") || !strings.Contains(l, "off") {
		t.Errorf("enrich.kev line = %q", l)
	}
	_, out, _, err = run(t, dir, "source", "list", "--kind", "feed")
	if err != nil || lineOf(out, "feed.nginx") == "" || lineOf(out, "osv.packagist") != "" {
		t.Errorf("--kind feed: err %v\n%s", err, out)
	}
	if _, _, _, err := run(t, dir, "source", "list", "--kind", "nope"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("unknown kind: %v", err)
	}
	_, out, _, err = run(t, dir, "source", "list", "--kind", "osv", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var list []struct {
		Key   string `json:"key"`
		Kind  string `json:"kind"`
		State string `json:"state"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil || len(list) == 0 {
		t.Fatalf("json: %v\n%s", err, out)
	}
	for _, e := range list {
		if e.Key == "osv.npm" && (e.State != "waiting_consent" || e.Kind != "osv") {
			t.Errorf("json osv.npm = %+v", e)
		}
	}
	_, out, _, err = run(t, dir, "source", "show", "enrich.kev")
	if err != nil || !strings.Contains(out, "www.cisa.gov") || !strings.Contains(out, "source.enrich") {
		t.Errorf("show: err %v\n%s", err, out)
	}
}

func TestSourceEnableNeedsYesWhenNotTTY(t *testing.T) {
	dir := t.TempDir()
	_, errOut, err := runIn(t, dir, strings.NewReader("y\n"), "source", "enable", "enrich.kev")
	if err == nil || ExitCode(err) != ExitCodePolicy {
		t.Fatalf("err = %v (exit %d)", err, ExitCode(err))
	}
	if !strings.Contains(errOut, "www.cisa.gov") || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("stderr = %q, err = %v", errOut, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.yaml")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the policy file was written without consent: %v", err)
	}
	if e, err := sourceEntry(t, dir, "enrich.kev"); err != nil || e.Enabled {
		t.Errorf("entry = %+v err %v", e, err)
	}
}

func TestSourceEnableYesWritesRule(t *testing.T) {
	dir := t.TempDir()
	out, _, err := runIn(t, dir, strings.NewReader(""), "source", "enable", "enrich.kev", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "enrich.kev") || !strings.Contains(out, "www.cisa.gov") {
		t.Errorf("out = %q", out)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil || !strings.Contains(string(raw), "www.cisa.gov") || !strings.Contains(string(raw), "source.enrich") {
		t.Fatalf("config = %s err %v", raw, err)
	}
	_, out, _, err = run(t, dir, "source", "list", "--kind", "enrichment")
	if err != nil || !strings.Contains(lineOf(out, "enrich.kev"), " on ") {
		t.Errorf("list after enable: err %v\n%s", err, out)
	}
	if ev := auditRows(t, dir, "source.consent"); len(ev) != 1 || ev[0].target != "enrich.kev" {
		t.Errorf("consent events = %+v", ev)
	}
	// Disabling keeps the rule unless --forget is given.
	if _, out, _, err = run(t, dir, "source", "disable", "enrich.kev"); err != nil || !strings.Contains(out, "--forget") {
		t.Errorf("disable: err %v out %q", err, out)
	}
	if raw, _ := os.ReadFile(filepath.Join(dir, "config.yaml")); !strings.Contains(string(raw), "www.cisa.gov") {
		t.Error("disable removed the rule")
	}
	if _, _, _, err = run(t, dir, "source", "disable", "enrich.kev", "--forget"); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(filepath.Join(dir, "config.yaml")); strings.Contains(string(raw), "www.cisa.gov") {
		t.Error("disable --forget kept the rule")
	}
}

func TestSourceAddFeedValidatesURL(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"--name", "Demo", "--url", "http://example.org/feed.xml"},
		{"--name", "Demo"},
		{"--name", "Demo", "--repo", "acme/lib"},
		{"--name", "Demo", "--url", "https://example.org/feed.xml", "--format", "weird"},
	} {
		_, _, _, err := run(t, dir, append([]string{"source", "add", "--kind", "feed"}, args...)...)
		if err == nil {
			t.Errorf("%v: expected a refusal", args)
		}
	}
	_, out, _, err := run(t, dir, "source", "add", "--kind", "feed", "--name", "Demo", "--url", "https://example.org/feed.xml", "--tech", "nginx")
	if err != nil || !strings.Contains(out, "feed.demo") {
		t.Fatalf("add: err %v out %q", err, out)
	}
	e, err := sourceEntry(t, dir, "feed.demo")
	if err != nil || e.Origin != source.OriginUser || e.Enabled || e.Hosts[0] != "example.org" || e.Purpose != "source.feed" || e.Tech[0] != "nginx" {
		t.Errorf("entry = %+v err %v", e, err)
	}
	if _, _, _, err := run(t, dir, "source", "add", "--kind", "feed", "--name", "Demo", "--url", "https://example.org/other.xml"); err == nil {
		t.Error("a second entry with the same key was accepted")
	}
	if _, _, _, err := run(t, dir, "source", "add", "--kind", "feed", "--name", "Lib advisories", "--repo", "acme/lib", "--format", "github_advisories"); err != nil {
		t.Errorf("github advisories feed: %v", err)
	}
	if e, err := sourceEntry(t, dir, "feed.lib-advisories"); err != nil || e.Hosts[0] != "api.github.com" || e.Config.Str("repo") != "acme/lib" {
		t.Errorf("advisories entry = %+v err %v", e, err)
	}
	for _, args := range [][]string{
		{"--kind", "osv"},
		{"--kind", "plugin", "--name", "x"},
		{"--kind", "skill", "--repo", "example/skill", "--pin", "abc"},
		{"--kind", "reference", "--name", "x"},
	} {
		if _, _, _, err := run(t, dir, append([]string{"source", "add"}, args...)...); err == nil {
			t.Errorf("%v: expected a refusal", args)
		}
	}
	if _, _, _, err := run(t, dir, "source", "add", "--kind", "skill", "--repo", "example/skill", "--pin", strings.Repeat("a1", 20)); err != nil {
		t.Errorf("skill: %v", err)
	}
	if ev := auditRows(t, dir, "source.add"); len(ev) != 3 {
		t.Errorf("source.add events = %+v", ev)
	}
}

func TestSourceRemoveUserDeletesCatalogHides(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := run(t, dir, "source", "add", "--kind", "feed", "--name", "Demo", "--url", "https://example.org/feed.xml"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "source", "remove", "feed.demo"); err != nil {
		t.Fatal(err)
	}
	if _, err := sourceEntry(t, dir, "feed.demo"); !errors.Is(err, source.ErrNotFound) {
		t.Errorf("user entry still there: %v", err)
	}
	if _, _, _, err := run(t, dir, "source", "remove", "feed.nginx"); err != nil {
		t.Fatal(err)
	}
	if e, err := sourceEntry(t, dir, "feed.nginx"); err != nil || !e.Hidden {
		t.Errorf("catalog entry = %+v err %v", e, err)
	}
	_, out, _, _ := run(t, dir, "source", "list", "--kind", "feed")
	if lineOf(out, "feed.nginx") != "" {
		t.Errorf("hidden entry listed:\n%s", out)
	}
	_, out, _, _ = run(t, dir, "source", "list", "--kind", "feed", "--all")
	if !strings.Contains(lineOf(out, "feed.nginx"), "hidden") {
		t.Errorf("--all does not show the hidden entry:\n%s", out)
	}
	if _, _, _, err := run(t, dir, "source", "reset", "feed.nginx"); err != nil {
		t.Fatal(err)
	}
	if e, _ := sourceEntry(t, dir, "feed.nginx"); e.Hidden {
		t.Error("reset did not bring the entry back")
	}
	if ev := auditRows(t, dir, "source.remove"); len(ev) != 2 {
		t.Errorf("source.remove events = %+v", ev)
	}
	if _, _, _, err := run(t, dir, "source", "remove", "feed.absent"); err == nil {
		t.Error("removing an unknown entry succeeded")
	}
}

func TestSourceResetPurgeNeedsYes(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := run(t, dir, "source", "add", "--kind", "feed", "--name", "Demo", "--url", "https://example.org/feed.xml"); err != nil {
		t.Fatal(err)
	}
	_, errOut, err := runIn(t, dir, strings.NewReader("y\n"), "source", "reset", "--all", "--purge-user")
	if err == nil || ExitCode(err) != ExitCodePolicy || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("err = %v (exit %d)", err, ExitCode(err))
	}
	if !strings.Contains(errOut, "feed.demo") {
		t.Errorf("stderr does not list what would be deleted: %q", errOut)
	}
	if _, err := sourceEntry(t, dir, "feed.demo"); err != nil {
		t.Errorf("user source deleted without confirmation: %v", err)
	}
	if ev := auditRows(t, dir, "source.reset"); len(ev) != 1 || ev[0].result != "denied" {
		t.Errorf("source.reset events = %+v", ev)
	}

	// Without --purge-user nothing needs a confirmation.
	if _, _, err := runIn(t, dir, strings.NewReader(""), "source", "reset", "--all"); err != nil {
		t.Fatal(err)
	}
	if _, err := sourceEntry(t, dir, "feed.demo"); err != nil {
		t.Errorf("reset --all deleted a user source: %v", err)
	}

	out, _, err := runIn(t, dir, strings.NewReader(""), "source", "reset", "--all", "--purge-user", "--yes")
	if err != nil || !strings.Contains(out, "sources are back") {
		t.Fatalf("--yes: out %q err %v", out, err)
	}
	if _, err := sourceEntry(t, dir, "feed.demo"); !errors.Is(err, source.ErrNotFound) {
		t.Errorf("user source kept by --purge-user --yes: %v", err)
	}
}
