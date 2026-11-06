package source

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/store"
	"gopkg.in/yaml.v3"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func synced(t *testing.T) (*Repo, *store.Store) {
	t.Helper()
	s := newStore(t)
	r := NewRepo(s)
	if _, _, err := Sync(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	return r, s
}

func get(t *testing.T, r *Repo, key string) Entry {
	t.Helper()
	e, err := r.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	return e
}

func readCatalog(t *testing.T, lang string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "i18n", "catalog", lang+".json"))
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCatalogParsesAndKeysAreValid(t *testing.T) {
	entries, rules, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 50 || len(rules) == 0 {
		t.Fatalf("entries = %d, rules = %d", len(entries), len(rules))
	}
	en, fr := readCatalog(t, "en"), readCatalog(t, "fr")
	kinds := map[Kind]int{}
	var enabled []string
	seen := map[string]bool{}
	for _, e := range entries {
		if !ValidKey(e.Key) {
			t.Errorf("%s: invalid key", e.Key)
		}
		if seen[e.Key] {
			t.Errorf("%s: listed twice", e.Key)
		}
		seen[e.Key] = true
		if !e.Kind.Valid() {
			t.Errorf("%s: unknown kind %q", e.Key, e.Kind)
		}
		kinds[e.Kind]++
		if (len(e.Hosts) == 0) != (e.Purpose == "") {
			t.Errorf("%s: hosts %v but purpose %q", e.Key, e.Hosts, e.Purpose)
		}
		if e.Origin != OriginCatalog || e.CatalogVersion != CatalogVersion {
			t.Errorf("%s: origin %q version %d", e.Key, e.Origin, e.CatalogVersion)
		}
		if e.Enabled {
			enabled = append(enabled, e.Key)
		}
		note := NoteKey(e.Key)
		if en[note] == "" || fr[note] == "" {
			t.Errorf("%s: note %s missing in en or fr", e.Key, note)
		}
		if e.Kind == KindOSV && (len(e.Hosts) != 1 || e.Hosts[0] != "osv-vulnerabilities.storage.googleapis.com" || e.Purpose != policy.PurposeOSV || e.Config.Str("ecosystem") == "") {
			t.Errorf("%s: osv hosts %v purpose %q config %v", e.Key, e.Hosts, e.Purpose, e.Config.Catalog)
		}
	}
	if !reflect.DeepEqual(enabled, []string{"osv.packagist", "osv.npm"}) {
		t.Errorf("enabled by default = %v", enabled)
	}
	for _, k := range []Kind{KindOSV, KindEnrichment, KindFeed, KindPlugin, KindSkill, KindMCP, KindReference} {
		if kinds[k] == 0 {
			t.Errorf("no entry of kind %s", k)
		}
	}
	for _, key := range []string{"enrich.kev", "feed.nginx", "skill.trailofbits-code-audit", "mcp.safedep-vet", "ref.cve-org", "plugin.trivy", "discover.github"} {
		if !seen[key] {
			t.Errorf("%s missing from the catalog", key)
		}
	}
	for _, r := range rules {
		if r.Tag == "" || !project.ValidTech(r.Tag) || r.Ecosystem == "" {
			t.Errorf("bad tech rule %+v", r)
		}
	}
}

func TestSyncInsertsThenKeepsUserChoices(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	r := NewRepo(s)
	entries, _, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	ins, upd, err := Sync(ctx, r)
	if err != nil || ins != len(entries) || upd != 0 {
		t.Fatalf("first sync: inserted %d updated %d err %v", ins, upd, err)
	}
	if ins, upd, err := Sync(ctx, r); err != nil || ins != 0 || upd != 0 {
		t.Fatalf("second sync: inserted %d updated %d err %v", ins, upd, err)
	}
	if err := r.SetEnabled(ctx, "enrich.kev", true); err != nil {
		t.Fatal(err)
	}
	if err := r.SetHidden(ctx, "feed.nginx", true); err != nil {
		t.Fatal(err)
	}
	if err := r.SetUserConfig(ctx, "feed.nginx", map[string]any{"format": "rss"}); err != nil {
		t.Fatal(err)
	}
	// A newer catalog renames both entries.
	next := make([]Entry, len(entries))
	copy(next, entries)
	for i := range next {
		switch next[i].Key {
		case "enrich.kev":
			next[i].Name = "CISA KEV (renamed)"
		case "feed.nginx":
			next[i].Name = "nginx (renamed)"
		}
	}
	ins, upd, err = syncEntries(ctx, r, next, CatalogVersion+1)
	if err != nil || ins != 0 || upd != len(entries) {
		t.Fatalf("newer sync: inserted %d updated %d err %v", ins, upd, err)
	}
	kev, nginx := get(t, r, "enrich.kev"), get(t, r, "feed.nginx")
	if kev.Name != "CISA KEV (renamed)" || !kev.Enabled || kev.CatalogVersion != CatalogVersion+1 {
		t.Errorf("kev = %+v", kev)
	}
	if nginx.Name != "nginx (renamed)" || !nginx.Hidden || nginx.Config.Str("format") != "rss" || !reflect.DeepEqual(nginx.Tech, []string{"nginx"}) {
		t.Errorf("nginx = %+v", nginx)
	}
	// An entry dropped by a newer catalog is hidden, never deleted.
	if _, _, err := syncEntries(ctx, r, next[1:], CatalogVersion+2); err != nil {
		t.Fatal(err)
	}
	if dropped := get(t, r, next[0].Key); !dropped.Hidden {
		t.Errorf("dropped entry = %+v", dropped)
	}
}

// A newer catalog that moves an entry to another host (the EPSS feed moved in
// catalog 4) leaves the entry enabled but waiting for consent: the allow rule
// written for the old host does not cover the new one, so the source is not
// read and its state says why, instead of a silent egress denial.
func TestSyncHostChangeWaitsForConsentAgain(t *testing.T) {
	ctx := context.Background()
	r := NewRepo(newStore(t))
	entries, _, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Sync(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := r.SetEnabled(ctx, "enrich.epss", true); err != nil {
		t.Fatal(err)
	}
	rules := map[string]bool{"old.example.org|" + get(t, r, "enrich.epss").Purpose: true}
	allowed := func(host, purpose string) bool { return rules[host+"|"+purpose] }
	next := make([]Entry, len(entries))
	copy(next, entries)
	for i := range next {
		if next[i].Key == "enrich.epss" {
			next[i].Hosts = []string{"old.example.org"}
		}
	}
	if _, _, err := syncEntries(ctx, r, next, CatalogVersion+1); err != nil {
		t.Fatal(err)
	}
	if st := get(t, r, "enrich.epss").State(allowed); st != StateOn {
		t.Fatalf("consented on the old host: state %s", st)
	}
	for i := range next {
		if next[i].Key == "enrich.epss" {
			next[i].Hosts = []string{"new.example.org"}
		}
	}
	if _, _, err := syncEntries(ctx, r, next, CatalogVersion+2); err != nil {
		t.Fatal(err)
	}
	e := get(t, r, "enrich.epss")
	if !e.Enabled || !reflect.DeepEqual(e.Hosts, []string{"new.example.org"}) {
		t.Fatalf("after the move: %+v", e)
	}
	if st := e.State(allowed); st != StateWaitingConsent {
		t.Errorf("after the move: state %s, want %s", st, StateWaitingConsent)
	}
	if need := ConsentNeeded(e, allowed); len(need) != 1 || need[0].Host != "new.example.org" {
		t.Errorf("consent needed = %+v", need)
	}
}

func TestStateWaitingConsentWithoutRule(t *testing.T) {
	r, _ := synced(t)
	none := func(string, string) bool { return false }
	all := func(string, string) bool { return true }
	pk := get(t, r, "osv.packagist")
	if st := pk.State(none); st != StateWaitingConsent {
		t.Errorf("enabled without rule: %s", st)
	}
	if st := pk.State(all); st != StateOn {
		t.Errorf("enabled with rule: %s", st)
	}
	if st := get(t, r, "enrich.kev").State(all); st != StateOff {
		t.Errorf("disabled: %s", st)
	}
	ctx := context.Background()
	if err := r.SetEnabled(ctx, "plugin.trivy", true); err != nil {
		t.Fatal(err)
	}
	if st := get(t, r, "plugin.trivy").State(none); st != StateOn {
		t.Errorf("plugin without host: %s", st)
	}
	if err := r.SetHidden(ctx, "plugin.trivy", true); err != nil {
		t.Fatal(err)
	}
	if st := get(t, r, "plugin.trivy").State(all); st != StateHidden {
		t.Errorf("hidden: %s", st)
	}
}

func TestUpsertUserEntryAndDeleteCatalogRefused(t *testing.T) {
	r, _ := synced(t)
	ctx := context.Background()
	key := KeyFor(KindFeed, "Mon flux à moi!")
	if key != "feed.mon-flux-moi" {
		t.Fatalf("KeyFor = %q", key)
	}
	e, err := r.Upsert(ctx, Entry{
		Key: key, Kind: KindFeed, Origin: OriginUser, Name: "Mon flux", URL: "https://example.org/feed.xml",
		Hosts: []string{"example.org"}, Purpose: policy.PurposeFeed,
		Config: Config{Catalog: map[string]any{}, User: map[string]any{"format": "rss"}}, Tech: []string{"nginx"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.ID == "" || e.CreatedAt.IsZero() {
		t.Errorf("upserted = %+v", e)
	}
	got := get(t, r, key)
	if got.Origin != OriginUser || got.Config.Str("format") != "rss" || got.Hosts[0] != "example.org" || got.CatalogVersion != 0 || got.ID != e.ID {
		t.Errorf("got = %+v", got)
	}
	if _, err := r.Upsert(ctx, Entry{Key: "feed.bad", Kind: KindFeed, Origin: OriginUser, Name: "x",
		Config: Config{User: map[string]any{"unknown": 1}}}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("unknown config key: %v", err)
	}
	if _, err := r.Upsert(ctx, Entry{Key: "Feed.Bad", Kind: KindFeed, Origin: OriginUser, Name: "x"}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("bad key: %v", err)
	}
	if err := r.Delete(ctx, "feed.nginx"); !errors.Is(err, ErrCatalogEntry) {
		t.Errorf("delete catalog entry: %v", err)
	}
	if err := r.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
	list, err := r.List(ctx, KindFeed, false)
	if err != nil || len(list) == 0 {
		t.Fatalf("list = %d err %v", len(list), err)
	}
	for _, e := range list {
		if e.Kind != KindFeed {
			t.Errorf("list by kind returned %s", e.Key)
		}
	}
	if err := r.SetHidden(ctx, "feed.nginx", true); err != nil {
		t.Fatal(err)
	}
	visible, _ := r.List(ctx, KindFeed, false)
	everything, _ := r.List(ctx, KindFeed, true)
	if len(everything) != len(visible)+1 {
		t.Errorf("hidden entries: visible %d, all %d", len(visible), len(everything))
	}
}

func TestResetRestoresCatalogAndKeepsUser(t *testing.T) {
	r, _ := synced(t)
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(r.SetEnabled(ctx, "enrich.kev", true))
	must(r.SetEnabled(ctx, "osv.npm", false))
	must(r.SetHidden(ctx, "feed.nginx", true))
	must(r.SetUserConfig(ctx, "feed.nginx", map[string]any{"format": "rss"}))
	_, err := r.Upsert(ctx, Entry{Key: "feed.mine", Kind: KindFeed, Origin: OriginUser, Name: "Mine",
		URL: "https://example.org/", Hosts: []string{"example.org"}, Purpose: policy.PurposeFeed})
	must(err)

	n, err := Reset(ctx, r, "enrich.kev", false, false)
	if err != nil || n != 1 || get(t, r, "enrich.kev").Enabled {
		t.Fatalf("reset one: n=%d err=%v", n, err)
	}
	if !get(t, r, "feed.nginx").Hidden {
		t.Error("reset of one entry touched another")
	}
	if _, err := Reset(ctx, r, "feed.mine", false, false); !errors.Is(err, ErrUserEntry) {
		t.Errorf("reset of a user entry: %v", err)
	}
	if _, err := Reset(ctx, r, "feed.absent", false, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("reset of an unknown entry: %v", err)
	}

	if _, err := Reset(ctx, r, "", true, false); err != nil {
		t.Fatal(err)
	}
	nginx := get(t, r, "feed.nginx")
	if nginx.Hidden || len(nginx.Config.User) != 0 || !get(t, r, "osv.npm").Enabled {
		t.Errorf("after reset --all: nginx %+v", nginx)
	}
	if _, err := r.Get(ctx, "feed.mine"); err != nil {
		t.Errorf("user entry lost by reset --all: %v", err)
	}
	if _, err := Reset(ctx, r, "", true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(ctx, "feed.mine"); !errors.Is(err, ErrNotFound) {
		t.Errorf("user entry kept by --purge-user: %v", err)
	}
}

// testDeps builds consent dependencies around a policy file at path.
func testDeps(t *testing.T, r *Repo, s *store.Store, path string) Deps {
	t.Helper()
	dir := t.TempDir()
	p, _, err := policy.Load(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	return Deps{
		Repo: r, Audit: audit.NewLogger(s, time.Now), Gateway: egress.New(p, nil), PolicyPath: path,
		Actor: "test", Now: time.Now,
		Reload: func() (policy.Policy, error) {
			p, _, err := policy.Load(path, dir)
			if err == nil {
				err = policy.Validate(p)
			}
			return p, err
		},
	}
}

func countAudit(t *testing.T, s *store.Store, action string) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM audit_event WHERE action = ?`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func allowedBy(d Deps) func(string, string) bool {
	return func(h, p string) bool { ok, _ := d.Gateway.Allowed(h, p); return ok }
}

func TestEnableWritesRuleRecordsConsentAndReloads(t *testing.T) {
	r, s := synced(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("# my policy\nsovereignty:\n  mode: strict_local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := testDeps(t, r, s, path)
	_, texts, err := Enable(ctx, d, "enrich.kev", false)
	if !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("err = %v", err)
	}
	if len(texts) != 1 || texts[0].Host != "www.cisa.gov" || texts[0].Purpose != "source.enrich" || texts[0].Key != "enrich.kev" || texts[0].What == "" {
		t.Fatalf("texts = %+v", texts)
	}
	if get(t, r, "enrich.kev").Enabled || countAudit(t, s, "source.consent") != 0 {
		t.Fatal("a refused consent changed something")
	}
	e, texts, err := Enable(ctx, d, "enrich.kev", true)
	if err != nil || len(texts) != 1 {
		t.Fatalf("texts = %+v err %v", texts, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := policy.Load(path, t.TempDir())
	if err != nil || len(p.Sovereignty.Network.Allow) != 1 || p.Sovereignty.Network.Allow[0] != (policy.AllowRule{Host: "www.cisa.gov", Purpose: "source.enrich"}) {
		t.Fatalf("file = %s err %v", raw, err)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf(".bak: %v", err)
	}
	if countAudit(t, s, "source.consent") != 1 || countAudit(t, s, "source.enable") != 1 {
		t.Errorf("audit consent=%d enable=%d", countAudit(t, s, "source.consent"), countAudit(t, s, "source.enable"))
	}
	if !e.Enabled || e.State(allowedBy(d)) != StateOn || get(t, r, "enrich.kev").State(allowedBy(d)) != StateOn {
		t.Errorf("entry = %+v", e)
	}
}

func TestEnableCreatesPolicyFileWhenAbsent(t *testing.T) {
	r, s := synced(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config.yaml")
	d := testDeps(t, r, s, path)
	if _, _, err := Enable(ctx, d, "enrich.kev", true); err != nil {
		t.Fatal(err)
	}
	p, src, err := policy.Load(path, t.TempDir())
	if err != nil || src != policy.SourceFile {
		t.Fatalf("src %s err %v", src, err)
	}
	if err := policy.Validate(p); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	sov, _ := doc["sovereignty"].(map[string]any)
	netw, _ := sov["network"].(map[string]any)
	if len(doc) != 1 || len(sov) != 1 || len(netw) != 1 || netw["allow"] == nil {
		t.Errorf("file holds more than sovereignty.network.allow:\n%s", raw)
	}
	if ok, _ := d.Gateway.Allowed("www.cisa.gov", policy.PurposeEnrich); !ok {
		t.Error("the gateway did not learn the new rule")
	}
}

func TestEnableSharedRuleAsksNothing(t *testing.T) {
	r, s := synced(t)
	ctx := context.Background()
	d := testDeps(t, r, s, filepath.Join(t.TempDir(), "config.yaml"))
	if _, _, err := Enable(ctx, d, "osv.packagist", true); err != nil {
		t.Fatal(err)
	}
	if need := ConsentNeeded(get(t, r, "osv.npm"), allowedBy(d)); len(need) != 0 {
		t.Fatalf("consent asked again: %+v", need)
	}
	if _, texts, err := Enable(ctx, d, "osv.npm", false); err != nil || len(texts) != 0 {
		t.Fatalf("texts %+v err %v", texts, err)
	}
	if n := countAudit(t, s, "source.consent"); n != 2 {
		t.Errorf("source.consent events = %d", n)
	}
	shared, err := SharedWith(ctx, r, get(t, r, "osv.npm"))
	if err != nil || !reflect.DeepEqual(shared, []string{"osv.packagist"}) {
		t.Errorf("shared = %v err %v", shared, err)
	}
}

func TestDisableForgetRefusedWhenShared(t *testing.T) {
	r, s := synced(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config.yaml")
	d := testDeps(t, r, s, path)
	for _, k := range []string{"osv.packagist", "osv.npm"} {
		if _, _, err := Enable(ctx, d, k, true); err != nil {
			t.Fatal(err)
		}
	}
	err := Disable(ctx, d, "osv.npm", true)
	var shared ErrRuleShared
	if !errors.As(err, &shared) || shared.Key != "osv.packagist" {
		t.Fatalf("err = %v", err)
	}
	if !get(t, r, "osv.npm").Enabled {
		t.Error("a refused --forget still disabled the entry")
	}
	if err := Disable(ctx, d, "osv.npm", false); err != nil {
		t.Fatal(err)
	}
	if err := Disable(ctx, d, "osv.packagist", true); err != nil {
		t.Fatal(err)
	}
	p, _, err := policy.Load(path, t.TempDir())
	if err != nil || len(p.Sovereignty.Network.Allow) != 0 {
		t.Errorf("rule kept after --forget: %+v err %v", p.Sovereignty.Network.Allow, err)
	}
	if ok, _ := d.Gateway.Allowed("osv-vulnerabilities.storage.googleapis.com", policy.PurposeOSV); ok {
		t.Error("the gateway still allows the forgotten rule")
	}
	if n := countAudit(t, s, "source.disable"); n != 2 {
		t.Errorf("source.disable events = %d", n)
	}
}

func TestDeclaredTechMergesThreeOrigins(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, tag := range []string{"postgresql", "nginx"} {
		if err := AddTech(ctx, s, tag); err != nil {
			t.Fatal(err)
		}
	}
	if err := AddTech(ctx, s, "nginx"); err != nil {
		t.Fatalf("adding a tag twice: %v", err)
	}
	if err := AddTech(ctx, s, "Nginx!"); !errors.Is(err, project.ErrInvalidTech) {
		t.Errorf("invalid tag: %v", err)
	}
	if got, err := ListTech(ctx, s); err != nil || !reflect.DeepEqual(got, []string{"nginx", "postgresql"}) {
		t.Errorf("list = %v err %v", got, err)
	}
	p := project.Project{Name: "demo", Tech: []string{"symfony", "nginx"}, TechAuto: []string{"php", "symfony"}}
	if got := DeclaredTech(ctx, s, p); !reflect.DeepEqual(got, []string{"nginx", "php", "postgresql", "symfony"}) {
		t.Errorf("declared = %v", got)
	}
	if err := RemoveTech(ctx, s, "postgresql"); err != nil {
		t.Fatal(err)
	}
	if got, _ := ListTech(ctx, s); !reflect.DeepEqual(got, []string{"nginx"}) {
		t.Errorf("after remove = %v", got)
	}
}

func TestEnableWritesNoRuleWhenOneOfTwoFails(t *testing.T) {
	r, s := synced(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("sovereignty:\n  mode: strict_local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The second host is not a bare host name: its rule fails validation.
	if _, err := r.Upsert(ctx, Entry{Key: "feed.two", Name: "two", Kind: KindFeed, Origin: OriginUser,
		Hosts: []string{"a.example.org", "b.example.org/x"}, Purpose: policy.PurposeFeed}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d := testDeps(t, r, s, path)
	if _, _, err := Enable(ctx, d, "feed.two", true); err == nil {
		t.Fatal("expected the invalid rule to fail")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("a rule stayed in the policy file:\n%s", after)
	}
	if get(t, r, "feed.two").Enabled || countAudit(t, s, "source.consent") != 0 {
		t.Error("a failed consent changed the entry or the audit")
	}
}
