package readers

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sourceupdate"
)

// witness records every egress attempt and hands it on to the audit sink.
type witness struct {
	mu       sync.Mutex
	attempts []egress.Attempt
	next     egress.Sink
}

func (w *witness) Record(a egress.Attempt) error {
	w.mu.Lock()
	w.attempts = append(w.attempts, a)
	w.mu.Unlock()
	return w.next.Record(a)
}

func (w *witness) take() []egress.Attempt {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.attempts
	w.attempts = nil
	return out
}

// offline answers every request the gateway lets through with a 404,
// without the network: each reader still makes its first request to the
// real host of its URL.
type offline struct{}

func (offline) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		r.Body.Close()
	}
	return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Header: http.Header{},
		Body: io.NopCloser(strings.NewReader("")), Request: r, ProtoMajor: 1, ProtoMinor: 1}, nil
}

// TestUpdateContactsOnlyTheCatalogHosts is the § 9 test: every catalog entry
// with a reader is enabled and read, one at a time, by source update; the
// readers keep their real URLs (the gateway's transport is replaced, not the
// readers' base URLs) and every attempt is witnessed. Each attempt must be
// to a host of that entry, for its purpose, and leave an egress.attempt
// audit event. A reader whose URL host is not in its catalog entry fails
// here.
func TestUpdateContactsOnlyTheCatalogHosts(t *testing.T) {
	ctx := context.Background()
	cat, _, err := source.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	var rules []policy.AllowRule
	for _, c := range cat {
		for _, h := range c.Hosts {
			rules = append(rules, policy.AllowRule{Host: h, Purpose: c.Purpose})
		}
	}
	d := deps(t)
	w := &witness{next: d.Audit.EgressSink()}
	var p policy.Policy
	p.Sovereignty.Network.Allow = rules
	d.Gateway = egress.New(p, w)
	d.Gateway.SetTransportForTest(offline{})
	d.Budget = &sourceupdate.Budget{Remaining: 10000}
	// One finding without a severity, so the on-demand sources ask about
	// its CVE.
	proj, err := project.NewRepo(d.Store).Add(ctx, project.Project{Name: "demo", Path: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.DB().Exec(`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, aliases,
		severity_label, installed_version, fixed_versions, status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, status_changed_at)
		VALUES ('f1', ?, 'composer.lock', 'Packagist', 'acme/lib', 'GHSA-f1', '["CVE-2024-0001"]', 'unknown', '1.0.0', '[]', 'new',
		's1', 's1', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')`, proj.ID); err != nil {
		t.Fatal(err)
	}
	egressEvents := func() int {
		var n int
		if err := d.Store.DB().QueryRow(`SELECT COUNT(*) FROM audit_event WHERE action = 'egress.attempt'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	read := 0
	for _, c := range cat {
		if err := d.Repo.SetEnabled(ctx, c.Key, true); err != nil {
			t.Fatal(err)
		}
		before := egressEvents()
		rep, _ := sourceupdate.Run(ctx, d, []string{c.Key}, "")
		got := w.take()
		if rep.SkipReasons[c.Key] == sourceupdate.SkipNoReader || !slices.Contains(rep.Order, c.Key) {
			if len(got) != 0 {
				t.Errorf("%s is not read but contacted %+v", c.Key, got)
			}
			continue
		}
		hosts, purpose := c.Hosts, c.Purpose
		if c.Kind == source.KindPlugin && len(hosts) == 0 {
			// A plugin has no host of its own: its repository status uses
			// the api.github.com rule a skill or MCP consent gave (spec § 6).
			hosts, purpose = []string{"api.github.com"}, policy.PurposeRepo
		}
		if len(hosts) > 0 && len(got) == 0 {
			t.Errorf("%s was read (%+v) without any request: the test proves nothing for it", c.Key, rep)
		}
		for _, a := range got {
			if !slices.Contains(hosts, a.Host) || a.Purpose != purpose || !a.Allowed {
				t.Errorf("%s contacted %s for %s (allowed %v), its catalog entry declares %v for %s", c.Key, a.Host, a.Purpose, a.Allowed, hosts, purpose)
			}
		}
		if n := egressEvents() - before; n != len(got) {
			t.Errorf("%s: %d attempts but %d egress.attempt events", c.Key, len(got), n)
		}
		read++
	}
	t.Logf("%d entries read", read)
	if read < 50 {
		t.Errorf("only %d entries were read", read)
	}
}
