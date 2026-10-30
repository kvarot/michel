package digest

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	src "github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sourceupdate"
	_ "github.com/kvarot/michel/internal/sourceupdate/readers"
)

// kevOnly answers the KEV list for www.cisa.gov, without the network.
type kevOnly struct{ body string }

func (k kevOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	status, body := http.StatusNotFound, ""
	if r.URL.Hostname() == "www.cisa.gov" {
		status, body = http.StatusOK, k.body
	}
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: http.Header{},
		Body: io.NopCloser(strings.NewReader(body)), Request: r, ProtoMajor: 1, ProtoMinor: 1}, nil
}

// TestSourceUpdateKEVSupersessionIsToReview: a decision superseded by
// enrich.Apply during source update (no scan) shows in the digest's
// decisions to review, with the kev_changed reason.
func TestSourceUpdateKEVSupersessionIsToReview(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	old := now.Add(-10 * 24 * time.Hour)
	id := f.seed(finding{pkg: "acme/lib", osv: "CVE-2024-0001", severity: "high", status: "decided", firstSeen: old})
	f.decide(decision{finding: id, action: "defer", due: now.Add(20 * 24 * time.Hour)})

	repo := src.NewRepo(f.st)
	if _, _, err := src.Sync(ctx, repo); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetEnabled(ctx, "enrich.kev", true); err != nil {
		t.Fatal(err)
	}
	var p policy.Policy
	p.Sovereignty.Network.Allow = []policy.AllowRule{{Host: "www.cisa.gov", Purpose: policy.PurposeEnrich}}
	at := func() time.Time { return now.Add(-time.Hour) }
	log := audit.NewLogger(f.st, at)
	gw := egress.New(p, log.EgressSink())
	gw.SetTransportForTest(kevOnly{body: `{"catalogVersion":"2026.10.22","vulnerabilities":[{"cveID":"CVE-2024-0001","dateAdded":"2026-10-22"}]}`})
	rep, err := sourceupdate.Run(ctx, sourceupdate.Deps{Store: f.st, Repo: repo, Audit: log, Gateway: gw, OSVRoot: t.TempDir(), Now: at,
		Budget: &sourceupdate.Budget{Remaining: 50}}, []string{"enrich.kev"}, "")
	if err != nil || rep.Apply.Superseded != 1 {
		t.Fatalf("source update: %v %+v", err, rep)
	}

	pd := projectNamed(t, f.compute(i18n.FR, Options{}), "demo")
	if len(pd.Superseded) != 1 || pd.Superseded[0].FindingID != id || pd.Superseded[0].Reason != "kev_changed" || pd.Superseded[0].PreviousAction != "defer" {
		t.Fatalf("superseded = %+v", pd.Superseded)
	}
	txt, err := RenderText(f.compute(i18n.FR, Options{}))
	if err != nil {
		t.Fatal(err)
	}
	head := strings.Index(txt, "Décisions à revoir")
	if head < 0 || !strings.Contains(txt[head:], "acme/lib CVE-2024-0001") ||
		!strings.Contains(txt[head:], i18n.T(i18n.FR, "digest.reason.kev_changed")) {
		t.Errorf("the decision to review is not in the digest:\n%s", txt)
	}
}
