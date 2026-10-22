package egress_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
)

func pol(rules ...policy.AllowRule) policy.Policy {
	p := policy.Defaults()
	p.Sovereignty.Network.Allow = rules
	return p
}

func server(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestDeniedHostReturnsErrEgressDenied(t *testing.T) {
	s := server(t)
	g := egress.New(pol(), nil)
	resp, err := g.Client("osv.db").Get(s.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected error")
	}
	if !errors.Is(err, egress.ErrEgressDenied) {
		t.Fatalf("want ErrEgressDenied, got %v", err)
	}
	if !strings.Contains(err.Error(), "host 127.0.0.1 purpose osv.db: no rule for host") {
		t.Fatalf("unexpected message: %v", err)
	}
	a := g.Attempts()
	if len(a) != 1 || a[0].Allowed || a[0].Reason != "no rule for host" {
		t.Fatalf("bad attempts: %+v", a)
	}
}

func TestAllowedHostAndPurposePasses(t *testing.T) {
	s := server(t)
	g := egress.New(pol(policy.AllowRule{Host: "127.0.0.1", Purpose: "osv.db"}), nil)
	resp, err := g.Client("osv.db").Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	a := g.Attempts()
	if len(a) != 1 || !a[0].Allowed || a[0].Reason != "allowed by rule 127.0.0.1/osv.db" {
		t.Fatalf("bad attempts: %+v", a)
	}
}

func TestPurposeMismatchDenied(t *testing.T) {
	s := server(t)
	g := egress.New(pol(policy.AllowRule{Host: "127.0.0.1", Purpose: "osv.db"}), nil)
	if resp, err := g.Client("other").Get(s.URL); err == nil {
		resp.Body.Close()
		t.Fatal("expected denial")
	} else if !errors.Is(err, egress.ErrEgressDenied) {
		t.Fatal(err)
	}
	if r := g.Attempts()[0].Reason; r != "purpose mismatch" {
		t.Fatalf("reason %q", r)
	}
}

func TestWildcardSuffix(t *testing.T) {
	g := egress.New(pol(policy.AllowRule{Host: "*.googleapis.com", Purpose: "osv.db"}), nil)
	cases := []struct {
		host string
		want bool
	}{
		{"osv-vulnerabilities.storage.googleapis.com", true},
		{"a.googleapis.com", true},
		{"A.GoogleAPIs.com", true},
		{"googleapis.com", false},
		{"googleapis.com.evil.net", false},
		{"evilgoogleapis.com", false},
	}
	for _, c := range cases {
		if got, reason := g.Allowed(c.host, "osv.db"); got != c.want {
			t.Errorf("%s: got %v (%s), want %v", c.host, got, reason, c.want)
		}
	}
}

func TestLoopbackLocalPurposeAllowed(t *testing.T) {
	s := server(t)
	g := egress.New(pol(), nil)
	resp, err := g.Client("local.ollama").Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if r := g.Attempts()[0].Reason; r != "loopback allowed for local purpose" {
		t.Fatalf("reason %q", r)
	}
	for _, h := range []string{"localhost", "::1", "127.5.6.7"} {
		if ok, _ := g.Allowed(h, "local.x"); !ok {
			t.Errorf("%s should be allowed", h)
		}
		if ok, _ := g.Allowed(h, "osv.db"); ok {
			t.Errorf("%s non-local purpose should be denied", h)
		}
	}
}

type captureSink struct{ got []egress.Attempt }

func (c *captureSink) Record(a egress.Attempt) { c.got = append(c.got, a) }

func TestAttemptNeverContainsQueryOrHeaders(t *testing.T) {
	s := server(t)
	sink := &captureSink{}
	g := egress.New(pol(), sink)
	req, _ := http.NewRequest("GET", s.URL+"/secret/path?token=SEKRET", nil)
	req.Header.Set("Authorization", "Bearer SEKRET")
	if resp, err := g.Client("osv.db").Do(req); err == nil {
		resp.Body.Close()
	}
	if len(sink.got) != 1 {
		t.Fatalf("sink got %d", len(sink.got))
	}
	for _, a := range [][]egress.Attempt{sink.got, g.Attempts()} {
		if strings.Contains(strings.Join([]string{a[0].Host, a[0].Purpose, a[0].Reason}, "|"), "SEKRET") ||
			strings.Contains(a[0].Host+a[0].Reason, "secret") {
			t.Fatalf("leak: %+v", a[0])
		}
	}
	if sink.got[0].At.IsZero() {
		t.Fatal("At not set")
	}
}

func TestNilSinkAndModeAndEmptyPurpose(t *testing.T) {
	g := egress.New(pol(), nil)
	if g.Mode() != policy.Defaults().Sovereignty.Mode {
		t.Fatal("mode")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on empty purpose")
		}
	}()
	g.Client("")
}

func TestAttemptsCappedAndCopied(t *testing.T) {
	g := egress.New(pol(), nil)
	for i := 0; i < 1005; i++ {
		g.Allowed("x.example", "p") // Allowed must not record
	}
	if len(g.Attempts()) != 0 {
		t.Fatal("Allowed must not record")
	}
	s := server(t)
	c := g.Client("p")
	for i := 0; i < 1005; i++ {
		if resp, err := c.Get(s.URL); err == nil {
			resp.Body.Close()
		}
	}
	a := g.Attempts()
	if len(a) != 1000 {
		t.Fatalf("len %d", len(a))
	}
	a[0].Host = "mutated"
	if g.Attempts()[0].Host == "mutated" {
		t.Fatal("not a copy")
	}
}

func TestRedirectToDisallowedHostDenied(t *testing.T) {
	b := server(t)
	bURL := strings.Replace(b.URL, "127.0.0.1", "localhost", 1)
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, bURL, http.StatusFound)
	}))
	t.Cleanup(a.Close)
	g := egress.New(pol(policy.AllowRule{Host: "127.0.0.1", Purpose: "x"}), nil)
	resp, err := g.Client("x").Get(a.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected redirect to be denied")
	}
	if !errors.Is(err, egress.ErrEgressDenied) {
		t.Fatalf("want ErrEgressDenied, got %v", err)
	}
	at := g.Attempts()
	if len(at) != 2 || !at[0].Allowed || at[1].Allowed || at[1].Host != "localhost" {
		t.Fatalf("bad attempts: %+v", at)
	}
}

func TestAttemptNeverLeaksOnAllowedPath(t *testing.T) {
	s := server(t)
	sink := &captureSink{}
	g := egress.New(pol(policy.AllowRule{Host: "127.0.0.1", Purpose: "osv.db"}), sink)
	req, _ := http.NewRequest("GET", s.URL+"/secret/path?token=SEKRET", nil)
	req.Header.Set("Authorization", "Bearer SEKRET")
	resp, err := g.Client("osv.db").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(sink.got) != 1 {
		t.Fatalf("sink got %d", len(sink.got))
	}
	for _, a := range append(append([]egress.Attempt{}, sink.got...), g.Attempts()...) {
		if !a.Allowed {
			t.Fatalf("expected allowed: %+v", a)
		}
		all := strings.ToLower(a.Host + "|" + a.Purpose + "|" + a.Reason)
		for _, bad := range []string{"sekret", "secret", "token", "bearer", "/path"} {
			if strings.Contains(all, bad) {
				t.Fatalf("leak %q in %+v", bad, a)
			}
		}
	}
}
