package denyproxy

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/egress"
)

type sink struct {
	mu  sync.Mutex
	got []egress.Attempt
}

func (s *sink) Record(a egress.Attempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, a)
	return nil
}

func TestDenyProxyRefusesAndRecords(t *testing.T) {
	s := &sink{}
	addr, closeFn, err := Listen(s, "plugin.trivy")
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	proxy, _ := url.Parse("http://" + addr)
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}

	resp, err := c.Get("http://example.com/data")
	if err != nil {
		t.Fatalf("GET through the proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("GET status = %d, want 403", resp.StatusCode)
	}
	if resp, err := c.Get("https://ghcr.io/v2/"); err == nil {
		resp.Body.Close()
		t.Error("CONNECT went through")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.got) != 2 {
		t.Fatalf("%d attempts recorded, want 2: %+v", len(s.got), s.got)
	}
	for i, host := range []string{"example.com", "ghcr.io"} {
		a := s.got[i]
		if a.Host != host || a.Allowed || a.Purpose != "plugin.trivy" || a.Reason != "plugin subprocess" || a.At.IsZero() {
			t.Errorf("attempt %d = %+v", i, a)
		}
	}
	closeFn() // idempotent
}
