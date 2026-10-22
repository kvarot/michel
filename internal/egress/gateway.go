// Package egress is the single place where Michel builds HTTP clients.
// Every outbound request is checked against the policy allowlist and
// recorded as an Attempt before it may touch the network.
package egress

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/policy"
)

const maxAttempts = 1000

// Attempt describes one egress decision. It deliberately holds no URL
// path, query, header or body.
type Attempt struct {
	Host    string
	Purpose string
	Allowed bool
	At      time.Time
	Reason  string
}

// Sink receives every Attempt (implemented by the audit logger).
type Sink interface{ Record(Attempt) }

type nopSink struct{}

func (nopSink) Record(Attempt) {}

// Gateway decides and records outbound requests.
type Gateway struct {
	mode  policy.Mode
	rules []policy.AllowRule
	sink  Sink
	inner *http.Transport

	mu       sync.Mutex
	attempts []Attempt
}

// New builds a Gateway. A nil sink is replaced by a no-op sink.
func New(p policy.Policy, sink Sink) *Gateway {
	if sink == nil {
		sink = nopSink{}
	}
	inner := http.DefaultTransport.(*http.Transport).Clone()
	inner.Proxy = nil // ignore HTTP_PROXY and friends
	inner.ResponseHeaderTimeout = 30 * time.Second
	inner.TLSHandshakeTimeout = 15 * time.Second
	inner.IdleConnTimeout = 90 * time.Second
	return &Gateway{
		mode:  p.Sovereignty.Mode,
		rules: append([]policy.AllowRule(nil), p.Sovereignty.Network.Allow...),
		sink:  sink,
		inner: inner,
	}
}

// Mode returns the sovereignty mode of the policy in force.
func (g *Gateway) Mode() policy.Mode { return g.mode }

// Client returns an HTTP client bound to purpose. It panics if purpose is
// empty: an unlabelled request is a programming error. The client has no
// overall Timeout (it would cut large downloads); the transport bounds
// connection, TLS and response-header waits, and callers bound the whole
// request with a context deadline.
func (g *Gateway) Client(purpose string) *http.Client {
	if purpose == "" {
		panic("egress: Client requires a non-empty purpose")
	}
	return &http.Client{
		Transport: checkedTransport{g: g, purpose: purpose},
	}
}

// Allowed reports whether host may be contacted for purpose, with the reason.
// It does not record an Attempt.
func (g *Gateway) Allowed(host, purpose string) (bool, string) {
	host = strings.ToLower(host)
	if isLoopback(host) && strings.HasPrefix(purpose, "local.") {
		return true, "loopback allowed for local purpose"
	}
	hostSeen := false
	for _, r := range g.rules {
		if !hostMatches(strings.ToLower(r.Host), host) {
			continue
		}
		hostSeen = true
		if r.Purpose == purpose {
			return true, fmt.Sprintf("allowed by rule %s/%s", r.Host, r.Purpose)
		}
	}
	if hostSeen {
		return false, "purpose mismatch"
	}
	return false, "no rule for host"
}

// Attempts returns a copy of the most recent attempts (at most 1000).
func (g *Gateway) Attempts() []Attempt {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]Attempt(nil), g.attempts...)
}

func (g *Gateway) record(a Attempt) {
	g.mu.Lock()
	if len(g.attempts) >= maxAttempts {
		g.attempts = append(g.attempts[:0], g.attempts[1:]...)
	}
	g.attempts = append(g.attempts, a)
	g.mu.Unlock()
	g.sink.Record(a)
}

func hostMatches(rule, host string) bool {
	if suffix, ok := strings.CutPrefix(rule, "*."); ok {
		return strings.HasSuffix(host, "."+suffix) && len(host) > len(suffix)+1
	}
	return rule == host
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 127
	}
	return ip.Equal(net.IPv6loopback)
}
