// Package egress is the single place where Michel builds HTTP clients.
// Every outbound request is checked against the policy allowlist and
// recorded as an Attempt before it may touch the network.
package egress

import (
	"context"
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

// Sink receives every Attempt (implemented by the audit logger). A non-nil
// error means the attempt left no durable trace: the gateway then refuses
// the request even when the policy allows it (fail closed).
type Sink interface{ Record(Attempt) error }

type nopSink struct{}

func (nopSink) Record(Attempt) error { return nil }

// Gateway decides and records outbound requests.
type Gateway struct {
	mode  policy.Mode
	sink  Sink
	inner *http.Transport
	// next carries the allowed requests: inner, or what a test set.
	next http.RoundTripper

	// mu guards rules (replaced by SetRules) and attempts.
	mu       sync.Mutex
	rules    []policy.AllowRule
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
		next:  inner,
	}
}

// SetTransportForTest makes the requests the gateway allows go through rt
// instead of the network. The allowlist check and the Attempt are unchanged,
// so a test sees the real hosts the readers ask for. Call it before the
// gateway's first request. Tests only.
func (g *Gateway) SetTransportForTest(rt http.RoundTripper) { g.next = rt }

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

// SetRules replaces the allowlist, so a rule written after the gateway was
// built (michel source enable) takes effect without a restart. The mode is
// unchanged.
func (g *Gateway) SetRules(rules []policy.AllowRule) {
	rules = append([]policy.AllowRule(nil), rules...)
	g.mu.Lock()
	g.rules = rules
	g.mu.Unlock()
}

// Allowed reports whether host may be contacted for purpose, with the reason.
// It does not record an Attempt.
func (g *Gateway) Allowed(host, purpose string) (bool, string) {
	host = strings.ToLower(host)
	if isLoopback(host) && strings.HasPrefix(purpose, "local.") {
		return true, "loopback allowed for local purpose"
	}
	g.mu.Lock()
	rules := g.rules // SetRules never mutates a published slice
	g.mu.Unlock()
	hostSeen := false
	for _, r := range rules {
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

// record keeps a in memory and hands it to the sink, returning the sink error.
func (g *Gateway) record(a Attempt) error {
	g.mu.Lock()
	if len(g.attempts) >= maxAttempts {
		g.attempts = append(g.attempts[:0], g.attempts[1:]...)
	}
	g.attempts = append(g.attempts, a)
	g.mu.Unlock()
	return g.sink.Record(a)
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

// dialTimeout bounds the TCP connection set-up of DialContext.
const dialTimeout = 15 * time.Second

// DialContext opens a TCP connection (network tcp, tcp4 or tcp6; anything
// else is refused without an Attempt) to addr (host:port) for purpose, after
// the same allowlist check and audit record as HTTP. It is the only way for
// non-HTTP protocols (SMTP) to reach the network. It panics if purpose is
// empty, like Client.
func (g *Gateway) DialContext(ctx context.Context, purpose, network, addr string) (net.Conn, error) {
	if purpose == "" {
		panic("egress: DialContext requires a non-empty purpose")
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("%w: purpose %s: network %q refused: only tcp, tcp4 and tcp6 may be dialed", ErrEgressDenied, purpose, network)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: purpose %s: bad address: %v", ErrEgressDenied, purpose, err)
	}
	ok, reason := g.Allowed(host, purpose)
	sinkErr := g.record(Attempt{Host: host, Purpose: purpose, Allowed: ok, At: time.Now(), Reason: reason})
	if ok && sinkErr != nil {
		// No audit trace, no connection (fail closed), as for HTTP.
		ok, reason = false, "audit unavailable: "+sinkErr.Error()
	}
	if !ok {
		return nil, fmt.Errorf("%w: host %s purpose %s: %s", ErrEgressDenied, host, purpose, reason)
	}
	d := net.Dialer{Timeout: dialTimeout}
	return d.DialContext(ctx, network, addr)
}
