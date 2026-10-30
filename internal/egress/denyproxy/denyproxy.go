// Package denyproxy is the HTTP proxy Michel hands to a tool it runs (Trivy,
// Semgrep): it refuses every request, CONNECT included, and records each one
// as a denied egress attempt. It fences the tools that honour the proxy
// variables; a tool that ignores them is not stopped by it.
package denyproxy

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/egress"
)

// Reason is the reason of every attempt the proxy records.
const Reason = "plugin subprocess"

// maxRecorded caps the attempts recorded by one proxy, so that a tool that
// retries in a loop cannot flood the audit log; later ones are still refused.
const maxRecorded = 200

// Listen starts a proxy on 127.0.0.1 (a free port) that answers 403 to every
// request and refuses every CONNECT, recording each as an egress.Attempt with
// purpose, Allowed false and Reason. close stops it; it may be called twice.
func Listen(sink egress.Sink, purpose string) (addr string, close func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	var mu sync.Mutex
	recorded := 0
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    16 << 10,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			record := recorded < maxRecorded
			recorded++
			mu.Unlock()
			if record {
				_ = sink.Record(egress.Attempt{Host: hostOf(r), Purpose: purpose, Allowed: false, At: time.Now().UTC(), Reason: Reason})
			}
			w.Header().Set("Connection", "close")
			http.Error(w, "Michel refuses network access to the tools it runs", http.StatusForbidden)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	var once sync.Once
	return ln.Addr().String(), func() { once.Do(func() { _ = srv.Close() }) }, nil
}

// hostOf is the host a proxied request aims at, without its port, lower
// case and kept to the characters of a host name.
func hostOf(r *http.Request) string {
	h := r.Host
	if r.Method != http.MethodConnect && r.URL != nil && r.URL.Host != "" {
		h = r.URL.Host
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.ToLower(strings.Trim(h, "[]"))
	h = strings.Map(func(c rune) rune {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == ':' || c == '_' {
			return c
		}
		return -1
	}, h)
	if len(h) > 253 {
		h = h[:253]
	}
	if h == "" {
		return "unknown"
	}
	return h
}
