// Package allowproxy is the HTTPS proxy Michel hands to the subprocesses of a
// fix (git, composer, npm, Claude Code) through HTTPS_PROXY and HTTP_PROXY.
// It opens a CONNECT tunnel to host:443 only when the egress gateway allows
// that host for the proxy's purpose (fix.install, agent.claude), and every
// attempt is recorded: the allowlist check and the Attempt are the gateway's
// (Gateway.DialContext); what the proxy refuses by itself (plain HTTP, a port
// other than 443, a malformed target) is recorded with Gateway.RecordRefused.
// A tool that ignores the proxy variables is not stopped by it.
package allowproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kvarot/michel/internal/egress"
)

// DialAddrForTest, when set, gives the address the tunnel to host really
// dials (a local TLS test server standing for host:443). Its host must be
// host itself: only the port may change, so the allowlist check and the
// Attempt stay on the host the client asked for. Tests only: production code
// never sets it, and it is nil in production.
var DialAddrForTest func(host string) string

// proxyUser is the user name in the proxy URL.
const proxyUser = "michel"

const (
	// maxTunnels caps the connections a proxy serves at once; one more is
	// answered 503.
	maxTunnels = 64
	// headerTimeout bounds the wait for the CONNECT request.
	headerTimeout = 10 * time.Second
	// maxHeaderBytes caps the CONNECT request line and headers.
	maxHeaderBytes = 16 << 10
	// maxRecorded caps the refusals the proxy records by itself, so that a
	// tool retrying in a loop cannot flood the audit log; later ones are
	// still refused. Gateway decisions are recorded by the gateway.
	maxRecorded = 200
	// lingerTimeout bounds the draining of a refused connection before it is
	// closed, so that the client reads the answer instead of a reset.
	lingerTimeout = time.Second
)

// idleTimeout closes a tunnel in which no byte moved either way for that
// long. A variable so that tests can shorten it.
var idleTimeout = 5 * time.Minute

type proxy struct {
	gw      *egress.Gateway
	purpose string
	ln      net.Listener
	ctx     context.Context
	cancel  context.CancelFunc
	slots   chan struct{}
	wg      sync.WaitGroup
	// cred is the base64 Basic credential every request must carry.
	cred string

	mu       sync.Mutex
	closed   bool
	conns    map[net.Conn]struct{}
	recorded int
}

// Listen starts a proxy on 127.0.0.1 (a free port) for purpose and returns
// its URL, http://michel:<token>@127.0.0.1:<port>, with a random token of
// its own: every request must carry Proxy-Authorization: Basic with these
// credentials, or it is answered 407 (so that another local process cannot
// borrow the proxy's allowlist). A CONNECT to host:443 is tunnelled through
// gw.DialContext(ctx, purpose, "tcp", "host:443"); a refusal is answered
// 403 Forbidden and the connection closed. Plain HTTP requests are refused
// (HTTPS only). close stops the listener, closes every connection and
// tunnel, and returns once all the proxy's goroutines have ended; it may be
// called twice.
func Listen(gw *egress.Gateway, purpose string) (proxyURL string, close func(), err error) {
	if gw == nil {
		return "", nil, errors.New("allowproxy: nil gateway")
	}
	if purpose == "" {
		return "", nil, errors.New("allowproxy: empty purpose")
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", nil, fmt.Errorf("allowproxy: token: %w", err)
	}
	token := hex.EncodeToString(raw[:])
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &proxy{
		gw: gw, purpose: purpose, ln: ln, ctx: ctx, cancel: cancel,
		slots: make(chan struct{}, maxTunnels),
		conns: map[net.Conn]struct{}{},
		cred:  base64.StdEncoding.EncodeToString([]byte(proxyUser + ":" + token)),
	}
	p.wg.Add(1)
	go p.serve()
	var once sync.Once
	return "http://" + proxyUser + ":" + token + "@" + ln.Addr().String(), func() { once.Do(p.close) }, nil
}

func (p *proxy) close() {
	p.mu.Lock()
	p.closed = true
	for c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
	_ = p.ln.Close()
	p.cancel()
	p.wg.Wait()
}

// track registers c so that close can cut it; false when the proxy is closed
// (c is then closed).
func (p *proxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = c.Close()
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *proxy) untrack(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
	_ = c.Close()
}

func (p *proxy) serve() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// A transient accept failure (descriptors exhausted): back off.
			select {
			case <-p.ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		select {
		case p.slots <- struct{}{}:
		default:
			p.record("", "too many connections")
			_ = c.SetWriteDeadline(time.Now().Add(lingerTimeout))
			_, _ = io.WriteString(c, answer(503, "Service Unavailable", ""))
			_ = c.Close()
			continue
		}
		if !p.track(c) {
			<-p.slots
			continue
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer func() { <-p.slots }()
			defer p.untrack(c)
			p.handle(c)
		}()
	}
}

// answer is a complete response without a body; extra is a header line
// (with its CRLF) or empty. It never echoes anything the client sent.
func answer(code int, text, extra string) string {
	return fmt.Sprintf("HTTP/1.1 %d %s\r\n%sConnection: close\r\nContent-Length: 0\r\n\r\n", code, text, extra)
}

// refuse answers code to c, waits briefly for the client to stop sending so
// that it reads the answer rather than a reset, and leaves c to be closed.
func refuse(c net.Conn, code int, text string) { refuseWith(c, code, text, "") }

// refuseWith is refuse with an extra header line.
func refuseWith(c net.Conn, code int, text, extra string) {
	_ = c.SetWriteDeadline(time.Now().Add(lingerTimeout))
	if _, err := io.WriteString(c, answer(code, text, extra)); err != nil {
		return
	}
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_ = c.SetReadDeadline(time.Now().Add(lingerTimeout))
	_, _ = io.Copy(io.Discard, io.LimitReader(c, maxHeaderBytes))
}

// record records a refusal the proxy decided by itself. reason is always one
// of the proxy's fixed strings; host is sanitized and bounded. The last
// record under maxRecorded says that further refusals are not recorded.
func (p *proxy) record(host, reason string) {
	p.mu.Lock()
	n := p.recorded
	p.recorded++
	p.mu.Unlock()
	switch {
	case n < maxRecorded-1:
		_ = p.gw.RecordRefused(sanitizeHost(host), p.purpose, reason)
	case n == maxRecorded-1:
		_ = p.gw.RecordRefused(sanitizeHost(host), p.purpose, "further refusals not recorded")
	}
}

// refuseRecorded refuses c with 403 and records the refusal for host.
func (p *proxy) refuseRecorded(c net.Conn, host, reason string) {
	p.record(host, reason)
	refuse(c, 403, "Forbidden")
}

// authorized checks the Proxy-Authorization header values, the credential
// in constant time; the empty reason means they carry the proxy's own.
func (p *proxy) authorized(values []string) string {
	if len(values) == 0 {
		return "proxy authentication missing"
	}
	if len(values) > 1 {
		return "proxy authentication refused"
	}
	scheme, cred, _ := strings.Cut(strings.TrimSpace(values[0]), " ")
	ok := subtle.ConstantTimeCompare([]byte(strings.TrimSpace(cred)), []byte(p.cred)) == 1
	if !strings.EqualFold(scheme, "Basic") || !ok {
		return "proxy authentication refused"
	}
	return ""
}

// requestHost is the host a request aims at, for the audit only (it is
// sanitized and bounded when recorded).
func requestHost(target string, hosts []string) string {
	host := target
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if host == "" && len(hosts) > 0 {
		host = hosts[0]
	}
	return host
}

func (p *proxy) handle(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(headerTimeout))
	br := bufio.NewReader(&io.LimitedReader{R: c, N: maxHeaderBytes})
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		return
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		refuse(c, 400, "Bad Request")
		return
	}
	method, target, proto, ok := splitRequestLine(line)
	if !ok {
		refuse(c, 400, "Bad Request")
		return
	}
	hosts := hdr["Host"]
	if why := p.authorized(hdr["Proxy-Authorization"]); why != "" {
		p.record(requestHost(target, hosts), why)
		refuseWith(c, 407, "Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"michel\"\r\n")
		return
	}
	if method != "CONNECT" {
		p.refuseRecorded(c, requestHost(target, hosts), "plain HTTP refused: HTTPS only")
		return
	}
	if proto != "HTTP/1.1" && proto != "HTTP/1.0" {
		refuse(c, 400, "Bad Request")
		return
	}
	host, reason := checkTarget(target)
	if reason == "" {
		switch {
		case len(hosts) > 1 || len(hosts) == 1 && !sameAuthority(hosts[0], target):
			reason = "host header differs from the CONNECT target"
		case hdr.Get("Content-Length") != "" && hdr.Get("Content-Length") != "0" || len(hdr["Transfer-Encoding"]) > 0:
			reason = "request body refused before CONNECT"
		case br.Buffered() > 0:
			reason = "data sent before the tunnel was established"
		}
	}
	if reason == "" && net.ParseIP(host) != nil {
		reason = p.checkIP(host)
	}
	if reason != "" {
		p.refuseRecorded(c, requestHost(target, nil), reason)
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	addr := net.JoinHostPort(host, "443")
	if DialAddrForTest != nil {
		addr = DialAddrForTest(host)
		if h, _, err := net.SplitHostPort(addr); err != nil || h != host {
			refuse(c, 502, "Bad Gateway")
			return
		}
	}
	// The gateway checks host against the allowlist and records the Attempt.
	up, err := p.gw.DialContext(p.ctx, p.purpose, "tcp", addr)
	if err != nil {
		if errors.Is(err, egress.ErrEgressDenied) {
			refuse(c, 403, "Forbidden")
		} else {
			refuse(c, 502, "Bad Gateway")
		}
		return
	}
	if !p.track(up) {
		return
	}
	defer p.untrack(up)
	_ = c.SetWriteDeadline(time.Now().Add(headerTimeout))
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	_ = c.SetWriteDeadline(time.Time{})
	pipe(c, up)
}

// checkIP accepts an IP literal target only when a policy rule names that
// exact address for the purpose (not a wildcard, not the loopback grant of
// local.* purposes). The empty reason means accepted.
func (p *proxy) checkIP(ip string) string {
	if r, ok := p.gw.MatchRule(ip, p.purpose); ok && strings.ToLower(r.Host) == ip {
		return ""
	}
	if ok, _ := p.gw.Allowed(ip, p.purpose); ok {
		return "IP address target without a rule naming it"
	}
	return "" // the gateway refuses and records it
}

// sameAuthority reports whether a Host header names the (already validated,
// lower case) CONNECT target, with or without its port (undici's ProxyAgent
// sends the host alone), in any case.
func sameAuthority(hostHeader, target string) bool {
	h := strings.ToLower(hostHeader)
	return h == target || h+":443" == target
}

func splitRequestLine(line string) (method, target, proto string, ok bool) {
	parts := strings.Split(line, " ")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// checkTarget validates a CONNECT target: host:443, the host a lower case
// DNS name or a canonical IP literal, no user info. It returns the host and
// the empty reason, or the refusal reason.
func checkTarget(target string) (string, string) {
	if strings.Contains(target, "@") {
		return "", "user info in the CONNECT target"
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", "CONNECT target is not host:port"
	}
	if port != "443" {
		return "", "port refused: only 443 is tunnelled"
	}
	if host != strings.ToLower(host) {
		return "", "CONNECT target not in lower case"
	}
	if strings.HasPrefix(target, "[") {
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() != nil || ip.String() != host {
			return "", "invalid IPv6 target"
		}
		return host, ""
	}
	if isIPv4(host) {
		if ip := net.ParseIP(host); ip == nil || ip.String() != host {
			return "", "invalid IPv4 target"
		}
		return host, ""
	}
	if !validHostname(host) {
		return "", "invalid host name"
	}
	return host, ""
}

func isIPv4(host string) bool {
	return host != "" && strings.Trim(host, "0123456789.") == ""
}

// validHostname is a lower case DNS name: labels of 1 to 63 letters, digits
// and hyphens, not starting or ending with a hyphen, no trailing dot, at
// most 253 characters, and a last label that is not all digits (it would
// read as an address).
func validHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

// sanitizeHost keeps an audited host to the characters of a host name, lower
// case and at most 253 characters, without user info or port.
func sanitizeHost(h string) string {
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
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

// pipe copies both ways between the client and the upstream until both
// sides are done, an error occurs, or nothing moved for idleTimeout.
func pipe(c, up net.Conn) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyIdle(up, c, &last) }()
	go func() { defer wg.Done(); copyIdle(c, up, &last) }()
	wg.Wait()
}

// copyIdle copies src to dst. On end of input it half-closes dst; on any
// error, or after idleTimeout without traffic either way, it closes both.
func copyIdle(dst, src net.Conn, last *atomic.Int64) {
	buf := make([]byte, 32<<10)
	for {
		_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			last.Store(time.Now().UnixNano())
			_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				break
			}
		}
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() && time.Since(time.Unix(0, last.Load())) < idleTimeout {
			continue // the other direction is active
		}
		if errors.Is(err, io.EOF) {
			if cw, ok := dst.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
				return
			}
		}
		break
	}
	_ = src.Close()
	_ = dst.Close()
}
