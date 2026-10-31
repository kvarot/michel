package allowproxy

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
)

func gateway(rules ...policy.AllowRule) *egress.Gateway {
	p := policy.Defaults()
	p.Sovereignty.Network.Allow = rules
	return egress.New(p, nil)
}

// testProxy is a running proxy: its URL, host:port and the
// Proxy-Authorization line a client must send.
type testProxy struct {
	url, addr, auth string
}

func listen(t *testing.T, gw *egress.Gateway, purpose string) testProxy {
	t.Helper()
	raw, closeFn, err := Listen(gw, purpose)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeFn)
	return parseProxy(t, raw)
}

func parseProxy(t *testing.T, raw string) testProxy {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := u.User.Password()
	cred := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + pw))
	return testProxy{url: raw, addr: u.Host, auth: "Proxy-Authorization: Basic " + cred + "\r\n"}
}

// withAuth inserts the proxy credentials after the request line of raw.
func (p testProxy) withAuth(raw string) string {
	i := strings.Index(raw, "\r\n")
	return raw[:i+2] + p.auth + raw[i+2:]
}

// redirect points DialAddrForTest at target for the duration of the test.
func redirect(t *testing.T, target string) {
	t.Helper()
	DialAddrForTest = func(string) string { return target }
	t.Cleanup(func() { DialAddrForTest = nil })
}

// connect sends raw to the proxy and returns the response and the
// connection, positioned after the response headers.
func connect(t *testing.T, addr, raw string) (*http.Response, net.Conn) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("reading the proxy answer to %q: %v", raw, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
	}
	_ = c.SetDeadline(time.Time{})
	return resp, c
}

func TestListenReturnsProxyURLWithToken(t *testing.T) {
	raw, closeFn, err := Listen(gateway(), policy.PurposeAgentClaude)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	if !regexp.MustCompile(`^http://michel:[0-9a-f]{32}@127\.0\.0\.1:[0-9]+$`).MatchString(raw) {
		t.Fatalf("proxy URL = %q", raw)
	}
	other, closeOther, err := Listen(gateway(), policy.PurposeAgentClaude)
	if err != nil {
		t.Fatal(err)
	}
	defer closeOther()
	if strings.Split(other, "@")[0] == strings.Split(raw, "@")[0] {
		t.Fatal("two proxies share a token")
	}
}

func TestAllowProxyTunnelsAllowedHost(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from upstream")
	}))
	defer srv.Close()
	redirect(t, srv.Listener.Addr().String())
	gw := gateway(policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeAgentClaude})
	p := listen(t, gw, policy.PurposeAgentClaude)

	proxy, _ := url.Parse(p.url)
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyURL(proxy)
	c := &http.Client{Timeout: 5 * time.Second, Transport: tr}
	defer tr.CloseIdleConnections()
	resp, err := c.Get("https://127.0.0.1/v1/messages")
	if err != nil {
		t.Fatalf("GET through the proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "hello from upstream" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	a := gw.Attempts()
	if len(a) != 1 || !a[0].Allowed || a[0].Host != "127.0.0.1" || a[0].Purpose != policy.PurposeAgentClaude || a[0].At.IsZero() {
		t.Fatalf("attempts = %+v", a)
	}
}

func TestAllowProxyRequiresToken(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	redirect(t, up.Addr().String())
	gw := gateway(policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeFixInstall})
	p := listen(t, gw, policy.PurposeFixInstall)
	const req = "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"
	wrong := "CONNECT 127.0.0.1:443 HTTP/1.1\r\nProxy-Authorization: Basic " +
		base64.StdEncoding.EncodeToString([]byte("michel:00000000000000000000000000000000")) + "\r\n\r\n"
	for _, tc := range []struct{ raw, reason string }{
		{req, "proxy authentication missing"},
		{wrong, "proxy authentication refused"},
		{"CONNECT 127.0.0.1:443 HTTP/1.1\r\nProxy-Authorization: Bearer x\r\n\r\n", "proxy authentication refused"},
		{"CONNECT 127.0.0.1:443 HTTP/1.1\r\n" + p.auth + p.auth + "\r\n", "proxy authentication refused"},
		{"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", "proxy authentication missing"},
	} {
		n := len(gw.Attempts())
		resp, _ := connect(t, p.addr, tc.raw)
		if resp.StatusCode != http.StatusProxyAuthRequired || resp.Header.Get("Proxy-Authenticate") != `Basic realm="michel"` {
			t.Errorf("%q: status %d, Proxy-Authenticate %q", tc.raw, resp.StatusCode, resp.Header.Get("Proxy-Authenticate"))
		}
		a := gw.Attempts()
		if len(a) != n+1 || a[n].Allowed || a[n].Reason != tc.reason {
			t.Errorf("%q: attempts = %+v, want reason %q", tc.raw, a[n:], tc.reason)
		}
	}
	resp, _ := connect(t, p.addr, p.withAuth(req))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("with the token: status %d", resp.StatusCode)
	}
	if a := gw.Attempts(); !a[len(a)-1].Allowed {
		t.Fatalf("last attempt = %+v", a[len(a)-1])
	}
}

func TestAllowProxyRefusesUnknownHost(t *testing.T) {
	gw := gateway(policy.AllowRule{Host: "api.anthropic.com", Purpose: policy.PurposeAgentClaude})
	p := listen(t, gw, policy.PurposeAgentClaude)
	resp, _ := connect(t, p.addr, p.withAuth("CONNECT exfil.example.com:443 HTTP/1.1\r\nHost: exfil.example.com:443\r\n\r\n"))
	if resp.Status != "403 Forbidden" {
		t.Fatalf("status = %q, want 403 Forbidden", resp.Status)
	}
	a := gw.Attempts()
	if len(a) != 1 || a[0].Allowed || a[0].Host != "exfil.example.com" || a[0].Purpose != policy.PurposeAgentClaude || a[0].Reason != "no rule for host" {
		t.Fatalf("attempts = %+v", a)
	}
}

func TestAllowProxyRefusesWrongPurpose(t *testing.T) {
	gw := gateway(policy.AllowRule{Host: "repo.packagist.org", Purpose: policy.PurposeFixInstall})
	p := listen(t, gw, policy.PurposeAgentClaude)
	resp, _ := connect(t, p.addr, p.withAuth("CONNECT repo.packagist.org:443 HTTP/1.1\r\n\r\n"))
	if resp.Status != "403 Forbidden" {
		t.Fatalf("status = %q", resp.Status)
	}
	a := gw.Attempts()
	if len(a) != 1 || a[0].Allowed || a[0].Reason != "purpose mismatch" {
		t.Fatalf("attempts = %+v", a)
	}
}

// undici's ProxyAgent (Claude Code) sends the Host header without the port.
func TestAllowProxyAcceptsHostHeaderWithoutPort(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	// Only the loopback target is redirected; the other host is denied by the
	// gateway before any dial.
	DialAddrForTest = func(host string) string {
		if host == "127.0.0.1" {
			return up.Addr().String()
		}
		return net.JoinHostPort(host, "443")
	}
	t.Cleanup(func() { DialAddrForTest = nil })
	gw := gateway(policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeAgentClaude})
	p := listen(t, gw, policy.PurposeAgentClaude)
	for _, h := range []string{"127.0.0.1", "127.0.0.1:443"} {
		resp, _ := connect(t, p.addr, p.withAuth("CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: "+h+"\r\n\r\n"))
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Host %q: status %d", h, resp.StatusCode)
		}
	}
	// A DNS name with its Host header without port reaches the gateway.
	resp, _ := connect(t, p.addr, p.withAuth("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: API.Anthropic.com\r\n\r\n"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if a := gw.Attempts(); a[len(a)-1].Host != "api.anthropic.com" || a[len(a)-1].Reason != "no rule for host" {
		t.Fatalf("last attempt = %+v", a[len(a)-1])
	}
}

func TestAllowProxyRefusesPlainHTTP(t *testing.T) {
	gw := gateway(policy.AllowRule{Host: "example.com", Purpose: policy.PurposeFixInstall})
	p := listen(t, gw, policy.PurposeFixInstall)
	proxy, _ := url.Parse(p.url)
	tr := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer tr.CloseIdleConnections()
	c := &http.Client{Timeout: 5 * time.Second, Transport: tr}
	resp, err := c.Get("http://example.com/packages.json")
	if err != nil {
		t.Fatalf("GET through the proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	a := gw.Attempts()
	if len(a) != 1 || a[0].Allowed || a[0].Host != "example.com" || a[0].Purpose != policy.PurposeFixInstall || a[0].Reason != "plain HTTP refused: HTTPS only" {
		t.Fatalf("attempts = %+v", a)
	}
}

func TestAllowProxyRefusesMalformedTargets(t *testing.T) {
	gw := gateway(
		policy.AllowRule{Host: "api.anthropic.com", Purpose: "local.test"},
		policy.AllowRule{Host: "*.anthropic.com", Purpose: "local.test"},
	)
	p := listen(t, gw, "local.test")
	junkPort := "443/../" + strings.Repeat("x", 4000)
	cases := []struct{ raw, reason string }{
		{"CONNECT api.anthropic.com:80 HTTP/1.1\r\n\r\n", "port refused: only 443 is tunnelled"},
		{"CONNECT api.anthropic.com:8443 HTTP/1.1\r\n\r\n", "port refused: only 443 is tunnelled"},
		{"CONNECT api.anthropic.com:" + junkPort + " HTTP/1.1\r\n\r\n", "port refused: only 443 is tunnelled"},
		{"CONNECT api.anthropic.com HTTP/1.1\r\n\r\n", "CONNECT target is not host:port"},
		{"CONNECT API.anthropic.com:443 HTTP/1.1\r\n\r\n", "CONNECT target not in lower case"},
		{"CONNECT user@api.anthropic.com:443 HTTP/1.1\r\n\r\n", "user info in the CONNECT target"},
		{"CONNECT api.anthropic.com.:443 HTTP/1.1\r\n\r\n", "invalid host name"},
		{"CONNECT -x.anthropic.com:443 HTTP/1.1\r\n\r\n", "invalid host name"},
		{"CONNECT 1.2.3:443 HTTP/1.1\r\n\r\n", "invalid IPv4 target"},
		{"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n", "host header differs from the CONNECT target"},
		{"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: evil.example.com\r\n\r\n", "host header differs from the CONNECT target"},
		{"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:80\r\n\r\n", "host header differs from the CONNECT target"},
		{"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com\r\nHost: api.anthropic.com\r\n\r\n", "host header differs from the CONNECT target"},
		{"CONNECT api.anthropic.com:443 HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd", "request body refused before CONNECT"},
		{"CONNECT api.anthropic.com:443 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "request body refused before CONNECT"},
		{"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n\x16\x03\x01early", "data sent before the tunnel was established"},
		// Loopback is allowed for local.* purposes, but an IP literal needs
		// a rule naming that exact address.
		{"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n", "IP address target without a rule naming it"},
		{"CONNECT [::1]:443 HTTP/1.1\r\n\r\n", "IP address target without a rule naming it"},
	}
	for i, tc := range cases {
		resp, _ := connect(t, p.addr, p.withAuth(tc.raw))
		if resp.Status != "403 Forbidden" {
			t.Errorf("%.80q: status = %q, want 403 Forbidden", tc.raw, resp.Status)
		}
		a := gw.Attempts()
		if len(a) != i+1 {
			t.Fatalf("%.80q: %d attempts recorded, want %d", tc.raw, len(a), i+1)
		}
		if got := a[i]; got.Allowed || got.Purpose != "local.test" || got.Reason != tc.reason || len(got.Host) > 253 {
			t.Errorf("%.80q: attempt = %.300v, want reason %q", tc.raw, got, tc.reason)
		}
	}
}

func TestAllowProxyAnswersNoEcho(t *testing.T) {
	gw := gateway()
	p := listen(t, gw, policy.PurposeAgentClaude)
	for _, raw := range []string{
		"CONNECT x.example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic c2VjcmV0LXZhbHVl\r\n\r\n",
		p.withAuth("CONNECT x.example.com:443 HTTP/1.1\r\nX-Note: c2VjcmV0LXZhbHVl\r\n\r\n"),
	} {
		c, err := net.DialTimeout("tcp", p.addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(c, raw)
		all, _ := io.ReadAll(c)
		c.Close()
		if !strings.HasPrefix(string(all), "HTTP/1.1 40") || strings.Contains(string(all), "c2VjcmV0") {
			t.Fatalf("answer = %q", all)
		}
	}
}

func TestAllowProxyCapsConcurrentTunnels(t *testing.T) {
	gw := gateway()
	p := listen(t, gw, policy.PurposeAgentClaude)
	for i := 0; i < maxTunnels; i++ {
		c, err := net.DialTimeout("tcp", p.addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	c, err := net.DialTimeout("tcp", p.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("65th connection: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("65th connection status = %d, want 503", resp.StatusCode)
	}
	a := gw.Attempts()
	if len(a) != 1 || a[0].Allowed || a[0].Reason != "too many connections" || a[0].Host != "unknown" {
		t.Fatalf("attempts = %+v", a)
	}
}

func TestAllowProxyCapsRecordedRefusals(t *testing.T) {
	gw := gateway()
	p := listen(t, gw, policy.PurposeFixInstall)
	for i := 0; i < maxRecorded+5; i++ {
		c, err := net.DialTimeout("tcp", p.addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(c, p.withAuth("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		c.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
	}
	a := gw.Attempts()
	if len(a) != maxRecorded {
		t.Fatalf("%d attempts recorded, want %d", len(a), maxRecorded)
	}
	if a[maxRecorded-2].Reason != "plain HTTP refused: HTTPS only" {
		t.Errorf("attempt %d = %+v", maxRecorded-2, a[maxRecorded-2])
	}
	if last := a[maxRecorded-1]; last.Allowed || last.Reason != "further refusals not recorded" {
		t.Errorf("last attempt = %+v", last)
	}
}

func TestAllowProxyCloseEndsTunnels(t *testing.T) {
	before := runtime.NumGoroutine()
	// An upstream that accepts the tunnel and then stays silent.
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upDone := make(chan struct{})
	go func() {
		defer close(upDone)
		var held []net.Conn
		for {
			c, err := up.Accept()
			if err != nil {
				for _, h := range held {
					h.Close()
				}
				return
			}
			held = append(held, c)
		}
	}()
	redirect(t, up.Addr().String())
	gw := gateway(policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeFixInstall})
	raw, closeFn, err := Listen(gw, policy.PurposeFixInstall)
	if err != nil {
		t.Fatal(err)
	}
	p := parseProxy(t, raw)
	var conns []net.Conn
	for i := 0; i < 3; i++ {
		resp, c := connect(t, p.addr, p.withAuth("CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"))
		if resp.Status != "200 Connection Established" {
			t.Fatalf("status = %q", resp.Status)
		}
		conns = append(conns, c)
	}
	// An idle connection that never sends its request is closed too.
	idle, err := net.DialTimeout("tcp", p.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()

	start := time.Now()
	closeFn()
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("close took %v", d)
	}
	for i, c := range append(conns, idle) {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Errorf("connection %d still open after close", i)
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Errorf("connection %d not closed by close: %v", i, err)
		}
		c.Close()
	}
	closeFn() // idempotent
	if _, err := net.DialTimeout("tcp", p.addr, time.Second); err == nil {
		t.Error("proxy still accepts after close")
	}
	up.Close()
	<-upDone

	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before+2 {
		t.Errorf("goroutines: %d before, %d after close", before, n)
	}
}

func TestAllowProxyIdleTunnelTimesOut(t *testing.T) {
	old := idleTimeout
	idleTimeout = 200 * time.Millisecond
	t.Cleanup(func() { idleTimeout = old })
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		c, err := up.Accept()
		if err == nil {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}
	}()
	redirect(t, up.Addr().String())
	gw := gateway(policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeFixInstall})
	p := listen(t, gw, policy.PurposeFixInstall)
	resp, c := connect(t, p.addr, p.withAuth("CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n"))
	if resp.Status != "200 Connection Established" {
		t.Fatalf("status = %q", resp.Status)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("read data from a silent tunnel")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("idle tunnel was not closed by the proxy")
	}
}

func TestListenRejectsMissingArguments(t *testing.T) {
	if _, _, err := Listen(nil, policy.PurposeAgentClaude); err == nil {
		t.Error("nil gateway accepted")
	}
	if _, _, err := Listen(gateway(), ""); err == nil {
		t.Error("empty purpose accepted")
	}
}
