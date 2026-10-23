package notify

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// testCert returns a self-signed certificate for 127.0.0.1 and localhost,
// as a server config and a client config that trusts it.
func testCert(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "michel test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12},
		&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// smtpServer is a minimal SMTP server on 127.0.0.1 speaking EHLO, STARTTLS,
// AUTH PLAIN, MAIL, RCPT, DATA and QUIT. It records what the client did.
type smtpServer struct {
	t           *testing.T
	ln          net.Listener
	tls         *tls.Config
	implicitTLS bool
	noStartTLS  bool

	mu       sync.Mutex
	commands []string
	auth     string // decoded AUTH PLAIN response
	authTLS  bool   // AUTH came over TLS
	from     string
	rcpts    []string
	data     string
}

func startSMTP(t *testing.T, cfg *tls.Config, implicitTLS, noStartTLS bool) *smtpServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpServer{t: t, ln: ln, tls: cfg, implicitTLS: implicitTLS, noStartTLS: noStartTLS}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *smtpServer) addr() string { return s.ln.Addr().String() }

func (s *smtpServer) record(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
}

// smtpSession is what the server recorded.
type smtpSession struct {
	commands []string
	auth     string
	authTLS  bool
	from     string
	rcpts    []string
	data     string
}

func (s *smtpServer) snapshot() smtpSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return smtpSession{commands: append([]string(nil), s.commands...), auth: s.auth, authTLS: s.authTLS, from: s.from,
		rcpts: append([]string(nil), s.rcpts...), data: s.data}
}

func (s *smtpServer) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	secure := false
	if s.implicitTLS {
		tc := tls.Server(c, s.tls)
		if err := tc.Handshake(); err != nil {
			return
		}
		c, secure = tc, true
	}
	r, w := bufio.NewReader(c), bufio.NewWriter(c)
	say := func(lines ...string) {
		for _, l := range lines {
			w.WriteString(l + "\r\n")
		}
		w.Flush()
	}
	say("220 test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb, arg, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(verb)
		s.record(func() { s.commands = append(s.commands, verb) })
		switch verb {
		case "EHLO", "HELO":
			lines := []string{"250-test"}
			if !secure && !s.noStartTLS {
				lines = append(lines, "250-STARTTLS")
			}
			if secure {
				lines = append(lines, "250-AUTH PLAIN")
			}
			say(append(lines, "250 8BITMIME")...)
		case "STARTTLS":
			say("220 ready")
			tc := tls.Server(c, s.tls)
			if err := tc.Handshake(); err != nil {
				return
			}
			c, secure = tc, true
			r, w = bufio.NewReader(c), bufio.NewWriter(c)
		case "AUTH":
			mech, resp, _ := strings.Cut(arg, " ")
			raw, err := base64.StdEncoding.DecodeString(resp)
			if strings.ToUpper(mech) != "PLAIN" || err != nil {
				say("504 unsupported")
				continue
			}
			s.record(func() { s.auth, s.authTLS = string(raw), secure })
			say("235 ok")
		case "MAIL":
			s.record(func() { s.from = angle(arg) })
			say("250 ok")
		case "RCPT":
			s.record(func() { s.rcpts = append(s.rcpts, angle(arg)) })
			say("250 ok")
		case "DATA":
			say("354 go ahead")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(strings.TrimPrefix(l, "."))
			}
			s.record(func() { s.data = b.String() })
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

// angle returns the address between < and > in a MAIL or RCPT argument.
func angle(arg string) string {
	_, rest, _ := strings.Cut(arg, "<")
	addr, _, _ := strings.Cut(rest, ">")
	return addr
}
