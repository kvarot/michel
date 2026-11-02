// Package sshtest is an in-memory SSH server for tests: it listens on
// 127.0.0.1, has a generated host key, accepts the client keys made by
// NewAgent, and runs simulated commands instead of a real shell. Nothing here
// touches the real ~/.ssh or the real SSH agent.
package sshtest

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Exec is one command the server received, as its handler sees it.
type Exec struct {
	// Ctx is cancelled when the client closes the session or signals it.
	Ctx context.Context
	// Args is the command split into words with the POSIX quoting rules.
	Args   []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Handler simulates one command and returns its exit status.
type Handler func(e Exec) int

// ShellFunc runs the script a client sent to `sh -s` on its standard input
// and returns the exit status. Task 9 provides the mini interpreter.
type ShellFunc func(s *Server, script string, stdout, stderr io.Writer) int

// Options shapes the simulated server.
type Options struct {
	// Files is the simulated file system (path → content).
	Files map[string]string
	// Commands maps a command to its handler: the exact command string is
	// tried first, then its first word.
	Commands map[string]Handler
	// Writable lists the paths the SSH user may write.
	Writable map[string]bool
	// Sudo tells whether the SSH user may use sudo without a password.
	Sudo bool
	// Shell runs `sh -s`; nil means `sh -s` is unsupported (exit 127).
	Shell ShellFunc
	// RootShell runs `sudo -n sh -s` when Sudo is set (a Shell with UID
	// 0); nil means it is unsupported (exit 127). Without Sudo, any
	// `sudo -n` command fails as a real sudo asking for a password does.
	RootShell ShellFunc
	// HostKeyTypes lists the host keys the server holds, among "ed25519",
	// "ecdsa" (P-256) and "rsa" (2048 bits); empty means ed25519 only.
	HostKeyTypes []string
	// PasswordOnly makes the server refuse every public key and offer only
	// password authentication.
	PasswordOnly bool
}

// Server is a running test server, closed when the test ends.
type Server struct {
	opts     Options
	ln       net.Listener
	signers  map[string]ssh.Signer // by Options.HostKeyTypes name
	main     ssh.Signer            // ed25519 when held, else the first
	accepted atomic.Int64
	signals  atomic.Int64
	authN    atomic.Int64

	mu         sync.Mutex
	files      map[string]string
	authorized map[string]bool // marshalled client public keys
	log        []string
	conns      []net.Conn

	wg sync.WaitGroup
}

// New starts a server on 127.0.0.1:0 and stops it at the end of the test.
func New(t testing.TB, opts Options) *Server {
	t.Helper()
	s, err := Start(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// Start starts a server on 127.0.0.1:0 outside a test (the demo command);
// the caller stops it with Close. It only ever listens on the loopback.
func Start(opts Options) (*Server, error) {
	types := opts.HostKeyTypes
	if len(types) == 0 {
		types = []string{"ed25519"}
	}
	signers := map[string]ssh.Signer{}
	var main ssh.Signer
	for _, typ := range types {
		sg, err := newHostSigner(typ)
		if err != nil {
			return nil, err
		}
		signers[typ] = sg
		if main == nil || typ == "ed25519" {
			main = sg
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{opts: opts, ln: ln, signers: signers, main: main, files: map[string]string{}, authorized: map[string]bool{}}
	for k, v := range opts.Files {
		s.files[k] = v
	}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

// Addr is the host:port the server listens on.
func (s *Server) Addr() string { return s.ln.Addr().String() }

func newHostSigner(typ string) (ssh.Signer, error) {
	var key any
	var err error
	switch typ {
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("sshtest: unknown host key type %q", typ)
	}
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

// HostPublicKey is the server's main host key: the Ed25519 one when the
// server holds it, else the first of Options.HostKeyTypes.
func (s *Server) HostPublicKey() ssh.PublicKey { return s.main.PublicKey() }

// HostPublicKeyOf is the host key of one Options.HostKeyTypes name, or nil.
func (s *Server) HostPublicKeyOf(typ string) ssh.PublicKey {
	if sg, ok := s.signers[typ]; ok {
		return sg.PublicKey()
	}
	return nil
}

// HostKeyFingerprint is the SHA256 fingerprint of the main host key.
func (s *Server) HostKeyFingerprint() string { return ssh.FingerprintSHA256(s.main.PublicKey()) }

// Signals counts the signal requests (such as SIGKILL) clients sent.
func (s *Server) Signals() int { return int(s.signals.Load()) }

// DropConnections cuts every open connection at once, as a network failure
// would: the clients see their sessions end without an exit status.
func (s *Server) DropConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		c.Close()
	}
}

// Accepted counts the TCP connections the server accepted.
func (s *Server) Accepted() int { return int(s.accepted.Load()) }

// AuthAttempts counts the authentication requests (public key or password)
// the server received.
func (s *Server) AuthAttempts() int { return int(s.authN.Load()) }

// Log returns every command received, in order, as the client sent it.
func (s *Server) Log() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.log...)
}

// Options returns the options the server was started with.
func (s *Server) Options() Options { return s.opts }

// File returns the content of a simulated file.
func (s *Server) File(path string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.files[path]
	return v, ok
}

// SetFile writes a simulated file.
func (s *Server) SetFile(path, content string) {
	s.mu.Lock()
	s.files[path] = content
	s.mu.Unlock()
}

// NewAgent returns an in-memory agent holding a fresh client key that the
// server accepts.
func (s *Server) NewAgent(t testing.TB) agent.ExtendedAgent {
	t.Helper()
	kr, err := s.AddClientKey()
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

// AddClientKey makes a fresh client key, has the server accept it, and
// returns an in-memory agent holding it (never the real SSH agent).
func (s *Server) AddClientKey() (agent.ExtendedAgent, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	kr := agent.NewKeyring().(agent.ExtendedAgent)
	if err := kr.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		return nil, err
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.authorized[string(pub.Marshal())] = true
	s.mu.Unlock()
	return kr, nil
}

// Close stops the server and cuts its connections.
func (s *Server) Close() { s.close() }

func (s *Server) close() {
	s.ln.Close()
	s.mu.Lock()
	for _, c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) config() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{}
	if s.opts.PasswordOnly {
		cfg.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			s.authN.Add(1)
			return nil, errors.New("password refused")
		}
	} else {
		cfg.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.authN.Add(1)
			s.mu.Lock()
			ok := s.authorized[string(key.Marshal())]
			s.mu.Unlock()
			if !ok {
				return nil, errors.New("key not authorized")
			}
			return &ssh.Permissions{}, nil
		}
	}
	for _, sg := range s.signers {
		cfg.AddHostKey(sg)
	}
	return cfg
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.accepted.Add(1)
		s.mu.Lock()
		s.conns = append(s.conns, c)
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(c)
		}()
	}
}

func (s *Server) handleConn(c net.Conn) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, s.config())
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	var wg sync.WaitGroup
	defer wg.Wait()
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.session(ch, creqs)
		}()
	}
}

// session serves one channel: the first exec request runs, everything else
// (pty, shell, env) is refused.
func (s *Server) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	started := false
	for {
		select {
		case req, ok := <-reqs:
			if !ok {
				cancel()
				if started {
					<-done
				}
				return
			}
			switch {
			case req.Type == "exec" && !started:
				cmd, ok := parseString(req.Payload)
				if !ok {
					req.Reply(false, nil)
					continue
				}
				req.Reply(true, nil)
				started = true
				s.mu.Lock()
				s.log = append(s.log, cmd)
				s.mu.Unlock()
				go func() { done <- s.run(ctx, cmd, ch) }()
			case req.Type == "signal":
				s.signals.Add(1)
				cancel()
				if req.WantReply {
					req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		case code := <-done:
			ch.CloseWrite()
			status := make([]byte, 4)
			binary.BigEndian.PutUint32(status, uint32(code))
			ch.SendRequest("exit-status", false, status)
			return
		}
	}
}

// stream is the part of an ssh.Channel a command uses.
type stream interface {
	io.ReadWriter
	Stderr() io.ReadWriter
}

func (s *Server) run(ctx context.Context, cmd string, ch stream) int {
	stderr := ch.Stderr()
	args, err := SplitWords(cmd)
	if err != nil || len(args) == 0 {
		fmt.Fprintf(stderr, "sshtest: cannot parse command: %v\n", err)
		return 2
	}
	if len(args) == 4 && args[0] == "sudo" && args[1] == "-n" && args[2] == "sh" && args[3] == "-s" {
		if !s.opts.Sudo {
			io.WriteString(stderr, "sudo: a password is required\n")
			return 1
		}
		if s.opts.RootShell == nil {
			io.WriteString(stderr, "sshtest: sudo -n sh -s unsupported\n")
			return 127
		}
		script, err := io.ReadAll(ch)
		if err != nil {
			return 2
		}
		return s.opts.RootShell(s, string(script), ch, stderr)
	}
	if len(args) >= 2 && args[0] == "sudo" && args[1] == "-n" && !s.opts.Sudo {
		io.WriteString(stderr, "sudo: a password is required\n")
		return 1
	}
	if len(args) == 2 && args[0] == "sh" && args[1] == "-s" {
		if s.opts.Shell == nil {
			io.WriteString(stderr, "sshtest: sh -s unsupported\n")
			return 127
		}
		script, err := io.ReadAll(ch)
		if err != nil {
			return 2
		}
		return s.opts.Shell(s, string(script), ch, stderr)
	}
	h, ok := s.opts.Commands[cmd]
	if !ok {
		h, ok = s.opts.Commands[args[0]]
	}
	if !ok {
		fmt.Fprintf(stderr, "sshtest: %s: command not found\n", args[0])
		return 127
	}
	return h(Exec{Ctx: ctx, Args: args, Stdin: ch, Stdout: ch, Stderr: stderr})
}

func parseString(p []byte) (string, bool) {
	if len(p) < 4 {
		return "", false
	}
	n := binary.BigEndian.Uint32(p)
	if uint64(n) != uint64(len(p)-4) {
		return "", false
	}
	return string(p[4:]), true
}

// SplitWords splits a command line into words with the POSIX quoting rules
// Michel's clients use: single quotes, double quotes (no expansion) and
// backslash escapes. It does no expansion of any kind.
func SplitWords(cmd string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		case c == '\'':
			inWord = true
			j := strings.IndexByte(cmd[i+1:], '\'')
			if j < 0 {
				return nil, errors.New("unterminated single quote")
			}
			cur.WriteString(cmd[i+1 : i+1+j])
			i += j + 1
		case c == '"':
			inWord = true
			i++
			for ; i < len(cmd) && cmd[i] != '"'; i++ {
				if cmd[i] == '\\' && i+1 < len(cmd) && strings.IndexByte(`"\$`+"`", cmd[i+1]) >= 0 {
					i++
				}
				cur.WriteByte(cmd[i])
			}
			if i >= len(cmd) {
				return nil, errors.New("unterminated double quote")
			}
		case c == '\\':
			inWord = true
			if i+1 < len(cmd) {
				i++
				cur.WriteByte(cmd[i])
			}
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}
