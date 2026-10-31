// Package sshx is Michel's SSH client. Every connection goes through the
// egress gateway (purpose target.ssh), authenticates with the keys of the
// SSH agent only (no private key is ever read) and checks the host key
// strictly: a confirmed fingerprint or a known_hosts entry, never a silent
// acceptance.
package sshx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/target"
)

const (
	// MaxOutput caps what Run keeps of each output stream.
	MaxOutput = 1 << 20
	// DefaultCommandTimeout bounds one command run by Run.
	DefaultCommandTimeout = 60 * time.Second
	// handshakeTimeout bounds the SSH handshake (key exchange and auth).
	handshakeTimeout = 30 * time.Second

	auditActor  = "michel"
	auditAction = "target.connect"
)

var (
	// ErrNoAgent means no SSH agent could be reached, or it holds no key.
	ErrNoAgent = errors.New("no SSH agent with a key is available: start the SSH agent and add your key (ssh-add)")
	// ErrNoKeyAccepted means the server accepted none of the agent's keys
	// (for instance a server that only offers password authentication).
	ErrNoKeyAccepted = errors.New("the server accepted none of the SSH agent's keys (Michel never uses passwords)")
	// ErrDenied means the egress policy refuses the server; it wraps
	// egress.ErrEgressDenied too.
	ErrDenied = errors.New("the network policy does not allow this server for target.ssh")
	// ErrCommandTimeout means a command ran past its time limit; it wraps
	// context.DeadlineExceeded too.
	ErrCommandTimeout = errors.New("the command ran past its time limit")
)

// Deps are the services Dial needs.
type Deps struct {
	Gateway *egress.Gateway
	// Audit records target.connect; nil records nothing (tests).
	Audit *audit.Logger
	// KnownHosts is the known_hosts file read (never written); empty means
	// ~/.ssh/known_hosts.
	KnownHosts string
	// Agent opens the SSH agent; nil means SystemAgent("").
	Agent func() (agent.ExtendedAgent, io.Closer, error)
	Now   func() time.Time
	// CommandTimeout bounds each Run; 0 means DefaultCommandTimeout.
	CommandTimeout time.Duration
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Result is the outcome of one command. Truncated is set when a stream went
// past MaxOutput and was cut.
type Result struct {
	Stdout, Stderr []byte
	Exit           int
	Truncated      bool
}

// Client is an authenticated SSH connection to one target.
type Client struct {
	c       *ssh.Client
	d       Deps
	t       target.Target
	fp      string
	keyType string
	start   time.Time
	timeout time.Duration

	once     sync.Once
	closeErr error
}

func address(t target.Target) string {
	port := t.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(port))
}

// open dials addr through the gateway and runs the SSH handshake bounded by
// ctx and handshakeTimeout. algos, once the TCP peer is known, chooses the
// host key algorithms to offer.
func open(ctx context.Context, d Deps, addr string, cfg *ssh.ClientConfig, algos func(remote net.Addr) []string) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	if d.Gateway == nil {
		return nil, nil, nil, errors.New("sshx: no egress gateway")
	}
	conn, err := d.Gateway.DialContext(ctx, policy.PurposeTargetSSH, "tcp", addr)
	if err != nil {
		if errors.Is(err, egress.ErrEgressDenied) {
			return nil, nil, nil, fmt.Errorf("%w: %w", ErrDenied, err)
		}
		return nil, nil, nil, err
	}
	cfg.HostKeyAlgorithms = algos(conn.RemoteAddr())
	deadline := time.Now().Add(handshakeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	stop()
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, nil, nil, fmt.Errorf("ssh handshake interrupted: %w", ctx.Err())
		}
		return nil, nil, nil, err
	}
	conn.SetDeadline(time.Time{})
	return sc, chans, reqs, nil
}

// Dial connects to t as t.User with the agent's keys, after the strict host
// key check.
func Dial(ctx context.Context, d Deps, t target.Target) (*Client, error) {
	start := d.now()
	c, fp, err := dial(ctx, d, t)
	if err != nil {
		if aerr := d.record(t, fp, start, resultOf(err)); aerr != nil {
			slog.Warn("sshx: cannot record a failed connection in the audit log", "err", aerr)
		}
		return nil, err
	}
	c.start = start
	return c, nil
}

func dial(ctx context.Context, d Deps, t target.Target) (*Client, string, error) {
	if t.Host == "" || t.User == "" {
		return nil, "", errors.New("sshx: the target has no host or no user")
	}
	openAgent := d.Agent
	if openAgent == nil {
		openAgent = SystemAgent("")
	}
	ag, closer, err := openAgent()
	if err != nil {
		return nil, "", fmt.Errorf("%w (%v)", ErrNoAgent, err)
	}
	if closer != nil {
		// The agent signs during the handshake only; no forwarding.
		defer closer.Close()
	}
	signers, err := ag.Signers()
	if err != nil {
		return nil, "", fmt.Errorf("%w (%v)", ErrNoAgent, err)
	}
	if len(signers) == 0 {
		return nil, "", fmt.Errorf("%w (the agent holds no key)", ErrNoAgent)
	}

	kh := d.KnownHosts
	if kh == "" {
		kh = defaultKnownHosts()
	}
	hk := &hostKeyCheck{}
	cfg := &ssh.ClientConfig{
		User:            t.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: hk.callback(t, kh),
		Timeout:         handshakeTimeout,
	}
	addr := address(t)
	algos := func(net.Addr) []string { return preferredHostKeyAlgos }
	if t.HostKey == "" {
		// Ask for a key type known_hosts holds, so an unchanged server is
		// never reported as changed because it offered another key type.
		algos = func(remote net.Addr) []string { return knownHostAlgorithms(kh, addr, remote) }
	}
	sc, chans, reqs, err := open(ctx, d, addr, cfg, algos)
	if err != nil {
		if hk.err != nil {
			return nil, hk.fingerprint, hk.err
		}
		if hk.accepted && strings.Contains(err.Error(), "unable to authenticate") {
			return nil, hk.fingerprint, fmt.Errorf("%w: %s@%s", ErrNoKeyAccepted, t.User, t.Host)
		}
		return nil, hk.fingerprint, err
	}
	timeout := d.CommandTimeout
	if timeout <= 0 {
		timeout = DefaultCommandTimeout
	}
	return &Client{c: ssh.NewClient(sc, chans, reqs), d: d, t: t, fp: hk.fingerprint, keyType: hk.keyType, timeout: timeout}, hk.fingerprint, nil
}

// errFingerprintRead stops the handshake once the host key is captured.
var errFingerprintRead = errors.New("host key captured")

// Fingerprint reads the server's host key without authenticating, so the
// user can confirm it: the handshake stops right after the key exchange. It
// asks for Ed25519 first (then ECDSA, then RSA), like Dial with a pin, so the
// fingerprint matches what OpenSSH shows and what Dial checks.
func Fingerprint(ctx context.Context, d Deps, t target.Target) (string, error) {
	fp, _, err := FingerprintKey(ctx, d, t)
	return fp, err
}

// FingerprintKey is Fingerprint plus the SSH key type of the host key
// (ssh-ed25519, ecdsa-sha2-nistp256, ssh-rsa...).
func FingerprintKey(ctx context.Context, d Deps, t target.Target) (string, string, error) {
	if t.Host == "" {
		return "", "", errors.New("sshx: the target has no host")
	}
	user := t.User
	if user == "" {
		user = "michel"
	}
	var fp, typ string
	cfg := &ssh.ClientConfig{
		User: user,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp, typ = ssh.FingerprintSHA256(key), key.Type()
			return errFingerprintRead
		},
		Timeout: handshakeTimeout,
	}
	sc, _, _, err := open(ctx, d, address(t), cfg, func(net.Addr) []string { return preferredHostKeyAlgos })
	if sc != nil {
		sc.Close()
	}
	if fp != "" {
		return fp, typ, nil
	}
	if err == nil {
		err = errors.New("sshx: the server sent no host key")
	}
	return "", "", err
}

// HostKeyFingerprint is the fingerprint of the host key accepted at Dial.
func (c *Client) HostKeyFingerprint() string { return c.fp }

// HostKeyType is the SSH key type of the host key accepted at Dial.
func (c *Client) HostKeyType() string { return c.keyType }

// Quote turns argv into one POSIX shell command line: every element is
// single-quoted ('\” for an apostrophe), so the remote shell sees exactly
// the given words, with no expansion.
func Quote(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(q, " ")
}

// capped keeps at most MaxOutput bytes and discards the rest, so the remote
// side is never blocked. It is safe for concurrent use.
type capped struct {
	mu        sync.Mutex
	buf       []byte
	truncated bool
}

func (w *capped) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	room := MaxOutput - len(w.buf)
	if len(p) > room {
		w.buf = append(w.buf, p[:max(room, 0)]...)
		w.truncated = true
	} else {
		w.buf = append(w.buf, p...)
	}
	return len(p), nil
}

func (w *capped) bytes() ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf...), w.truncated
}

// Run runs argv (quoted by Quote) with stdin, bounded by the command timeout
// and ctx. A non-zero exit status is a Result, not an error.
func (c *Client) Run(ctx context.Context, argv []string, stdin io.Reader) (Result, error) {
	if len(argv) == 0 {
		return Result{}, errors.New("sshx: empty command")
	}
	sess, err := c.c.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("cannot open an SSH session: %w", err)
	}
	defer sess.Close()
	var out, errOut capped
	sess.Stdout = &out
	sess.Stderr = &errOut
	sess.Stdin = stdin

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sess.Run(Quote(argv)) }()

	var runErr error
	select {
	case runErr = <-done:
	case <-ctx.Done():
		sess.Signal(ssh.SIGKILL)
		sess.Close()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Result{}, fmt.Errorf("%w (%v): %w", ErrCommandTimeout, c.timeout, ctx.Err())
		}
		return Result{}, ctx.Err()
	}
	res := Result{}
	var t1, t2 bool
	res.Stdout, t1 = out.bytes()
	res.Stderr, t2 = errOut.bytes()
	res.Truncated = t1 || t2
	var exit *ssh.ExitError
	switch {
	case runErr == nil:
	case errors.As(runErr, &exit):
		res.Exit = exit.ExitStatus()
	default:
		res.Exit = -1
		return res, fmt.Errorf("the command did not complete: %w", runErr)
	}
	return res, nil
}

// Close ends the connection and records target.connect. It is idempotent.
func (c *Client) Close() error {
	c.once.Do(func() {
		err := c.c.Close()
		if err != nil && errors.Is(err, net.ErrClosed) {
			err = nil
		}
		if aerr := c.d.record(c.t, c.fp, c.start, "ok"); aerr != nil {
			err = errors.Join(err, aerr)
		}
		c.closeErr = err
	})
	return c.closeErr
}

// resultOf names a Dial failure for the audit, without its message.
func resultOf(err error) string {
	var unk ErrHostKeyUnknown
	var chg ErrHostKeyChanged
	switch {
	case errors.Is(err, ErrDenied):
		return "denied"
	case errors.Is(err, ErrNoAgent):
		return "no_agent"
	case errors.Is(err, ErrNoKeyAccepted):
		return "no_key_accepted"
	case errors.As(err, &unk):
		return "host_key_unknown"
	case errors.As(err, &chg):
		return "host_key_changed"
	default:
		return "error"
	}
}

// record writes target.connect: user, host key fingerprint, duration and
// result only, never a command or its output.
func (d Deps) record(t target.Target, fp string, start time.Time, result string) error {
	if d.Audit == nil {
		return nil
	}
	_, err := d.Audit.Record(context.Background(), audit.Event{
		Actor: auditActor, Action: auditAction, Target: t.ID, Result: result,
		Evidence: map[string]any{
			"user":        t.User,
			"host_key":    fp,
			"duration_ms": d.now().Sub(start).Milliseconds(),
			"result":      result,
		},
	})
	return err
}
