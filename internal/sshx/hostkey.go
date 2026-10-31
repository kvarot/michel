package sshx

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/kvarot/michel/internal/target"
)

// ErrHostKeyUnknown means the server's host key is neither the confirmed
// fingerprint of the target nor in known_hosts. Fingerprint is the SHA256
// fingerprint the user must confirm before Michel connects; KeyType is its
// SSH key type (ssh-ed25519 when the server has one).
type ErrHostKeyUnknown struct{ Fingerprint, KeyType string }

func (e ErrHostKeyUnknown) Error() string {
	return fmt.Sprintf("the server's host key %s is not known yet: confirm this fingerprint before connecting", e.Fingerprint)
}

// ErrHostKeyChanged means the server presented another key than the one
// Michel knows. Nothing was sent: it can be a reinstall or an attack.
// KeyType is the type of the key presented (Got).
type ErrHostKeyChanged struct{ Want, Got, KeyType string }

func (e ErrHostKeyChanged) Error() string {
	return fmt.Sprintf("the server's host key changed (expected %s, got %s): connection refused", e.Want, e.Got)
}

// defaultKnownHosts is ~/.ssh/known_hosts, read only.
func defaultKnownHosts() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

// preferredHostKeyAlgos is the host key algorithm order Michel asks for when
// nothing else decides it: Ed25519 first, as OpenSSH shows it, then ECDSA,
// then RSA. Fingerprint and Dial use the same order, so the fingerprint the
// user confirms is the key Dial later negotiates.
var preferredHostKeyAlgos = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA,
}

// keyTypeOf is the key type an algorithm proves (rsa-sha2-* sign with an
// ssh-rsa key).
func keyTypeOf(algo string) string {
	switch algo {
	case ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256:
		return ssh.KeyAlgoRSA
	}
	return algo
}

// placeholderKey never matches a real host key: it only makes known_hosts
// list the keys it holds for a host.
var placeholderKey = func() ssh.PublicKey {
	k, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public())
	if err != nil {
		panic(err)
	}
	return k
}()

// knownHostAlgorithms returns the host key algorithms, in preferred order,
// for the key types known_hosts holds for hostname / remote, so the server
// presents a key known_hosts can confirm. Without any entry (or file) it
// returns the preferred order.
func knownHostAlgorithms(knownHostsPath, hostname string, remote net.Addr) []string {
	if knownHostsPath == "" {
		return preferredHostKeyAlgos
	}
	if _, err := os.Stat(knownHostsPath); err != nil {
		return preferredHostKeyAlgos
	}
	cb, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return preferredHostKeyAlgos // the real check reports the error
	}
	var ke *knownhosts.KeyError
	if err := cb(hostname, remote, placeholderKey); !errors.As(err, &ke) || len(ke.Want) == 0 {
		return preferredHostKeyAlgos
	}
	types := map[string]bool{}
	for _, k := range ke.Want {
		types[k.Key.Type()] = true
	}
	var out []string
	covered := map[string]bool{}
	for _, a := range preferredHostKeyAlgos {
		if types[keyTypeOf(a)] {
			out = append(out, a)
			covered[keyTypeOf(a)] = true
		}
	}
	for typ := range types { // other types known_hosts holds (ML-DSA...)
		if !covered[typ] {
			out = append(out, typ)
		}
	}
	return out
}

// hostKeyCheck holds the outcome of the host key callback, so Dial can tell
// a host key refusal from an authentication failure.
type hostKeyCheck struct {
	fingerprint string
	keyType     string
	err         error // the refusal, nil when the key was accepted
	accepted    bool
}

// callback checks the host key strictly: the confirmed fingerprint of the
// target is a pin; without one, the key must be in known_hosts. Anything
// else stops the handshake before authentication.
func (h *hostKeyCheck) callback(t target.Target, knownHostsPath string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		h.fingerprint = ssh.FingerprintSHA256(key)
		h.keyType = key.Type()
		h.err = verifyHostKey(t, knownHostsPath, hostname, remote, key)
		h.accepted = h.err == nil
		return h.err
	}
}

func verifyHostKey(t target.Target, knownHostsPath, hostname string, remote net.Addr, key ssh.PublicKey) error {
	got := ssh.FingerprintSHA256(key)
	if t.HostKey != "" {
		if t.HostKey == got {
			return nil
		}
		return ErrHostKeyChanged{Want: t.HostKey, Got: got, KeyType: key.Type()}
	}
	if knownHostsPath == "" {
		return ErrHostKeyUnknown{Fingerprint: got, KeyType: key.Type()}
	}
	if _, err := os.Stat(knownHostsPath); errors.Is(err, os.ErrNotExist) {
		return ErrHostKeyUnknown{Fingerprint: got, KeyType: key.Type()}
	}
	cb, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return fmt.Errorf("cannot read known_hosts: %w", err)
	}
	err = cb(hostname, remote, key)
	var ke *knownhosts.KeyError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ke) && len(ke.Want) == 0:
		return ErrHostKeyUnknown{Fingerprint: got, KeyType: key.Type()}
	case errors.As(err, &ke):
		return ErrHostKeyChanged{Want: ssh.FingerprintSHA256(ke.Want[0].Key), Got: got, KeyType: key.Type()}
	default:
		var re *knownhosts.RevokedError
		if errors.As(err, &re) {
			return fmt.Errorf("the server's host key %s is revoked in known_hosts: connection refused", got)
		}
		return err
	}
}
