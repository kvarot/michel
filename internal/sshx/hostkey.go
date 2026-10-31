package sshx

import (
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
// fingerprint the user must confirm before Michel connects.
type ErrHostKeyUnknown struct{ Fingerprint string }

func (e ErrHostKeyUnknown) Error() string {
	return fmt.Sprintf("the server's host key %s is not known yet: confirm this fingerprint before connecting", e.Fingerprint)
}

// ErrHostKeyChanged means the server presented another key than the one
// Michel knows. Nothing was sent: it can be a reinstall or an attack.
type ErrHostKeyChanged struct{ Want, Got string }

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

// hostKeyCheck holds the outcome of the host key callback, so Dial can tell
// a host key refusal from an authentication failure.
type hostKeyCheck struct {
	fingerprint string
	err         error // the refusal, nil when the key was accepted
	accepted    bool
}

// callback checks the host key strictly: the confirmed fingerprint of the
// target is a pin; without one, the key must be in known_hosts. Anything
// else stops the handshake before authentication.
func (h *hostKeyCheck) callback(t target.Target, knownHostsPath string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		h.fingerprint = ssh.FingerprintSHA256(key)
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
		return ErrHostKeyChanged{Want: t.HostKey, Got: got}
	}
	if knownHostsPath == "" {
		return ErrHostKeyUnknown{Fingerprint: got}
	}
	if _, err := os.Stat(knownHostsPath); errors.Is(err, os.ErrNotExist) {
		return ErrHostKeyUnknown{Fingerprint: got}
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
		return ErrHostKeyUnknown{Fingerprint: got}
	case errors.As(err, &ke):
		return ErrHostKeyChanged{Want: ssh.FingerprintSHA256(ke.Want[0].Key), Got: got}
	default:
		var re *knownhosts.RevokedError
		if errors.As(err, &re) {
			return fmt.Errorf("the server's host key %s is revoked in known_hosts: connection refused", got)
		}
		return err
	}
}
