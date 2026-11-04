package sshx

import "time"

// SetHandshakeTimeout shortens the bound of the SSH handshake for a test and
// returns what puts it back.
func SetHandshakeTimeout(d time.Duration) (restore func()) {
	was := handshakeTimeout
	handshakeTimeout = d
	return func() { handshakeTimeout = was }
}

// NetCause exposes netCause to the tests.
var NetCause = netCause
