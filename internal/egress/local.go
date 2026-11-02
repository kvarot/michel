package egress

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
)

// DialLocalSocket connects to a Unix domain socket on this machine, such as
// the SSH agent socket named by SSH_AUTH_SOCK. A Unix socket never leaves
// the machine, so no allowlist rule and no Attempt apply; it lives here
// because internal/egress is the only package that may dial. Only an
// absolute file path is accepted.
func DialLocalSocket(ctx context.Context, path string) (net.Conn, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("local socket %q refused: only an absolute path may be dialed", path)
	}
	d := net.Dialer{Timeout: dialTimeout}
	return d.DialContext(ctx, "unix", path)
}
