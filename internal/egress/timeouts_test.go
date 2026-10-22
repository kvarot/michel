package egress

import (
	"testing"
	"time"

	"github.com/kvarot/michel/internal/policy"
)

func TestClientHasNoOverallTimeoutButBoundsHeaders(t *testing.T) {
	g := New(policy.Defaults(), nil)
	if c := g.Client("x.y"); c.Timeout != 0 {
		t.Errorf("Timeout = %v", c.Timeout)
	}
	if g.inner.ResponseHeaderTimeout != 30*time.Second || g.inner.TLSHandshakeTimeout != 15*time.Second || g.inner.IdleConnTimeout != 90*time.Second {
		t.Errorf("transport timeouts not set: %v %v %v", g.inner.ResponseHeaderTimeout, g.inner.TLSHandshakeTimeout, g.inner.IdleConnTimeout)
	}
}
