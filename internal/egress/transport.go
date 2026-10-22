package egress

import (
	"fmt"
	"net/http"
	"time"
)

// checkedTransport enforces the allowlist before delegating to the shared
// inner transport.
type checkedTransport struct {
	g       *Gateway
	purpose string
}

func (t checkedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	ok, reason := t.g.Allowed(host, t.purpose)
	t.g.record(Attempt{Host: host, Purpose: t.purpose, Allowed: ok, At: time.Now(), Reason: reason})
	if !ok {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, fmt.Errorf("%w: host %s purpose %s: %s", ErrEgressDenied, host, t.purpose, reason)
	}
	return t.g.inner.RoundTrip(req)
}
