package egress

import "errors"

// ErrEgressDenied is returned (wrapped) when a request is refused by policy.
var ErrEgressDenied = errors.New("egress denied by policy")
