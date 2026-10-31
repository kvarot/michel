// Package servererr names the refusals of the server registry, of SSH and of
// the checks with the catalog key of their sentence, for the API and the
// command line. The sentences never carry what the errors carry (a socket
// path, a user, an address): only the key is used.
package servererr

import (
	"context"
	"errors"

	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/target"
)

// Check failed generically: the key of a check that ended for another
// reason.
const CheckFailed = "api.target.check_failed"

// Unreachable is the key of a server that could not be reached.
const Unreachable = "api.target.unreachable"

// Key is the catalog key of the sentence that tells err, "" when err is none
// of the refusals this package knows. A key's hint, when it has one, is the
// key with "_hint" added.
func Key(err error) string {
	var unknown sshx.ErrHostKeyUnknown
	var changed sshx.ErrHostKeyChanged
	for _, k := range []struct {
		err error
		key string
	}{
		{target.ErrNotFound, "api.target.not_found"},
		{target.ErrDuplicateName, "api.target.duplicate"},
		{target.ErrEmptyName, "api.target.bad_name"},
		{target.ErrEmptyHost, "api.target.bad_host"},
		{target.ErrInvalidPort, "api.target.bad_port"},
		{target.ErrInvalidKind, "api.target.bad_kind"},
		{target.ErrInvalidEnv, "api.target.bad_env"},
		{target.ErrInvalidExecutor, "api.target.bad_executor"},
		{target.ErrInvalidSudo, "api.target.bad_sudo"},
		{target.ErrInvalidFixLevel, "api.target.bad_fix_level"},
		{target.ErrInvalidClass, "api.target.bad_classification"},
		{target.ErrHDSIsHealth, "api.target.hds_health"},
		{target.ErrInvalidSiteURL, "api.target.bad_site_url"},
		{target.ErrInvalidInterval, "api.target.bad_interval"},
		{target.ErrPreprodNotFound, "api.target.preprod_not_found"},
		{target.ErrPreprodSelf, "api.target.preprod_self"},
		{target.ErrPreprodChain, "api.target.preprod_chain"},
		{servercheck.ErrInactive, "api.target.inactive"},
		{sshx.ErrNoAgent, "api.target.no_agent"},
		{sshx.ErrNoKeyAccepted, "api.target.no_key_accepted"},
		{sshx.ErrDenied, "api.target.denied"},
		{egress.ErrEgressDenied, "api.target.denied"},
		{sshx.ErrCommandTimeout, "api.target.timeout"},
		{context.DeadlineExceeded, "api.target.timeout"},
	} {
		if errors.Is(err, k.err) {
			return k.key
		}
	}
	switch {
	case errors.As(err, &unknown):
		return "api.target.hostkey_unknown"
	case errors.As(err, &changed):
		return "api.target.hostkey_changed"
	}
	return ""
}
