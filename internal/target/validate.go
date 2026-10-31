package target

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/policy"
)

// The refusals of the checks the API and the command line share before they
// store a server.
var (
	ErrPreprodNotFound = errors.New("the preprod server is not a server of Michel")
	ErrPreprodSelf     = errors.New("a server cannot be its own preprod")
	ErrPreprodChain    = errors.New("a preprod server has no preprod of its own, and a server that is a preprod has none either")
	ErrInvalidSiteURL  = errors.New("the site address must be an http or https address")
	ErrInvalidInterval = errors.New("the check interval must be \"manual\" or a duration between 5 minutes and 365 days")
)

// ManualText is the word that stands for ManualOnly in the API and on the
// command line.
const ManualText = "manual"

// minInterval and maxInterval bound an automatic check interval.
const (
	minInterval = 5 * time.Minute
	maxInterval = 365 * 24 * time.Hour
)

// ParseInterval reads a check interval as the API and the command line give
// it: "" is 0 (the default one), "manual" is ManualOnly, else a duration
// ("12h", "90m") between 5 minutes and 365 days.
func ParseInterval(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "":
		return 0, nil
	case ManualText:
		return ManualOnly, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < minInterval || d > maxInterval {
		return 0, ErrInvalidInterval
	}
	return d, nil
}

// IntervalText is ParseInterval's reverse for a stored interval, the default
// one written out: "manual", "24h", "90m".
func IntervalText(d time.Duration) string {
	switch {
	case d < 0:
		return ManualText
	case d == 0:
		d = DefaultCheckInterval
	}
	s := d.String()
	s = strings.TrimSuffix(s, "0s")
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// ValidateSiteURL accepts "" or an http(s) address with a host and no
// credentials.
func ValidateSiteURL(s string) error {
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return ErrInvalidSiteURL
	}
	return nil
}

// ResolvePreprod finds the preprod server named by ref (its id or its name)
// for server t and returns its id. ref "" is no preprod. The preprod must be
// a server of Michel, not t itself, and no chain is allowed: the preprod has
// no preprod, and t is not the preprod of another server.
func (r *Repo) ResolvePreprod(ctx context.Context, t Target, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", nil
	}
	p, err := r.Get(ctx, ref)
	if errors.Is(err, ErrNotFound) {
		return "", ErrPreprodNotFound
	}
	if err != nil {
		return "", err
	}
	if (t.ID != "" && p.ID == t.ID) || (t.ID == "" && t.Name != "" && p.Name == t.Name) {
		return "", ErrPreprodSelf
	}
	if p.PreprodID != "" {
		return "", ErrPreprodChain
	}
	if t.ID != "" {
		all, err := r.List(ctx)
		if err != nil {
			return "", err
		}
		for _, o := range all {
			if o.PreprodID == t.ID {
				return "", fmt.Errorf("%w", ErrPreprodChain)
			}
		}
	}
	return p.ID, nil
}

// AllowRules are the network rules a server needs: SSH to its host, and the
// GET of its site when it has one. Adding the server is the user's opt-in
// for them.
func AllowRules(t Target) []policy.AllowRule {
	rules := []policy.AllowRule{{Host: t.Host, Purpose: policy.PurposeTargetSSH}}
	if u, err := url.Parse(t.SiteURL); err == nil && t.SiteURL != "" && u.Hostname() != "" {
		rules = append(rules, policy.AllowRule{Host: u.Hostname(), Purpose: policy.PurposeTargetHTTP})
	}
	return rules
}
