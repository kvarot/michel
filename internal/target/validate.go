package target

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/policy"
)

// The refusals of the checks the API and the command line share before they
// store a server.
var (
	ErrPreprodNotFound  = errors.New("the preprod server is not a server of Michel")
	ErrPreprodSelf      = errors.New("a server cannot be its own preprod")
	ErrPreprodChain     = errors.New("a preprod server has no preprod of its own, and a server that is a preprod has none either")
	ErrInvalidSiteURL   = errors.New("the site address must be an http or https address")
	ErrPreprodRole      = errors.New("a preprod server must have the role preprod or dev")
	ErrInvalidHost      = errors.New("the host must be a host name or an IPv4 address, without wildcard, user, port or path")
	ErrEmptyUser        = errors.New("the SSH user is missing")
	ErrInvalidRemoteDir = errors.New("a project folder on the server must be an absolute path below a top-level folder")
	ErrInvalidInterval  = errors.New("the check interval must be \"manual\" or a duration between 5 minutes and 365 days")
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

var (
	hostRe      = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$`)
	remoteDirRe = regexp.MustCompile(`^/[A-Za-z0-9._@+,:~/ -]{0,510}$`)
)

// ValidateHost accepts a host name or an IPv4 address: no wildcard (the
// network rule written for the server names this host only), no user, port,
// path or space. An IPv6 literal cannot become a network rule, so it is
// refused too.
func ValidateHost(h string) error {
	if !hostRe.MatchString(h) {
		return ErrInvalidHost
	}
	return nil
}

// ValidateRemoteDir accepts the folder a project lives in on a server: an
// absolute path without "..", below a top-level folder: not "/", "/home" or
// "/root", and not "/home/<user>" itself (a project folder is below these).
func ValidateRemoteDir(dir string) error {
	if !remoteDirRe.MatchString(dir) {
		return ErrInvalidRemoteDir
	}
	clean := path.Clean(dir)
	if strings.Contains(dir, "..") || clean != strings.TrimRight(dir, "/") {
		return ErrInvalidRemoteDir
	}
	parts := strings.Split(strings.Trim(clean, "/"), "/")
	switch {
	case clean == "/", clean == "/home", clean == "/root":
		return ErrInvalidRemoteDir
	case parts[0] == "home" && len(parts) < 3, parts[0] == "root" && len(parts) < 2:
		return ErrInvalidRemoteDir
	}
	return nil
}

// cleanText tells whether s is at most 64 characters with no control
// character.
func cleanText(s string) bool {
	if utf8.RuneCountInString(s) > 64 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == 0xFFFD || (r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0xFEFF {
			return false
		}
	}
	return true
}

// Check validates what the API and the command line both check before a
// server is stored or changed: name, alias, host and user (none empty where
// it matters, none invisible or too long), the host as a host name, the
// site address. The other fields are checked by the registry.
func Check(t Target) error {
	for _, f := range []string{t.Name, t.Alias, t.User} {
		if f != strings.TrimSpace(f) || !cleanText(f) {
			return ErrEmptyName
		}
	}
	if strings.TrimSpace(t.Name) == "" {
		return ErrEmptyName
	}
	if strings.TrimSpace(t.User) == "" {
		return ErrEmptyUser
	}
	if strings.TrimSpace(t.Host) == "" {
		return ErrEmptyHost
	}
	if err := ValidateHost(t.Host); err != nil {
		return err
	}
	return ValidateSiteURL(t.SiteURL)
}

// ValidateSiteURL accepts "" or an http(s) address with a host and no
// credentials.
func ValidateSiteURL(s string) error {
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || ValidateHost(u.Hostname()) != nil {
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
	if p.Env == EnvProd {
		return "", ErrPreprodRole
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

// ReleasedRules are the network rules a server no longer needs once it is
// gone or changed: those of old that none of kept (the servers that stay, the
// changed one in its new form) still uses.
func ReleasedRules(old Target, kept []Target) []policy.AllowRule {
	used := map[policy.AllowRule]bool{}
	for _, k := range kept {
		for _, r := range AllowRules(k) {
			used[r] = true
		}
	}
	var out []policy.AllowRule
	for _, r := range AllowRules(old) {
		if !used[r] {
			out = append(out, r)
		}
	}
	return out
}

// NewRules are the rules of want that current does not hold yet.
func NewRules(current, want []policy.AllowRule) []policy.AllowRule {
	have := map[policy.AllowRule]bool{}
	for _, r := range current {
		have[r] = true
	}
	var out []policy.AllowRule
	for _, r := range want {
		if !have[r] {
			out = append(out, r)
			have[r] = true
		}
	}
	return out
}

// CheckEnv refuses to make a server production while another one has it as
// its preprod.
func (r *Repo) CheckEnv(ctx context.Context, t Target) error {
	if t.Env != EnvProd || t.ID == "" {
		return nil
	}
	all, err := r.List(ctx)
	if err != nil {
		return err
	}
	for _, o := range all {
		if o.PreprodID == t.ID {
			return ErrPreprodRole
		}
	}
	return nil
}
