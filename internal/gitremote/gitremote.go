// Package gitremote reads the address of a Git remote and builds the link that
// asks for a merge on the site. It is pure: no exec, no network.
//
// The address comes from a project's .git/config, so it is untrusted. What is
// not understood is refused with one fixed error that never carries the value,
// because the value may hold a password. A secret in the address is dropped
// here and only its presence is remembered. The provider is an exact match on
// six hosts, and the link is built from validated parts on three fixed origins:
// a strange address gives no link, never an approximate one.
package gitremote

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrUnsupported is the only error of Parse. It never holds the value read.
var ErrUnsupported = errors.New("gitremote: unsupported address")

// Provider names the site a remote lives on.
type Provider string

const (
	GitHub    Provider = "github"
	Bitbucket Provider = "bitbucket"
	GitLab    Provider = "gitlab"
	Other     Provider = "other"
	Local     Provider = "local"
)

// Scheme values of Remote.
const (
	schemeHTTPS = "https"
	schemeSSH   = "ssh"
	schemeSCP   = "scp"
	schemeFile  = "file"
)

// Remote is an address once read, without any secret.
type Remote struct {
	Clean         string   // the address to use and to compare, without secret
	Host          string   // lower case; empty for Local
	Port          int      // the port written in the address, 0 if none
	Scheme        string   // "https", "ssh", "scp" or "file"
	Path          string   // "owner/repo.git", no leading slash; empty for Local
	Provider      Provider // exact match on the host
	HadCredential bool     // a secret was in the address and was dropped
}

const (
	maxAddress = 4096
	maxHost    = 253
	maxParts   = 20
	httpsPort  = 443
	gitSuffix  = ".git"
	localLabel = "dépôt local"
)

var (
	hostRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
	userRe   = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$`)
	partRe   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$`)
	portRe   = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)
	branchRe = regexp.MustCompile(`^michel/fix-[0-9a-z]{8,26}$`)
)

// providers is the whole recognition: strict equality on the host, never a
// substring.
var providers = map[string]Provider{
	"github.com":           GitHub,
	"ssh.github.com":       GitHub,
	"bitbucket.org":        Bitbucket,
	"altssh.bitbucket.org": Bitbucket,
	"gitlab.com":           GitLab,
	"altssh.gitlab.com":    GitLab,
}

// uriSchemes are the words that, before a colon and without a user, mean a URI
// to a browser or a transport to Git, not a host. "javascript:alert" has the
// shape of host:path.
var uriSchemes = map[string]bool{
	"about": true, "blob": true, "data": true, "ext": true, "fd": true,
	"file": true, "ftp": true, "ftps": true, "git": true, "http": true,
	"https": true, "javascript": true, "ssh": true, "vbscript": true,
}

// Parse reads a remote address. Anything else than https, ssh and the scp form
// [user@]host:path gives ErrUnsupported. A local address does too, unless
// allowLocal: the local transport runs the hooks of the target (R28).
func Parse(raw string, allowLocal bool) (Remote, error) {
	if raw == "" || len(raw) > maxAddress || !printable(raw) {
		return Remote{}, ErrUnsupported
	}
	if isLocal(raw) {
		if !allowLocal {
			return Remote{}, ErrUnsupported
		}
		return parseLocal(raw)
	}
	// ASCII before any lower-casing: strings.ToLower folds U+0130 onto "i" and
	// would read a look-alike as github.com. ? and # end an authority for Git.
	if !ascii(raw) || strings.ContainsAny(raw, `\?#`) {
		return Remote{}, ErrUnsupported
	}
	if rest, ok := strings.CutPrefix(raw, "https://"); ok {
		return parseHTTPS(rest)
	}
	if rest, ok := strings.CutPrefix(raw, "ssh://"); ok {
		return parseSSH(rest)
	}
	if strings.Contains(raw, "://") {
		return Remote{}, ErrUnsupported
	}
	return parseSCP(raw)
}

// parseHTTPS: everything before the @ is dropped and counted as a secret, even
// a value that looks like a host. Port 443 only: the authorizing proxy takes
// nothing else.
func parseHTTPS(rest string) (Remote, error) {
	authority, path, ok := strings.Cut(rest, "/")
	if !ok {
		return Remote{}, ErrUnsupported
	}
	credential := false
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority, credential = authority[at+1:], true
	}
	host, port, ok := hostPort(authority)
	if !ok || (port != 0 && port != httpsPort) || !validPath(path) {
		return Remote{}, ErrUnsupported
	}
	return Remote{
		Clean:         "https://" + withPort(host, port) + "/" + path,
		Host:          host,
		Port:          port,
		Scheme:        schemeHTTPS,
		Path:          path,
		Provider:      providerOf(host),
		HadCredential: credential,
	}, nil
}

// parseSSH keeps the user, which is part of the address, and drops a password.
func parseSSH(rest string) (Remote, error) {
	authority, path, ok := strings.Cut(rest, "/")
	if !ok {
		return Remote{}, ErrUnsupported
	}
	user, credential := "", false
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		user, _, credential = strings.Cut(authority[:at], ":")
		authority = authority[at+1:]
		if !userRe.MatchString(user) {
			return Remote{}, ErrUnsupported
		}
	}
	host, port, ok := hostPort(authority)
	if !ok || !validPath(path) {
		return Remote{}, ErrUnsupported
	}
	clean := "ssh://"
	if user != "" {
		clean += user + "@"
	}
	return Remote{
		Clean:         clean + withPort(host, port) + "/" + path,
		Host:          host,
		Port:          port,
		Scheme:        schemeSSH,
		Path:          path,
		Provider:      providerOf(host),
		HadCredential: credential,
	}, nil
}

// parseSCP stays scp: git@host:a/b and ssh://git@host/a/b do not always name
// the same path on a self-hosted server. The first colon ends the host, as in
// Git; a host of one letter is a Windows path.
func parseSCP(raw string) (Remote, error) {
	left, path, ok := strings.Cut(raw, ":")
	if !ok {
		return Remote{}, ErrUnsupported
	}
	user, host, hasUser := "", left, false
	if at := strings.LastIndexByte(left, '@'); at >= 0 {
		user, host, hasUser = left[:at], left[at+1:], true
		if !userRe.MatchString(user) {
			return Remote{}, ErrUnsupported
		}
	}
	host = strings.ToLower(host)
	if len(host) == 1 || !validHost(host) || (!hasUser && uriSchemes[host]) || !validPath(path) {
		return Remote{}, ErrUnsupported
	}
	clean := host + ":" + path
	if hasUser {
		clean = user + "@" + clean
	}
	return Remote{
		Clean:    clean,
		Host:     host,
		Scheme:   schemeSCP,
		Path:     path,
		Provider: providerOf(host),
	}, nil
}

func isLocal(raw string) bool {
	if strings.HasPrefix(raw, "file:///") || strings.HasPrefix(raw, "/") {
		return true
	}
	return hasDrive(raw)
}

// hasDrive tells a Windows absolute path; C:demo is relative and is not one.
func hasDrive(raw string) bool {
	if len(raw) < 3 || raw[1] != ':' || (raw[2] != '/' && raw[2] != '\\') {
		return false
	}
	c := raw[0] | 0x20
	return c >= 'a' && c <= 'z'
}

// parseLocal keeps the address as read. Only tests and the trial build get
// here, so the parts stay free, within what a path may safely hold.
func parseLocal(raw string) (Remote, error) {
	rest := strings.TrimPrefix(raw, "file:///")
	if strings.HasPrefix(rest, "//") || strings.ContainsAny(rest, "?#%") {
		return Remote{}, ErrUnsupported
	}
	if hasDrive(rest) {
		rest = rest[2:]
	}
	named := false
	for _, part := range strings.FieldsFunc(rest, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == "." || part == ".." {
			return Remote{}, ErrUnsupported
		}
		named = true
	}
	if !named {
		return Remote{}, ErrUnsupported
	}
	return Remote{Clean: raw, Scheme: schemeFile, Provider: Local}, nil
}

// hostPort splits host[:port], lower-cases the host and validates both.
func hostPort(authority string) (string, int, bool) {
	host, digits, hasPort := strings.Cut(authority, ":")
	host = strings.ToLower(host)
	if !validHost(host) {
		return "", 0, false
	}
	if !hasPort {
		return host, 0, true
	}
	if !portRe.MatchString(digits) {
		return "", 0, false
	}
	port, err := strconv.Atoi(digits)
	if err != nil || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

// validHost takes a DNS name or an IPv4 address. A last label of digits can
// only be an IPv4 address: 2130706433 or 999.1.1.1 is not a name.
func validHost(host string) bool {
	if len(host) > maxHost || !hostRe.MatchString(host) {
		return false
	}
	last := host[strings.LastIndexByte(host, '.')+1:]
	if strings.Trim(last, "0123456789") != "" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Is4()
}

func validPath(path string) bool {
	parts := strings.Split(path, "/")
	if len(parts) > maxParts {
		return false
	}
	for _, part := range parts {
		if !partRe.MatchString(part) || strings.Contains(part, "..") {
			return false
		}
	}
	return true
}

func withPort(host string, port int) string {
	if port == 0 {
		return host
	}
	return host + ":" + strconv.Itoa(port)
}

func providerOf(host string) Provider {
	if p, ok := providers[host]; ok {
		return p
	}
	return Other
}

// printable refuses invalid UTF-8, spaces and control or format characters.
func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == ' ' || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// ID identifies the address, without its secret, for comparison and storage.
func (r Remote) ID() string {
	sum := sha256.Sum256([]byte(r.Clean))
	return hex.EncodeToString(sum[:])
}

// Display is what the page shows: host/owner/repo, never an absolute path.
func (r Remote) Display() string {
	if r.Provider == Local {
		return localLabel
	}
	return r.Host + "/" + strings.TrimSuffix(r.Path, gitSuffix)
}

// MergeURL builds the link asking for a merge of a michel/fix-… branch, on one
// of three fixed origins. It is empty for a site it does not know, and when a
// part is not valid. Every part is checked again here: the link goes into a page.
func MergeURL(r Remote, branch string) string {
	if !branchRe.MatchString(branch) || !validPath(r.Path) {
		return ""
	}
	repo := strings.TrimSuffix(r.Path, gitSuffix)
	parts := strings.Count(repo, "/") + 1
	switch r.Provider {
	case GitHub:
		if parts == 2 {
			return "https://github.com/" + repo + "/pull/new/" + branch
		}
	case Bitbucket:
		if parts == 2 {
			return "https://bitbucket.org/" + repo + "/pull-requests/new?source=" + branch + "&t=1"
		}
	case GitLab:
		if parts >= 2 && parts <= maxParts {
			return "https://gitlab.com/" + repo + "/-/merge_requests/new?merge_request%5Bsource_branch%5D=" + branch
		}
	}
	return ""
}
