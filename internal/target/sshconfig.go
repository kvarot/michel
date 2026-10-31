package target

import (
	"bufio"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	sourceSSHConfig = "ssh_config"
	sourcePhpStorm  = "phpstorm"
	maxIncludeDepth = 2
	maxConfigBytes  = 256 << 10
	defaultSSHPort  = 22
)

// Candidate is a server found on the workstation, not yet tracked.
type Candidate struct {
	Alias string
	Host  string
	Port  int
	User  string
	// IdentityFile is a path relative to HOME ("~/.ssh/id_ed25519") or a bare
	// file name; never an absolute path of this machine, never key content.
	IdentityFile string
	From         []string
	Projects     []CandidateLink
	// Known is true when a tracked server already has this host, port and user.
	Known bool
}

// CandidateLink says that a project uses the candidate, and where it lives.
type CandidateLink struct {
	ProjectID string
	RemoteDir string
}

// ParseSSHConfig reads an ssh client configuration. Host blocks with wildcard
// or negated patterns are skipped. Include directives are not followed here
// (there is no HOME to resolve them against); Discover follows them.
func ParseSSHConfig(r io.Reader) ([]Candidate, error) {
	return parseSSHConfig(r, "", 0)
}

// parseSSHConfig parses r; with a non-empty home, Include directives are
// followed while depth < maxIncludeDepth.
func parseSSHConfig(r io.Reader, home string, depth int) ([]Candidate, error) {
	var out []Candidate
	type block struct {
		aliases []string
		host    string
		user    string
		port    int
		ident   string
	}
	var cur *block
	flush := func() {
		if cur == nil {
			return
		}
		for _, a := range cur.aliases {
			host := cur.host
			if host == "" {
				host = a
			}
			port := cur.port
			if port == 0 {
				port = defaultSSHPort
			}
			out = append(out, Candidate{
				Alias: a, Host: host, Port: port, User: cur.user,
				IdentityFile: relIdentity(cur.ident, home),
				From:         []string{sourceSSHConfig},
			})
		}
		cur = nil
	}

	sc := bufio.NewScanner(io.LimitReader(r, maxConfigBytes))
	sc.Buffer(make([]byte, 0, 64<<10), maxConfigBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val := splitDirective(line)
		switch strings.ToLower(key) {
		case "host":
			flush()
			var aliases []string
			for _, p := range strings.Fields(val) {
				p = strings.Trim(p, `"`)
				if p == "" || strings.ContainsAny(p, "*?!") {
					continue
				}
				aliases = append(aliases, p)
			}
			cur = &block{aliases: aliases}
		case "match":
			flush()
		case "include":
			if home == "" || depth >= maxIncludeDepth {
				continue
			}
			flush()
			for _, pat := range strings.Fields(val) {
				inc, _ := followInclude(strings.Trim(pat, `"`), home, depth+1)
				out = append(out, inc...)
			}
		case "hostname":
			if cur != nil {
				cur.host = unquote(val)
			}
		case "user":
			if cur != nil {
				cur.user = unquote(val)
			}
		case "port":
			if cur != nil {
				if n, err := strconv.Atoi(unquote(val)); err == nil && n > 0 && n < 65536 {
					cur.port = n
				}
			}
		case "identityfile":
			if cur != nil && cur.ident == "" {
				cur.ident = unquote(val)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
	return out, nil
}

// followInclude parses the files an Include pattern matches. A missing file
// is ignored.
func followInclude(pattern, home string, depth int) ([]Candidate, error) {
	switch {
	case strings.HasPrefix(pattern, "~/"):
		pattern = filepath.Join(home, pattern[2:])
	case !filepath.IsAbs(pattern):
		pattern = filepath.Join(home, ".ssh", pattern)
	}
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, nil
	}
	var out []Candidate
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		cs, err := parseSSHConfig(fh, home, depth)
		fh.Close()
		if err == nil {
			out = append(out, cs...)
		}
	}
	return out, nil
}

// splitDirective splits "Key value" or "Key=value".
func splitDirective(line string) (string, string) {
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return line, ""
	}
	return line[:i], strings.TrimLeft(strings.TrimSpace(line[i:]), "= \t")
}

func unquote(s string) string { return strings.Trim(strings.TrimSpace(s), `"`) }

// relIdentity keeps an identity file path relative to HOME, or only its base
// name when it lives elsewhere.
func relIdentity(p, home string) string {
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, "~/") {
		return p
	}
	if home != "" {
		if rel, err := filepath.Rel(home, p); err == nil && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel) {
			return "~/" + filepath.ToSlash(rel)
		}
	}
	return path.Base(strings.ReplaceAll(p, `\`, "/"))
}
