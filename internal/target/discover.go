package target

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/kvarot/michel/internal/project"
)

func candidateKey(host string, port int, user string) string {
	if port == 0 {
		port = defaultSSHPort
	}
	return host + ":" + strconv.Itoa(port) + ":" + user
}

// Discover lists the servers found in HOME/.ssh/config and in the PhpStorm
// deployment files of the given projects, merged by host, port and user.
// Servers already tracked are flagged Known. It only reads.
func Discover(ctx context.Context, home string, projects []project.Project, existing []Target) ([]Candidate, error) {
	var all []Candidate

	if home != "" {
		f, err := os.Open(filepath.Join(home, ".ssh", "config"))
		switch {
		case err == nil:
			cs, perr := parseSSHConfig(f, home, 0)
			f.Close()
			if perr != nil {
				return nil, perr
			}
			all = append(all, cs...)
		case !errors.Is(err, fs.ErrNotExist):
			return nil, err
		}
	}

	for _, p := range projects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cs, err := ParsePhpStorm(p.Path)
		if err != nil {
			continue // a broken file in one project must not hide the others
		}
		for _, c := range cs {
			for i := range c.Projects {
				c.Projects[i].ProjectID = p.ID
			}
			all = append(all, c)
		}
	}

	byKey := map[string]*Candidate{}
	var order []string
	for _, c := range all {
		k := candidateKey(c.Host, c.Port, c.User)
		m, ok := byKey[k]
		if !ok {
			c := c
			byKey[k] = &c
			order = append(order, k)
			continue
		}
		if m.IdentityFile == "" {
			m.IdentityFile = c.IdentityFile
		}
		for _, s := range c.From {
			if !hasString(m.From, s) {
				m.From = append(m.From, s)
			}
		}
		for _, l := range c.Projects {
			if !hasLink(m.Projects, l) {
				m.Projects = append(m.Projects, l)
			}
		}
	}

	known := map[string]bool{}
	for _, t := range existing {
		known[candidateKey(t.Host, t.Port, t.User)] = true
	}
	out := make([]Candidate, 0, len(order))
	for _, k := range order {
		c := *byKey[k]
		c.Known = known[k]
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Alias != out[j].Alias {
			return out[i].Alias < out[j].Alias
		}
		return out[i].Host < out[j].Host
	})
	return out, nil
}

func hasString(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func hasLink(l []CandidateLink, x CandidateLink) bool {
	for _, y := range l {
		if y == x {
			return true
		}
	}
	return false
}
