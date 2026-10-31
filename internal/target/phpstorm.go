package target

import (
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const maxXMLBytes = 1 << 20

// node is a generic XML element. Only the attributes the parser asks for are
// ever read, so password attributes never leave this file.
type node struct {
	name     string
	attrs    map[string]string
	children []*node
}

func parseXMLFile(p string) (*node, error) {
	f, err := os.Open(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	dec := xml.NewDecoder(io.LimitReader(f, maxXMLBytes))
	root := &node{}
	stack := []*node{root}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &node{name: t.Name.Local, attrs: map[string]string{}}
			for _, a := range t.Attr {
				n.attrs[a.Name.Local] = a.Value
			}
			top := stack[len(stack)-1]
			top.children = append(top.children, n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return root, nil
}

func (n *node) walk(fn func(*node)) {
	fn(n)
	for _, c := range n.children {
		c.walk(fn)
	}
}

func (n *node) child(name string) *node {
	for _, c := range n.children {
		if c.name == name {
			return c
		}
	}
	return nil
}

// field reads a setting given either as an attribute or as a nested
// <option name="key" value="..."/>.
func (n *node) field(keys ...string) string {
	for _, k := range keys {
		if v := n.attrs[k]; v != "" {
			return v
		}
	}
	for _, c := range n.children {
		if c.name != "option" {
			continue
		}
		for _, k := range keys {
			if c.attrs["name"] == k && c.attrs["value"] != "" {
				return c.attrs["value"]
			}
		}
	}
	return ""
}

// ParsePhpStorm reads the SFTP servers declared in a project's .idea files:
// webServers.xml (host, port, user) and deployment.xml (the remote folder the
// project root is mapped to). Absent files give no candidate. Credentials of
// any kind are never read.
func ParsePhpStorm(projectRoot string) ([]Candidate, error) {
	idea := filepath.Join(projectRoot, ".idea")
	ws, err := parseXMLFile(filepath.Join(idea, "webServers.xml"))
	if err != nil {
		return nil, err
	}
	if ws == nil {
		return nil, nil
	}
	remote := map[string]string{}
	if dep, err := parseXMLFile(filepath.Join(idea, "deployment.xml")); err == nil && dep != nil {
		dep.walk(func(n *node) {
			if n.name != "paths" || n.attrs["name"] == "" {
				return
			}
			n.walk(func(m *node) {
				if m.name == "mapping" && isProjectRoot(m.attrs["local"]) && remote[n.attrs["name"]] == "" {
					remote[n.attrs["name"]] = m.attrs["deploy"]
				}
			})
		})
	}

	var out []Candidate
	ws.walk(func(n *node) {
		if n.name != "webServer" {
			return
		}
		ft := n.child("fileTransfer")
		if ft == nil || !strings.EqualFold(ft.field("accessType"), "SFTP") {
			return
		}
		host := ft.field("host")
		if host == "" {
			return
		}
		port := defaultSSHPort
		if p, err := strconv.Atoi(ft.field("port")); err == nil && p > 0 && p < 65536 {
			port = p
		}
		name := n.attrs["name"]
		if name == "" {
			name = host
		}
		out = append(out, Candidate{
			Alias: name, Host: host, Port: port,
			User:     ft.field("userName", "username", "user"),
			From:     []string{sourcePhpStorm},
			Projects: []CandidateLink{{RemoteDir: remote[name]}},
		})
	})
	return out, nil
}

func isProjectRoot(local string) bool {
	switch strings.TrimRight(local, "/") {
	case "$PROJECT_DIR$", ".", "":
		return true
	}
	return false
}
