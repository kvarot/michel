package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// AddAllowRule writes r under sovereignty.network.allow of the policy file at
// path, keeping its comments and key order. It returns false, and leaves the
// file untouched, when the rule is already there. The previous content is
// copied to <path>.bak, the new content replaces the file through a temporary
// file and a rename, and the file is read back and validated: when that fails
// the previous content is put back and the error returned. An absent file is
// created with only sovereignty.network.allow (Load merges it over the
// defaults).
func AddAllowRule(path string, r AllowRule) (bool, error) {
	n, err := AddAllowRules(path, r)
	return n > 0, err
}

// AddAllowRules writes the rules not already there in one edit of the file,
// with the same care as AddAllowRule: either all of them are written, or
// none (the file is left as it was). It returns how many it added.
func AddAllowRules(path string, rules ...AllowRule) (int, error) {
	added := 0
	_, err := editAllow(path, func(seq *yaml.Node) bool {
		added = 0
	next:
		for _, r := range rules {
			for _, item := range seq.Content {
				if sameRule(ruleOf(item), r) {
					continue next
				}
			}
			seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
				scalar("host"), scalar(r.Host), scalar("purpose"), scalar(r.Purpose),
			}})
			added++
		}
		if added > 0 {
			seq.Style = 0 // a flow list ("allow: []") becomes a block list
		}
		return added > 0
	}, true)
	if err != nil {
		return 0, err
	}
	return added, nil
}

// RemoveAllowRule removes r from sovereignty.network.allow of the policy file
// at path, with the same care as AddAllowRule. It returns false when the rule
// is not there (or the file does not exist).
func RemoveAllowRule(path string, r AllowRule) (bool, error) {
	return editAllow(path, func(seq *yaml.Node) bool {
		kept := seq.Content[:0:0]
		for _, item := range seq.Content {
			if !sameRule(ruleOf(item), r) {
				kept = append(kept, item)
			}
		}
		if len(kept) == len(seq.Content) {
			return false
		}
		seq.Content = kept
		if len(kept) == 0 {
			seq.Style = yaml.FlowStyle // "allow: []"
		}
		return true
	}, false)
}

func scalar(v string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v} }

func sameRule(a, b AllowRule) bool {
	return strings.EqualFold(a.Host, b.Host) && a.Purpose == b.Purpose
}

// ruleOf reads a {host, purpose} mapping node; anything else gives a zero rule.
func ruleOf(n *yaml.Node) AllowRule {
	var r AllowRule
	if n.Kind != yaml.MappingNode {
		return r
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		switch n.Content[i].Value {
		case "host":
			r.Host = n.Content[i+1].Value
		case "purpose":
			r.Purpose = n.Content[i+1].Value
		}
	}
	return r
}

// child returns the value node of key in the mapping m, creating it (as a
// mapping) when create is true. It refuses a key whose value is not a mapping.
func child(m *yaml.Node, key string, create bool) (*yaml.Node, error) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != key {
			continue
		}
		v := m.Content[i+1]
		if v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
			*v = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", LineComment: v.LineComment}
		}
		if v.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s is not a mapping", key)
		}
		return v, nil
	}
	if !create {
		return nil, nil
	}
	v := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	m.Content = append(m.Content, scalar(key), v)
	return v, nil
}

// allowSeq finds (or, with create, builds) the sovereignty.network.allow
// sequence of the document doc, with its key node. It returns nil when it is
// absent and create is false.
func allowSeq(doc *yaml.Node, create bool) (key, seq *yaml.Node, err error) {
	if len(doc.Content) == 0 {
		if !create {
			return nil, nil, nil
		}
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	root := doc.Content[0]
	if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
		*root = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", HeadComment: root.HeadComment}
	}
	if root.Kind != yaml.MappingNode {
		return nil, nil, errors.New("the policy file is not a mapping")
	}
	m := root
	for _, name := range []string{"sovereignty", "network"} {
		next, err := child(m, name, create)
		if err != nil || next == nil {
			return nil, nil, err
		}
		m = next
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != "allow" {
			continue
		}
		v := m.Content[i+1]
		if v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
			*v = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", LineComment: v.LineComment}
		}
		if v.Kind != yaml.SequenceNode {
			return nil, nil, errors.New("sovereignty.network.allow is not a list")
		}
		return m.Content[i], v, nil
	}
	if !create {
		return nil, nil, nil
	}
	k, v := scalar("allow"), &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	m.Content = append(m.Content, k, v)
	return k, v, nil
}

// placeComment keeps the line comment of "allow:" on its line: yaml.v3
// writes it there only when it sits on the key for a block list, and on the
// list itself for a flow list ("allow: [] # ...").
func placeComment(key, seq *yaml.Node) {
	c := key.LineComment
	if c == "" {
		c = seq.LineComment
	}
	key.LineComment, seq.LineComment = "", ""
	if seq.Style&yaml.FlowStyle != 0 {
		seq.LineComment = c
	} else {
		key.LineComment = c
	}
}

// editAllow applies change to the allow list of the file at path and writes
// the result when change reports a modification.
func editAllow(path string, change func(seq *yaml.Node) bool, create bool) (bool, error) {
	original, err := os.ReadFile(path)
	absent := errors.Is(err, fs.ErrNotExist)
	if err != nil && !absent {
		return false, fmt.Errorf("cannot read policy file %s: %w", path, err)
	}
	if absent && !create {
		return false, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(original, &doc); err != nil {
		return false, fmt.Errorf("cannot parse policy file %s: %w", path, err)
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode}
	}
	key, seq, err := allowSeq(&doc, create)
	if err != nil {
		return false, fmt.Errorf("cannot edit policy file %s: %w", path, err)
	}
	if seq == nil || !change(seq) {
		return false, nil
	}
	placeComment(key, seq)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return false, fmt.Errorf("cannot write policy file %s: %w", path, err)
	}
	if err := enc.Close(); err != nil {
		return false, fmt.Errorf("cannot write policy file %s: %w", path, err)
	}

	mode := fs.FileMode(0o600)
	if absent {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return false, fmt.Errorf("cannot create the folder of policy file %s: %w", path, err)
		}
	} else {
		if fi, err := os.Stat(path); err == nil {
			mode = fi.Mode().Perm()
		}
		if err := os.WriteFile(path+".bak", original, mode); err != nil {
			return false, fmt.Errorf("cannot write the backup %s.bak: %w", path, err)
		}
	}
	if err := writeAtomic(path, buf.Bytes(), mode); err != nil {
		return false, err
	}
	if err := reread(path); err != nil {
		var rerr error
		if absent {
			rerr = os.Remove(path)
		} else {
			rerr = writeAtomic(path, original, mode)
		}
		if rerr != nil {
			return false, fmt.Errorf("the edited policy file %s is invalid (%v) and could not be restored from %s.bak: %w", path, err, path, rerr)
		}
		return false, fmt.Errorf("the edited policy file %s is invalid, the previous content is back: %w", path, err)
	}
	return true, nil
}

// reread loads and validates the file the way Michel does at start-up.
func reread(path string) error {
	p, _, err := Load(path, "")
	if err != nil {
		return err
	}
	return Validate(p)
}

// writeAtomic writes data to a temporary file next to path, then renames it
// over path.
func writeAtomic(path string, data []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("cannot write policy file %s: %w", path, err)
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, mode)
	}
	if werr == nil {
		werr = os.Rename(name, path)
	}
	if werr != nil {
		os.Remove(name)
		return fmt.Errorf("cannot write policy file %s: %w", path, werr)
	}
	return nil
}
