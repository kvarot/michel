// Package serverrules holds the embedded, versioned rules Michel applies to
// the inventory of a server: risky PHP settings, upstream PHP advisories
// (judged on the version number) and end-of-life branches.
package serverrules

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"gopkg.in/yaml.v3"
)

// Version is the version of the embedded rules. It must equal the version:
// line of rules.yaml; bump both whenever a rule changes.
const Version = 1

//go:embed rules.yaml
var rulesYAML []byte

// ConfigRule is one risky PHP setting. Risky is "on", "off" or "empty".
// Mitigation marks a rule that only holds back advisories (listed in
// Mitigates, by id or alias): it never closes them. Key is the i18n prefix
// of its title and explanation.
type ConfigRule struct {
	ID             string   `yaml:"id"`
	Directive      string   `yaml:"directive"`
	Risky          string   `yaml:"risky"`
	Advised        string   `yaml:"advised"`
	Severity       string   `yaml:"severity"`
	MissingIsRisky bool     `yaml:"missing_is_risky"`
	Context        []string `yaml:"context"`
	Branches       []string `yaml:"branches"`
	Mitigates      []string `yaml:"mitigates"`
	Mitigation     bool     `yaml:"mitigation"`
	Key            string   `yaml:"key"`
}

// BranchFix is the first fixed version of a PHP branch.
type BranchFix struct {
	Branch string `yaml:"branch"`
	Fixed  string `yaml:"fixed"`
}

// UpstreamAdvisory is a flaw fixed by the PHP project itself.
type UpstreamAdvisory struct {
	ID          string      `yaml:"id"`
	Aliases     []string    `yaml:"aliases"`
	Severity    string      `yaml:"severity"`
	CVSS        float64     `yaml:"cvss"`
	Key         string      `yaml:"key"`
	Branches    []BranchFix `yaml:"branches"`
	Mitigations []string    `yaml:"mitigations"`
}

// Branch is a PHP branch ("8.1").
type Branch struct {
	Branch string `yaml:"branch"`
}

// Set is the parsed rule set.
type Set struct {
	Config   []ConfigRule       `yaml:"config"`
	Upstream []UpstreamAdvisory `yaml:"upstream"`
	EOL      []Branch           `yaml:"eol"`
}

type rulesFile struct {
	Version int `yaml:"version"`
	Set     `yaml:",inline"`
}

var (
	once   sync.Once
	parsed Set
	perr   error
)

// Rules returns the embedded rules, parsed and checked once. Callers must
// not modify the result.
func Rules() (Set, error) {
	once.Do(func() { parsed, perr = parse(rulesYAML) })
	return parsed, perr
}

func parse(raw []byte) (Set, error) {
	var f rulesFile
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return Set{}, fmt.Errorf("the embedded server rules are invalid: %w", err)
	}
	if f.Version != Version {
		return Set{}, fmt.Errorf("the embedded server rules have version %d, the code expects %d", f.Version, Version)
	}
	ids := map[string]bool{}
	for _, r := range f.Config {
		if r.ID == "" || r.Directive == "" || r.Key == "" || ids[r.ID] {
			return Set{}, fmt.Errorf("server rule %q is incomplete or duplicated", r.ID)
		}
		if !slices.Contains([]string{"on", "off", "empty"}, r.Risky) {
			return Set{}, fmt.Errorf("server rule %q has an unknown risky value %q", r.ID, r.Risky)
		}
		ids[r.ID] = true
	}
	for _, a := range f.Upstream {
		if a.ID == "" || a.Key == "" || len(a.Branches) == 0 {
			return Set{}, fmt.Errorf("server advisory %q is incomplete", a.ID)
		}
		for _, m := range a.Mitigations {
			if !ids[m] {
				return Set{}, fmt.Errorf("server advisory %q names the unknown rule %q", a.ID, m)
			}
		}
		for _, b := range a.Branches {
			if _, ok := parseVersion(b.Fixed); !ok || branchOf(b.Fixed) != b.Branch {
				return Set{}, fmt.Errorf("server advisory %q has a bad fix %q for branch %q", a.ID, b.Fixed, b.Branch)
			}
		}
	}
	return f.Set, nil
}
