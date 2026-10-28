// Package source is the registry of the places Michel reads (OSV databases,
// enrichments, feeds) or offers (plugins, skills, MCP servers, references):
// the embedded catalog, the user's own entries, their consent to contact a
// host and the allow rule written for it.
package source

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Kind is the sort of a source.
type Kind string

const (
	KindOSV        Kind = "osv"
	KindEnrichment Kind = "enrichment"
	KindFeed       Kind = "feed"
	KindPlugin     Kind = "plugin"
	KindSkill      Kind = "skill"
	KindMCP        Kind = "mcp"
	KindReference  Kind = "reference"
)

// Kinds lists every kind, in display order.
var Kinds = []Kind{KindOSV, KindEnrichment, KindFeed, KindPlugin, KindSkill, KindMCP, KindReference}

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	for _, v := range Kinds {
		if k == v {
			return true
		}
	}
	return false
}

// prefixes maps a kind to the prefix of its keys.
var prefixes = map[Kind]string{
	KindOSV: "osv", KindEnrichment: "enrich", KindFeed: "feed", KindPlugin: "plugin",
	KindSkill: "skill", KindMCP: "mcp", KindReference: "ref",
}

// Origin tells who wrote an entry.
type Origin string

const (
	OriginCatalog Origin = "catalog"
	OriginUser    Origin = "user"
)

// State is the displayed state of an entry, computed, never stored.
type State string

const (
	StateOff            State = "off"
	StateWaitingConsent State = "waiting_consent"
	StateOn             State = "on"
	StateHidden         State = "hidden"
)

var (
	ErrNotFound        = errors.New("source not found")
	ErrCatalogEntry    = errors.New("this source comes from the catalog: it can be hidden, not deleted")
	ErrUserEntry       = errors.New("this source is one of yours: reset only applies to catalog sources")
	ErrInvalidKey      = errors.New("invalid source key")
	ErrInvalidConfig   = errors.New("invalid source settings")
	ErrInvalidEntry    = errors.New("invalid source")
	ErrConsentRequired = errors.New("this source contacts the network: it needs your consent")
	ErrInstalled       = errors.New("this source is installed: uninstall it first")
)

// ErrRuleShared refuses to forget an allow rule another enabled source needs.
type ErrRuleShared struct{ Key string }

func (e ErrRuleShared) Error() string {
	return fmt.Sprintf("the network rule is also used by %s, which is enabled", e.Key)
}

// Config holds the kind-specific settings: Catalog from the embedded catalog,
// User from the user. Reading merges them, User wins.
type Config struct {
	Catalog map[string]any `json:"catalog"`
	User    map[string]any `json:"user"`
}

// Merged returns Catalog overlaid by User.
func (c Config) Merged() map[string]any {
	out := make(map[string]any, len(c.Catalog)+len(c.User))
	for k, v := range c.Catalog {
		out[k] = v
	}
	for k, v := range c.User {
		out[k] = v
	}
	return out
}

func (c Config) value(key string) (any, bool) {
	if v, ok := c.User[key]; ok {
		return v, true
	}
	v, ok := c.Catalog[key]
	return v, ok
}

// Str returns the merged value of key as a string ("" when absent or not a string).
func (c Config) Str(key string) string {
	v, _ := c.value(key)
	s, _ := v.(string)
	return s
}

// Bool returns the merged value of key as a bool (false when absent).
func (c Config) Bool(key string) bool {
	v, _ := c.value(key)
	b, _ := v.(bool)
	return b
}

// List returns the merged value of key as a list of strings.
func (c Config) List(key string) []string {
	v, _ := c.value(key)
	switch l := v.(type) {
	case []string:
		return append([]string(nil), l...)
	case []any:
		out := make([]string, 0, len(l))
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// configKeys are the settings each kind accepts; other keys are refused.
var configKeys = map[Kind][]string{
	KindOSV:        {"ecosystem", "url"},
	KindEnrichment: {"format", "on_demand", "api_key_secret"},
	KindFeed:       {"format", "repo"},
	KindPlugin:     {"format", "tool", "run", "projects", "input", "repo"},
	KindSkill:      {"repo", "path", "pinned", "installed_sha", "install_dir", "license"},
	KindMCP:        {"repo", "pinned", "installed_sha", "launch", "license"},
	KindReference:  {"topics"},
}

// checkConfig refuses a key the kind does not know.
func checkConfig(kind Kind, m map[string]any) error {
	for k := range m {
		known := false
		for _, ok := range configKeys[kind] {
			if k == ok {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("%w: %q is not a setting of a %s source (use %s)", ErrInvalidConfig, k, kind, strings.Join(configKeys[kind], ", "))
		}
	}
	return nil
}

// Entry is one source of the registry.
type Entry struct {
	ID      string   `json:"id"`
	Key     string   `json:"key"`
	Kind    Kind     `json:"kind"`
	Origin  Origin   `json:"origin"`
	Name    string   `json:"name"`
	URL     string   `json:"url"`
	Hosts   []string `json:"hosts"`
	Purpose string   `json:"purpose"`
	Enabled bool     `json:"enabled"`
	Hidden  bool     `json:"hidden"`
	Config  Config   `json:"config"`
	Tech    []string `json:"tech"`
	// CatalogVersion is the version of the catalog that wrote the entry (0
	// for a user entry).
	CatalogVersion int `json:"catalog_version"`

	LastReadAt     time.Time `json:"last_read_at"`
	LastReadResult string    `json:"last_read_result"`
	LastReadError  string    `json:"last_read_error"`
	LastReadItems  int       `json:"last_read_items"`
	LastReadETag   string    `json:"last_read_etag"`

	Status    map[string]any `json:"status"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// State computes the displayed state. allowed says whether the policy has a
// network.allow rule for a host and purpose. An entry without host (plugin,
// reference) is never waiting for consent.
func (e Entry) State(allowed func(host, purpose string) bool) State {
	switch {
	case e.Hidden:
		return StateHidden
	case !e.Enabled:
		return StateOff
	}
	for _, h := range e.Hosts {
		if !allowed(h, e.Purpose) {
			return StateWaitingConsent
		}
	}
	return StateOn
}

var keyPattern = regexp.MustCompile(`^(osv|enrich|feed|plugin|skill|mcp|ref|discover)\.[a-z0-9][a-z0-9-]{0,63}$`)

// ValidKey reports whether k is a well-formed source key.
func ValidKey(k string) bool { return keyPattern.MatchString(k) }

// KeyFor builds the key of a user entry: the prefix of its kind and a slug of
// name (lowercase ASCII letters and digits, other runs become one hyphen).
func KeyFor(kind Kind, name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r)
			dash = false
		default:
			dash = true
		}
	}
	slug := b.String()
	if len(slug) > 64 {
		slug = strings.TrimRight(slug[:64], "-")
	}
	return prefixes[kind] + "." + slug
}

// NoteKey is the i18n key of the note of a catalog entry.
func NoteKey(key string) string {
	return "source.note." + strings.ReplaceAll(key, "-", "_")
}

// NewVersion reads the "new version available" mark of a repository status
// (skill, mcp, plugin): status.new_version is either {"from": ..., "to": ...}
// or the new version alone, From then being the pinned one. ok is false when
// the entry carries no such mark.
func (e Entry) NewVersion() (from, to string, ok bool) {
	switch v := e.Status["new_version"].(type) {
	case map[string]any:
		from, _ = v["from"].(string)
		to, _ = v["to"].(string)
	case string:
		from, to = e.Config.Str("pinned"), v
	}
	return from, to, to != ""
}
