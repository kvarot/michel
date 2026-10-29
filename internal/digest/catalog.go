package digest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	srcreg "github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

// NewVersion is a repository source (skill, MCP server, plugin) with a newer
// version than the one installed.
type NewVersion struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
}

// Catalog is the state of the sources after the last "michel source
// update": only the entries an update has touched count, so a user who never
// runs it gets no catalog line. Every list holds source keys.
type Catalog struct {
	// Updated counts the enabled sources whose last read went through.
	Updated        int          `json:"updated"`
	Failed         []string     `json:"failed"`
	WaitingConsent []string     `json:"waiting_consent"`
	Unreachable    []string     `json:"unreachable"`
	NewVersions    []NewVersion `json:"new_versions"`
	DiscoverNew    int          `json:"discover_new"`
	// UpdatedAt is the latest successful read.
	UpdatedAt time.Time `json:"updated_at"`
	// Silent: everything is current and there is nothing new to say.
	Silent bool `json:"silent"`
}

// catalogOf reads the registry. allowed, when not nil, decides which
// entries wait for consent (the policy may have changed since the update);
// else the last read's result does.
func catalogOf(ctx context.Context, s *store.Store, allowed func(host, purpose string) bool) (Catalog, error) {
	c := Catalog{Failed: []string{}, WaitingConsent: []string{}, Unreachable: []string{}, NewVersions: []NewVersion{}}
	list, err := srcreg.NewRepo(s).List(ctx, "", false)
	if err != nil {
		return Catalog{}, err
	}
	for _, e := range list {
		if from, to, ok := e.NewVersion(); ok {
			c.NewVersions = append(c.NewVersions, NewVersion{Key: e.Key, Name: scan.SanitizeText(e.Name),
				From: scan.SanitizeText(from), To: scan.SanitizeText(to)})
		}
		if !e.Enabled || e.LastReadResult == "" {
			continue
		}
		waiting := e.LastReadResult == "waiting_consent"
		if allowed != nil {
			waiting = e.State(allowed) == srcreg.StateWaitingConsent
		}
		switch {
		case waiting:
			c.WaitingConsent = append(c.WaitingConsent, e.Key)
		case e.LastReadResult == "ok":
			c.Updated++
			if e.LastReadAt.After(c.UpdatedAt) {
				c.UpdatedAt = e.LastReadAt.UTC()
			}
		case e.LastReadResult == "unreachable":
			c.Unreachable = append(c.Unreachable, e.Key)
		case e.LastReadResult == "error" || e.LastReadResult == "denied":
			c.Failed = append(c.Failed, e.Key)
		}
	}
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM discovery WHERE state = 'new'`).Scan(&c.DiscoverNew); err != nil {
		return Catalog{}, fmt.Errorf("cannot read the discoveries: %w", err)
	}
	c.Silent = len(c.Failed)+len(c.WaitingConsent)+len(c.Unreachable)+len(c.NewVersions) == 0 && c.DiscoverNew == 0
	return c, nil
}

// CatalogLine is the one-sentence summary of c in lang (the digest's
// catalog line, also shown on the Today page).
func CatalogLine(lang i18n.Lang, c Catalog) string {
	var parts []string
	if c.Updated > 0 {
		parts = append(parts, i18n.N(lang, "digest.catalog.updated", c.Updated))
	}
	if len(c.Failed) > 0 {
		parts = append(parts, i18n.N(lang, "digest.catalog.failed", len(c.Failed), strings.Join(c.Failed, ", ")))
	}
	if len(c.Unreachable) > 0 {
		parts = append(parts, i18n.N(lang, "digest.catalog.unreachable", len(c.Unreachable), strings.Join(c.Unreachable, ", ")))
	}
	if len(c.WaitingConsent) > 0 {
		parts = append(parts, i18n.N(lang, "digest.catalog.waiting", len(c.WaitingConsent), strings.Join(c.WaitingConsent, ", ")))
	}
	for _, v := range c.NewVersions {
		parts = append(parts, i18n.T(lang, "digest.catalog.new_version", v.Name))
	}
	if c.DiscoverNew > 0 {
		parts = append(parts, i18n.N(lang, "digest.catalog.discover", c.DiscoverNew))
	}
	return i18n.T(lang, "digest.catalog.line", strings.Join(parts, ", "))
}
