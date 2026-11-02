package digest

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

// CauseRolledBack is the cause stored on a server fix attempt that was
// undone after a failed step (the server is as before).
const CauseRolledBack = "rolled_back"

// ServerDigest is what happened on one active server in the window: findings
// that appeared, findings that went away, fixes that were undone. Counts
// only: never a version, a path or a setting.
type ServerDigest struct {
	Name       string `json:"name"`
	New        int    `json:"new"`
	Fixed      int    `json:"fixed"`
	RolledBack int    `json:"rolled_back"`
}

// servers lists the active servers touched in the window (a server with
// nothing to say is left out), sorted by name.
func (c computer) servers(ctx context.Context) ([]ServerDigest, error) {
	targets, err := target.NewRepo(c.s).List(ctx)
	if err != nil {
		return nil, err
	}
	since := c.since.UTC().Format(time.RFC3339)
	var out []ServerDigest
	for _, t := range targets {
		if !t.Active {
			continue
		}
		sd := ServerDigest{Name: scan.SanitizeText(t.Name)}
		if sd.New, err = countOf(ctx, c.s, `SELECT COUNT(*) FROM finding WHERE project_id = ? AND source_key = '' AND first_seen_at > ? AND status NOT IN ('gone','ignored')`, t.ID, since); err != nil {
			return nil, err
		}
		if sd.Fixed, err = countOf(ctx, c.s, `SELECT COUNT(*) FROM finding WHERE project_id = ? AND source_key = '' AND status = 'gone' AND status_changed_at > ?`, t.ID, since); err != nil {
			return nil, err
		}
		if sd.RolledBack, err = countOf(ctx, c.s, `SELECT COUNT(*) FROM fix_attempt WHERE project_id = ? AND state = 'failed' AND cause = ? AND updated_at > ?`, t.ID, CauseRolledBack, since); err != nil {
			return nil, err
		}
		if sd.New+sd.Fixed+sd.RolledBack > 0 {
			out = append(out, sd)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func countOf(ctx context.Context, s *store.Store, q string, args ...any) (int, error) {
	var n int
	if err := s.DB().QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("cannot read the servers: %w", err)
	}
	return n, nil
}

// serverLine is one server in the digest: its name and what happened.
func serverLine(lang i18n.Lang, s ServerDigest) string {
	var parts []string
	if s.New > 0 {
		parts = append(parts, i18n.N(lang, "digest.servers.new", s.New))
	}
	if s.Fixed > 0 {
		parts = append(parts, i18n.N(lang, "digest.servers.fixed", s.Fixed))
	}
	if s.RolledBack > 0 {
		parts = append(parts, i18n.N(lang, "digest.servers.rolled_back", s.RolledBack))
	}
	sep := ": "
	if lang == i18n.FR {
		sep = " : "
	}
	return s.Name + sep + strings.Join(parts, ", ")
}
