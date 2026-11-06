package gitrepo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

// ErrNoSkillsDir means the user's skills folder cannot be found.
var ErrNoSkillsDir = errors.New("cannot find the skills folder")

// NewDeps wires an installation the same way for the command line and the
// API: the archive client of the gateway (purpose source.repo), the data
// folder, the skills folder (DefaultSkillsDir) and the folders of the
// scanned projects, where Michel never writes. actor is the audit actor.
func NewDeps(ctx context.Context, st *store.Store, log *audit.Logger, gw *egress.Gateway, dataDir string, now func() time.Time, actor string) (Deps, error) {
	skills, err := DefaultSkillsDir()
	if err != nil {
		return Deps{}, fmt.Errorf("%w: %v", ErrNoSkillsDir, err)
	}
	projects, err := project.NewRepo(st).List(ctx)
	if err != nil {
		return Deps{}, err
	}
	var forbidden []string
	for _, p := range projects {
		if p.Path != "" {
			forbidden = append(forbidden, p.Path)
		}
	}
	return Deps{Repo: source.NewRepo(st), Audit: log, Client: gw.Client(policy.PurposeRepo), DataDir: dataDir, SkillsDir: skills,
		Forbidden: forbidden, Now: now, Actor: actor}, nil
}

// WithoutNewVersion is a repository status without its new version mark,
// once that version is installed.
func WithoutNewVersion(st map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range st {
		if k != "new_version" {
			out[k] = v
		}
	}
	out["new_version_available"] = false
	return out
}
