package readers

import (
	"context"
	"errors"
	"fmt"

	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sourceupdate"
)

func init() { sourceupdate.Register(osvReader{}) }

// osvReader downloads the offline database of an osv entry's ecosystem.
type osvReader struct{}

func (osvReader) Kinds() []source.Kind { return []source.Kind{source.KindOSV} }

func (osvReader) Read(ctx context.Context, e source.Entry, deps sourceupdate.Deps) (sourceupdate.Result, error) {
	eco := e.Config.Str("ecosystem")
	if eco == "" {
		return sourceupdate.Result{}, fmt.Errorf("source %s has no ecosystem setting", e.Key)
	}
	if deps.OSVRoot == "" {
		return sourceupdate.Result{}, errors.New("no folder for the offline databases (db.osv_path in the policy)")
	}
	_, n, err := osvdb.UpdateEcosystem(ctx, deps.OSVRoot, deps.Gateway.Client(policy.PurposeOSV), eco, deps.Now)
	if errors.Is(err, osvdb.ErrNotModified) {
		return sourceupdate.Result{Skipped: sourceupdate.SkipNotModified}, nil
	}
	if err != nil {
		return sourceupdate.Result{}, err
	}
	return sourceupdate.Result{Items: n}, nil
}
