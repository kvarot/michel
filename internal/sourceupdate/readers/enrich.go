package readers

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kvarot/michel/internal/enrich"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sourceupdate"
)

func init() { sourceupdate.Register(enrichReader{}) }

// enrichReader reads an enrichment entry by its format: the whole KEV list
// or EPSS file, or the on-demand sources (Vulnrichment, NVD, CIRCL) for the
// CVEs of the findings without a severity, within their per-run caps.
type enrichReader struct{}

func (enrichReader) Kinds() []source.Kind { return []source.Kind{source.KindEnrichment} }

func (enrichReader) Read(ctx context.Context, e source.Entry, deps sourceupdate.Deps) (sourceupdate.Result, error) {
	ed := enrich.Deps{Store: deps.Store, Audit: deps.Audit, Client: deps.Gateway.Client(policy.PurposeEnrich), Now: deps.Now}
	whole := func(read func(context.Context, enrich.Deps, string) (int, string, error)) (sourceupdate.Result, error) {
		n, etag, err := read(ctx, ed, e.LastReadETag)
		if errors.Is(err, enrich.ErrNotModified) {
			return sourceupdate.Result{Skipped: sourceupdate.SkipNotModified}, nil
		}
		if err != nil {
			return sourceupdate.Result{}, err
		}
		return sourceupdate.Result{Items: n, ETag: etag}, nil
	}
	switch f := strings.ToLower(e.Config.Str("format")); f {
	case "kev":
		return whole(enrich.ReadKEV)
	case "epss":
		return whole(enrich.ReadEPSS)
	case "vulnrichment":
		return onDemand(ctx, ed, enrich.Vulnrichment(), enrich.MaxVulnrichmentPerRun)
	case "nvd":
		key, err := apiKey(e, deps.Secrets)
		if err != nil {
			return sourceupdate.Result{}, err
		}
		return onDemand(ctx, ed, enrich.NVD(key), enrich.MaxNVDPerRun)
	case "circl":
		return onDemand(ctx, ed, enrich.CIRCL(), enrich.MaxCIRCLPerRun)
	default:
		return sourceupdate.Result{}, fmt.Errorf("source %s has an unknown enrichment format %q (use kev, epss, vulnrichment, nvd or circl)", e.Key, f)
	}
}

// apiKey reads the secret named by the entry's api_key_secret setting; a
// secret not set means no key. The value never reaches an error.
func apiKey(e source.Entry, secrets secret.Store) (string, error) {
	name := e.Config.Str("api_key_secret")
	if name == "" || secrets == nil {
		return "", nil
	}
	v, err := secrets.Get(name)
	if errors.Is(err, secret.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("cannot read the secret %s of source %s: %w", name, e.Key, err)
	}
	return strings.TrimSpace(string(v)), nil
}

// onDemand asks src about up to limit CVEs. A rate limit, or the read's time
// running out, keeps what was read and is not a failure; a run where every
// request failed is.
func onDemand(ctx context.Context, ed enrich.Deps, src enrich.OnDemand, limit int) (sourceupdate.Result, error) {
	fetched, notFound, failed, err := enrich.RunOnDemand(ctx, ed, src, limit)
	switch {
	case errors.Is(err, enrich.ErrRateLimited):
		return sourceupdate.Result{Items: fetched, Skipped: sourceupdate.SkipRateLimited}, nil
	case errors.Is(err, enrich.ErrOutOfTime):
		return sourceupdate.Result{Items: fetched, Skipped: sourceupdate.SkipPartial}, nil
	case err != nil:
		return sourceupdate.Result{}, err
	case failed > 0 && fetched+notFound == 0:
		return sourceupdate.Result{}, fmt.Errorf("all %d requests to %s failed", failed, src.Key())
	}
	return sourceupdate.Result{Items: fetched}, nil
}
