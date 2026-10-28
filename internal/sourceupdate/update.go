// Package sourceupdate reads every enabled source of the registry once, in a
// fixed order (spec § 8.1): the OSV databases, the enrichments (KEV, EPSS,
// then on demand) followed by enrich.Apply, the feeds, the GitHub status of
// the skills, MCP servers and plugins, then discovery.
//
// The readers are registered by the adapter packages under
// internal/sourceupdate/readers, so this package does not depend on them.
// An entry still waiting for consent is never read and makes no network
// attempt. A failed entry is recorded and the run goes on. Every entry read
// or skipped is one source.read audit event, which never holds content.
package sourceupdate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/enrich"
	"github.com/kvarot/michel/internal/feed"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

// Reasons a read is skipped (Result.Skipped).
const (
	// SkipNotModified: the source answered that nothing changed since the
	// last read (304); the stored data is current.
	SkipNotModified = "not_modified"
	// SkipRateBudget: the GitHub request budget of this update is spent;
	// the next update goes on.
	SkipRateBudget = "rate budget"
	// SkipRateLimited: the source refused more requests for now; what was
	// read before is kept.
	SkipRateLimited = "rate limited"
	// SkipNoReader: this Michel cannot read that kind of source yet.
	SkipNoReader = "no reader"
	// SkipOff: the entry is disabled.
	SkipOff = "off"
	// SkipNoRepoConsent: a plugin's repository status needs a network rule
	// for api.github.com (purpose source.repo) that no consent gave yet.
	SkipNoRepoConsent = "no repo consent"
)

// Results stored on an entry (last_read_result) and in source.read events.
const (
	ResultOK             = "ok"
	ResultError          = "error"
	ResultDenied         = "denied"
	ResultUnreachable    = "unreachable"
	ResultSkipped        = "skipped"
	ResultWaitingConsent = "waiting_consent"
)

// GitHub request budgets of one update: the public limit is 60 an hour
// without a token.
const (
	BudgetWithoutToken = 50
	BudgetWithToken    = 500
)

// Bounds of one entry's read.
const (
	OSVTimeout   = 15 * time.Minute
	OtherTimeout = 5 * time.Minute
)

// maxErrorRunes bounds the error text stored on an entry and in the audit.
const maxErrorRunes = 500

// ErrSomeFailed means at least one entry could not be read (or enrich.Apply
// failed); the report says which.
var ErrSomeFailed = errors.New("some sources could not be read")

// Reader reads the entries of its kinds.
type Reader interface {
	Kinds() []source.Kind
	Read(ctx context.Context, e source.Entry, deps Deps) (Result, error)
}

// Result is what one read gave. Status, when not nil, replaces the entry's
// status (repository readers). Skipped is "" for a read, else one of the
// Skip* reasons. A rate-limited read may still carry Items.
type Result struct {
	Items   int
	ETag    string
	Status  map[string]any
	Skipped string
}

// Budget is the GitHub request budget shared by the readers of one update.
type Budget struct {
	mu        sync.Mutex
	Remaining int
}

// Take spends n requests and reports whether they were available; nothing is
// spent when they are not.
func (b *Budget) Take(n int) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Remaining < n {
		return false
	}
	b.Remaining -= n
	return true
}

func (b *Budget) empty() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Remaining <= 0
}

// Deps are the collaborators of a run. Every request goes through Gateway.
type Deps struct {
	Store   *store.Store
	Repo    *source.Repo
	Audit   *audit.Logger
	Gateway *egress.Gateway
	Secrets secret.Store
	OSVRoot string
	Now     func() time.Time
	Budget  *Budget
	// Actor is the audit actor ("cli" when empty).
	Actor string
}

// NewVersion is a repository source with a newer version than the pinned one.
type NewVersion struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
}

// ApplyResult is what enrich.Apply changed on the findings.
type ApplyResult struct {
	Ran        bool `json:"ran"`
	Updated    int  `json:"updated"`
	NowKEV     int  `json:"now_kev"`
	Superseded int  `json:"superseded"`
}

// Report is the outcome of a run, entry keys in run order.
type Report struct {
	// Order lists every key the run handled, in run order.
	Order          []string          `json:"order"`
	Updated        []string          `json:"updated"`
	Skipped        []string          `json:"skipped"`
	WaitingConsent []string          `json:"waiting_consent"`
	Failed         []string          `json:"failed"`
	Items          map[string]int    `json:"items"`
	SkipReasons    map[string]string `json:"skip_reasons"`
	// Errors maps a failed key to its error, in English.
	Errors      map[string]string `json:"errors"`
	NewVersions []NewVersion      `json:"new_versions"`
	DiscoverNew int               `json:"discover_new"`
	Apply       ApplyResult       `json:"apply"`
	ApplyError  string            `json:"apply_error,omitempty"`
}

var (
	regMu    sync.Mutex
	registry = map[source.Kind]Reader{}
)

// Register makes r the reader of its kinds. It panics when a kind already
// has a reader: two adapters for one kind is a programming error.
func Register(r Reader) {
	regMu.Lock()
	defer regMu.Unlock()
	for _, k := range r.Kinds() {
		if _, dup := registry[k]; dup {
			panic(fmt.Sprintf("sourceupdate: kind %s already has a reader", k))
		}
		registry[k] = r
	}
}

func readerOf(k source.Kind) (Reader, bool) {
	regMu.Lock()
	defer regMu.Unlock()
	r, ok := registry[k]
	return r, ok
}

// Phases of a run, in order.
const (
	phaseOSV = iota
	phaseEnrich
	phaseFeed
	phaseRepo
	phaseDiscover
	phaseOther
)

func phaseOf(e source.Entry) int {
	if strings.HasPrefix(e.Key, "discover.") {
		return phaseDiscover
	}
	switch e.Kind {
	case source.KindOSV:
		return phaseOSV
	case source.KindEnrichment:
		return phaseEnrich
	case source.KindFeed:
		return phaseFeed
	case source.KindSkill, source.KindMCP, source.KindPlugin:
		return phaseRepo
	}
	return phaseOther
}

// usesGitHubBudget: the repository and discovery reads share the budget.
func usesGitHubBudget(e source.Entry) bool {
	p := phaseOf(e)
	return p == phaseRepo || p == phaseDiscover
}

// order sorts entries by phase, then catalog order (KEV, EPSS, Vulnrichment,
// NVD, CIRCL; Packagist, npm...), user entries last in key order.
func order(entries []source.Entry) error {
	cat, _, err := source.Catalog()
	if err != nil {
		return err
	}
	pos := map[string]int{}
	for i, c := range cat {
		pos[c.Key] = i
	}
	rank := func(e source.Entry) int {
		if i, ok := pos[e.Key]; ok {
			return i
		}
		return len(cat)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if pa, pb := phaseOf(a), phaseOf(b); pa != pb {
			return pa < pb
		}
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra < rb
		}
		return a.Key < b.Key
	})
	return nil
}

// Run reads the entries named by keys (every entry when keys is empty), of
// kind when kind is not "". An unknown key fails the run before any read
// with source.ErrNotFound. Without keys, disabled entries and kinds without
// a reader are left out. The error is ErrSomeFailed when an entry failed.
func Run(ctx context.Context, deps Deps, keys []string, kind source.Kind) (Report, error) {
	rep := Report{Order: []string{}, Updated: []string{}, Skipped: []string{}, WaitingConsent: []string{}, Failed: []string{}, Items: map[string]int{},
		SkipReasons: map[string]string{}, Errors: map[string]string{}, NewVersions: []NewVersion{}}
	if deps.Actor == "" {
		deps.Actor = "cli"
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	var entries []source.Entry
	if len(keys) > 0 {
		seen := map[string]bool{}
		for _, k := range keys {
			if seen[k] {
				continue
			}
			seen[k] = true
			e, err := deps.Repo.Get(ctx, k)
			if err != nil {
				return rep, err
			}
			if kind != "" && e.Kind != kind {
				continue
			}
			entries = append(entries, e)
		}
	} else {
		all, err := deps.Repo.List(ctx, kind, false)
		if err != nil {
			return rep, err
		}
		for _, e := range all {
			if _, ok := readerOf(e.Kind); ok && e.Enabled {
				entries = append(entries, e)
			}
		}
	}
	if err := order(entries); err != nil {
		return rep, err
	}
	allowed := func(host, purpose string) bool {
		ok, _ := deps.Gateway.Allowed(host, purpose)
		return ok
	}
	// The feed items past their retention go once per run, whichever
	// sources this run reads: those of a source no longer read go too.
	if _, err := feed.NewRepo(deps.Store).Purge(ctx, deps.Now()); err != nil {
		return rep, err
	}
	enrichRead, applied := false, false
	failed := false
	for _, e := range entries {
		if !applied && phaseOf(e) > phaseEnrich {
			applied = true
			if enrichRead {
				failed = applyEnrichment(ctx, deps, &rep) || failed
			}
		}
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		rep.Order = append(rep.Order, e.Key)
		ok, err := readOne(ctx, deps, e, allowed, &rep)
		if err != nil {
			return rep, err
		}
		if ok && phaseOf(e) == phaseEnrich {
			enrichRead = true
		}
	}
	if !applied && enrichRead {
		failed = applyEnrichment(ctx, deps, &rep) || failed
	}
	if failed || len(rep.Failed) > 0 {
		return rep, ErrSomeFailed
	}
	return rep, nil
}

// applyEnrichment runs enrich.Apply and reports whether it failed.
func applyEnrichment(ctx context.Context, deps Deps, rep *Report) bool {
	res, err := enrich.Apply(ctx, enrich.Deps{Store: deps.Store, Audit: deps.Audit, Now: deps.Now})
	if err != nil {
		rep.ApplyError = bounded(err.Error())
		return true
	}
	rep.Apply = ApplyResult{Ran: true, Updated: res.Updated, NowKEV: res.NowKEV, Superseded: res.Superseded}
	return false
}

// bounded is s on one line, without control characters, at most
// maxErrorRunes runes.
func bounded(s string) string {
	s = strings.Join(strings.Fields(scan.SanitizeText(s)), " ")
	if utf8.RuneCountInString(s) > maxErrorRunes {
		s = string([]rune(s)[:maxErrorRunes-1]) + "…"
	}
	return s
}

// classify maps a read error to the stored result.
func classify(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, egress.ErrEgressDenied):
		return ResultDenied
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne):
		return ResultUnreachable
	}
	return ResultError
}

// readOne reads e, records the outcome on the entry and in the audit, and
// adds it to rep. ok tells that the read went through (data read or
// current). err is a store or audit failure, which stops the run.
func readOne(ctx context.Context, deps Deps, e source.Entry, allowed func(host, purpose string) bool, rep *Report) (ok bool, err error) {
	skip := func(reason string) {
		rep.Skipped = append(rep.Skipped, e.Key)
		rep.SkipReasons[e.Key] = reason
	}
	r, has := readerOf(e.Kind)
	switch {
	case !e.Enabled:
		skip(SkipOff)
		return false, nil
	case !has:
		skip(SkipNoReader)
		return false, nil
	}
	ev := map[string]any{"key": e.Key, "kind": string(e.Kind), "hosts": e.Hosts}
	if e.State(allowed) == source.StateWaitingConsent {
		rep.WaitingConsent = append(rep.WaitingConsent, e.Key)
		if err := deps.Repo.RecordRead(ctx, e.Key, e.LastReadAt, ResultWaitingConsent, "", e.LastReadItems, e.LastReadETag); err != nil {
			return false, err
		}
		return false, record(ctx, deps, e.Key, ResultWaitingConsent, ev)
	}
	now := deps.Now().UTC().Truncate(time.Second)
	if usesGitHubBudget(e) && deps.Budget.empty() {
		skip(SkipRateBudget)
		if err := deps.Repo.RecordRead(ctx, e.Key, now, ResultSkipped, SkipRateBudget, e.LastReadItems, e.LastReadETag); err != nil {
			return false, err
		}
		ev["skipped"] = SkipRateBudget
		return false, record(ctx, deps, e.Key, ResultSkipped, ev)
	}
	timeout := OtherTimeout
	if e.Kind == source.KindOSV {
		timeout = OSVTimeout
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	start := time.Now()
	res, rerr := r.Read(rctx, e, deps)
	cancel()
	ev["duration_ms"] = time.Since(start).Milliseconds()
	if rerr != nil && ctx.Err() != nil {
		return false, ctx.Err()
	}
	switch {
	case errors.Is(rerr, enrich.ErrNotModified):
		res, rerr = Result{Skipped: SkipNotModified}, nil
	case errors.Is(rerr, enrich.ErrRateLimited):
		res.Skipped, rerr = SkipRateLimited, nil
	}
	if rerr != nil {
		result, msg := classify(rerr), bounded(rerr.Error())
		rep.Failed = append(rep.Failed, e.Key)
		rep.Errors[e.Key] = msg
		if err := deps.Repo.RecordRead(ctx, e.Key, now, result, msg, e.LastReadItems, e.LastReadETag); err != nil {
			return false, err
		}
		ev["error"] = msg
		return false, record(ctx, deps, e.Key, result, ev)
	}
	result, items, etag, errText := ResultOK, res.Items, res.ETag, ""
	switch res.Skipped {
	case "":
		rep.Updated = append(rep.Updated, e.Key)
		rep.Items[e.Key] = res.Items
	case SkipNotModified:
		// Current: the entry keeps what the last full read counted.
		skip(SkipNotModified)
		items = e.LastReadItems
	default:
		skip(res.Skipped)
		result, errText = ResultSkipped, res.Skipped
		if res.Items > 0 {
			rep.Items[e.Key] = res.Items
		} else {
			items = e.LastReadItems
		}
	}
	if etag == "" {
		etag = e.LastReadETag
	}
	if err := deps.Repo.RecordRead(ctx, e.Key, now, result, errText, items, etag); err != nil {
		return false, err
	}
	if res.Status != nil {
		if err := deps.Repo.SetStatus(ctx, e.Key, res.Status); err != nil {
			return false, err
		}
		e.Status = res.Status
		if from, to, ok := e.NewVersion(); ok {
			rep.NewVersions = append(rep.NewVersions, NewVersion{Key: e.Key, Name: scan.SanitizeText(e.Name), From: from, To: to})
		}
		if n, ok := res.Status["discover_new"].(int); ok && phaseOf(e) == phaseDiscover {
			rep.DiscoverNew += n
		}
	}
	ev["items"] = items
	if res.Skipped != "" {
		ev["skipped"] = res.Skipped
	}
	return true, record(ctx, deps, e.Key, result, ev)
}

// record writes the source.read event of key.
func record(ctx context.Context, deps Deps, key, result string, ev map[string]any) error {
	if _, err := deps.Audit.Record(ctx, audit.Event{Actor: deps.Actor, Action: "source.read", Target: key, Result: result, Evidence: ev}); err != nil {
		return fmt.Errorf("cannot write the audit event of %s: %w", key, err)
	}
	return nil
}
