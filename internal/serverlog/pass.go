package serverlog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/target"
)

// AlertKind is what an alert tells.
type AlertKind string

const (
	// AlertNew: errors seen for the first time.
	AlertNew AlertKind = "new"
	// AlertReopened: errors that came back after being resolved.
	AlertReopened AlertKind = "reopened"
	// AlertSpike: errors that jumped to ten times the hour before (and at least
	// 100 occurrences). Count is the occurrences of that hour.
	AlertSpike AlertKind = "spike"
	// AlertFrequent: an error among the most frequent of the period of a digest
	// (it is not new, back or spiking). Only the digest uses it, and it has no
	// label: its count says it.
	AlertFrequent AlertKind = "frequent"
	// AlertVolume: a log so big that the read cap was reached. One item per
	// source, named by SourceID; Count is the bytes left unread. It follows the
	// route of the error level.
	AlertVolume AlertKind = "volume"
	// AlertNotReading: Michel no longer reads. Reason is the cause (a key of
	// the Reason* constants), Items name the servers (Type is the server name,
	// Level and the rest are empty). A cause shared by many servers (the SSH
	// agent) is one alert, with Target the first of them.
	AlertNotReading AlertKind = "not_reading"
	// AlertCapReached: the hourly cap of alerts was reached; the other errors
	// wait for the digest. It has no item.
	AlertCapReached AlertKind = "cap_reached"
)

// Reasons a pass or a read failed. They are keys, not texts, and never carry
// what the server printed.
const (
	ReasonNoAgent        = "no_agent"
	ReasonNoKeyAccepted  = "no_key_accepted"
	ReasonHostKeyUnknown = "host_key_unknown"
	ReasonHostKeyChanged = "host_key_changed"
	ReasonDenied         = "denied"
	ReasonTimeout        = "timeout"
	ReasonRefused        = "refused"
	ReasonPolicy         = "policy"
	ReasonOutputCut      = "output_cut"
	ReasonTools          = "tools"
	ReasonInactive       = "inactive"
	ReasonBusy           = "busy"
	ReasonError          = "error"
)

// AlertItem is one error in an alert. Kind is its own reason, which can differ
// from the one of the alert. Text is set only when the server settings send the
// text of errors (it is the cleaned text, never a log line); Location is the
// project relative `file:line` (never a server path). SourceID is set on volume
// items only: it is an id, never the path of the log.
type AlertItem struct {
	Kind     AlertKind `json:"kind"`
	Level    Level     `json:"level"`
	Type     string    `json:"type"`
	Location string    `json:"location,omitempty"`
	Text     string    `json:"text,omitempty"`
	Count    int64     `json:"count"`
	// SourceID never leaves the process: an id means nothing in a message.
	SourceID string `json:"-"`
}

// AlertInput is one alert, to be sent on the channels of the user. Channels
// live outside this package: they get it through Deps.Alert.
//
// One pass sends at most one alert for its errors (spec § 8.2): new, reopened
// and spike items go together, and Kind is the first present of AlertNew,
// AlertReopened, AlertSpike. AlertVolume and AlertCapReached say something else
// and stay separate messages.
type AlertInput struct {
	Target target.Target
	Kind   AlertKind
	Items  []AlertItem
	Reason string
	// Sources, on an AlertNotReading, are the sources (never their paths) that
	// fail when the others of the server were read: the alert then speaks of
	// these sources only, by number and format. Empty: the server as a whole cannot
	// be read.
	Sources []SourceRef
}

// Deps are the services a pass needs.
type Deps struct {
	Repo    *Repo
	Targets *target.Repo
	// Audit records log.read and log.purge; nil records nothing (tests).
	Audit *audit.Logger
	SSH   sshx.Deps
	// Alert is told about each alert to send now; nil tells no one (and an
	// error is then not marked as told).
	Alert func(context.Context, AlertInput)
	// FirstRound, when set, is called once the first round of the scheduler is
	// over (every server due was read or failed). The digest of michel serve
	// waits for it, so that what was written while the computer was off is in
	// the first digest, holes included.
	FirstRound func()
	Now        func() time.Time
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

// PassResult is what one pass did. Records counts the groups read, Rejected the
// lines the double barrier threw away, Alerts the alerts handed to Deps.Alert.
// Reason is the key of the failure, when the pass failed.
type PassResult struct {
	Records, Rejected, Alerts int
	// Unseen counts the files that could not be opened (the page says which and why).
	Unseen int
	Reason string
	// Read counts the sources read well in this pass, Failed names the ones whose
	// read failed (a connection that fails names none: no source was tried).
	Read   int            `json:"-"`
	Failed []FailedSource `json:"-"`
}

// SourceRef names a source without its path, which no message carries: its
// number on the sheet of the server (Rank, from 1, in the order of
// Repo.Sources, the sheet's order) and its format.
type SourceRef struct {
	Rank   int
	Format Format
}

// FailedSource is a source whose read failed in a pass. ID is the source's id
// (for the memory of the scheduler only, it never leaves the process); Reason is
// the cause, a key of the Reason* constants. Never what the server printed.
type FailedSource struct {
	ID     string
	Ref    SourceRef
	Reason string
}

// Errors of a pass.
var (
	// ErrInactive: the server is turned off in Michel; it is not read.
	ErrInactive = errors.New("the server is turned off: its logs are not read")
	// ErrPassRunning: a read of this server is already running.
	ErrPassRunning = errors.New("a log read of this server is already running")
)

const (
	auditActorRead  = "serverlog"
	auditActionRead = "log.read"
)

// running holds the servers being read: one read at a time per server, whoever
// asks (the scheduler or a read by hand).
var running sync.Map

// hourlyMemo remembers when a message was last sent, for a message that goes at
// most once an hour. It lives in memory: a restart can repeat a message.
type hourlyMemo struct {
	sync.Mutex
	at map[string]time.Time
}

// due says whether the message of key may go now, and remembers it.
func (m *hourlyMemo) due(key string, now time.Time) bool {
	m.Lock()
	defer m.Unlock()
	if m.at == nil {
		m.at = map[string]time.Time{}
	}
	if at, ok := m.at[key]; ok && now.Sub(at) < capWindow && !now.Before(at) {
		return false
	}
	m.at[key] = now
	return true
}

// hourlySlots counts the messages sent over the last hour, for a cap on them. It
// lives in memory: a restart gives the hour back.
type hourlySlots struct {
	sync.Mutex
	at map[string][]time.Time
}

// take says whether fewer than limit messages of key went in the last hour, and
// then counts one more.
func (m *hourlySlots) take(key string, now time.Time, limit int) bool {
	m.Lock()
	defer m.Unlock()
	if m.at == nil {
		m.at = map[string][]time.Time{}
	}
	kept := m.at[key][:0]
	for _, at := range m.at[key] {
		if now.Sub(at) < capWindow && !now.Before(at) {
			kept = append(kept, at)
		}
	}
	ok := len(kept) < limit
	if ok {
		kept = append(kept, now)
	}
	m.at[key] = kept
	return ok
}

var (
	// alertSlots: the messages that tell errors, by server (spec § 8.2). The cap
	// counts these messages, not the errors they hold.
	alertSlots hourlySlots
	// capSent: the "cap reached" message, by server (spec § 8.2).
	capSent hourlyMemo
	// volumeSent: the volume alert, by source.
	volumeSent hourlyMemo
)

// capWindow is the hour the caps are counted over.
const capWindow = time.Hour

// gapFloor is the shortest silence that counts as a gap in the reading.
const gapFloor = 30 * time.Minute

// Pass reads every active source of one server over SSH, once: it stores the
// records and the new positions, applies the alert rules of the server, and
// tells Deps.Alert what has to be told at once. A server without an active
// source is not contacted. Errors that only the digest carries are left to it:
// nothing is sent for them here.
//
// A failing read (connection, filter, cap on the answer) makes the pass fail
// after the other sources were read: the failed source keeps its positions and
// is read again next time. PassResult.Reason then names the cause, and Failed
// the sources. The sources that were read well resolve their old errors all the
// same; the one that failed keeps its errors as they are.
func Pass(ctx context.Context, d Deps, targetID string) (PassResult, error) {
	t, err := d.Targets.Get(ctx, targetID)
	if err != nil {
		return PassResult{Reason: ReasonError}, err
	}
	if !t.Active {
		return PassResult{Reason: ReasonInactive}, fmt.Errorf("%w (%s)", ErrInactive, t.Name)
	}
	if _, busy := running.LoadOrStore(t.ID, struct{}{}); busy {
		return PassResult{Reason: ReasonBusy}, fmt.Errorf("%w (%s)", ErrPassRunning, t.Name)
	}
	defer running.Delete(t.ID)

	all, err := d.Repo.Sources(ctx, t.ID)
	if err != nil {
		return PassResult{Reason: ReasonError}, err
	}
	var sources []Source
	rank := make(map[string]int, len(all))
	for i, s := range all {
		rank[s.ID] = i + 1
		if s.Active {
			sources = append(sources, s)
		}
	}
	if len(sources) == 0 {
		return PassResult{}, nil
	}
	st, err := d.Repo.Settings(ctx, t.ID)
	if err != nil {
		return PassResult{Reason: ReasonError}, err
	}
	links, err := d.Targets.Links(ctx, t.ID)
	if err != nil {
		return PassResult{Reason: ReasonError}, err
	}
	o := FilterOptions{Text: st.StoreText, ReadCap: st.ReadCap}
	for _, l := range links {
		o.RemoteDirs = append(o.RemoteDirs, l.RemoteDir)
	}
	now := d.now()
	client, err := sshx.Dial(ctx, d.SSH, t)
	if err != nil {
		return PassResult{Reason: reasonOf(err)}, fmt.Errorf("cannot connect to %s: %w", t.Name, err)
	}
	defer client.Close()

	p := &onePass{d: d, t: t, st: st, now: now, texts: map[string]string{}, counts: map[string]int64{}}
	var res PassResult
	var firstErr error
	var readIDs []string
	for _, src := range sources {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		read, err := p.readSource(ctx, client, src, o, &res)
		if err != nil {
			reason := reasonOf(err)
			if res.Reason == "" {
				res.Reason = reason
			}
			res.Failed = append(res.Failed, FailedSource{ID: src.ID, Ref: SourceRef{Rank: rank[src.ID], Format: src.Format}, Reason: reason})
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if read.opened {
			res.Read++
		}
		if read.whole {
			readIDs = append(readIDs, src.ID)
		}
	}
	// The read happened whatever comes next: what fails from here on is said in
	// the log, and does not count as "not reading".
	if err := p.alert(ctx, &res); err != nil && ctx.Err() == nil {
		slog.Warn("serverlog: the alerts of a log read could not be completed", "target", t.ID, "err", err)
	}
	// A missing occurrence is no proof after a gap, but the delay is the user's
	// and the record is "resolved", never "fixed". Only the sources seen entire can
	// say it: one that failed, was read in part or not at all keeps its errors.
	if _, err := d.Repo.Resolve(ctx, t.ID, now, readIDs); err != nil && ctx.Err() == nil {
		slog.Warn("serverlog: cannot mark the log errors as resolved", "target", t.ID, "err", err)
	}
	return res, firstErr
}

// onePass is the state of one pass over the sources of a server.
type onePass struct {
	d   Deps
	t   target.Target
	st  Settings
	now time.Time

	cands   []candidate
	volumes []AlertItem
	// What the records of this pass said, by signature: the cleaned text and the
	// occurrences.
	texts  map[string]string
	counts map[string]int64
}

// candidate is an error to tell now.
type candidate struct {
	id   string
	item AlertItem
}

func (p *onePass) readSource(ctx context.Context, c *sshx.Client, src Source, o FilterOptions, res *PassResult) (readOutcome, error) {
	cursors, err := p.d.Repo.Cursors(ctx, src.ID)
	if err != nil {
		return readOutcome{}, err
	}
	lastRead := latestRead(cursors)
	out, next, err := Read(ctx, c, src, cursors, o, p.st.ReadTimeout, p.now)
	if err != nil {
		if ctx.Err() == nil {
			p.audit(ctx, "failed", map[string]any{"source": src.ID, "reason": reasonOf(err)})
		}
		return readOutcome{}, err
	}
	fresh, reopened, spiked, err := p.d.Repo.Apply(ctx, src, out.Records, p.d.now())
	if err != nil {
		return readOutcome{}, err
	}
	for _, r := range out.Records {
		id := SignatureID(src.ID, r.Level, r.Type, r.Location, r.Channel)
		p.counts[id] += r.Count
		if p.texts[id] == "" {
			p.texts[id] = r.Text
		}
	}
	// Apply has committed: these errors will not come back as new, so they are
	// queued before anything else can fail.
	p.queue(ctx, src, fresh, reopened, spiked, lastRead)
	if err := p.d.Repo.SaveCursors(ctx, next); err != nil {
		return readOutcome{}, err
	}
	// Files that are gone, and the placeholder of an activation, leave their
	// positions only when the answer is whole: a cut list (too many files) or a
	// refused line could hide a file that is still there, which would then be
	// read again from its start.
	if len(out.Files) > 0 && !out.TooManyFiles && out.Rejected == 0 {
		keep := make([]string, 0, len(out.Files)+len(out.Unseen))
		for _, f := range out.Files {
			keep = append(keep, f.File)
		}
		keep = append(keep, out.Unseen...)
		if err := p.d.Repo.PruneCursors(ctx, src.ID, keep); err != nil {
			return readOutcome{}, err
		}
	}
	// A pass that opened no file (all unseen, or nothing matched) moves no date: the
	// page must not show a fresh read where nothing was read.
	if len(out.Files) > 0 {
		if err := p.d.Repo.TouchCursors(ctx, src.ID, p.now, out.Unseen); err != nil {
			return readOutcome{}, err
		}
	}
	if err := p.notes(ctx, src, out, cursors, lastRead); err != nil {
		return readOutcome{}, err
	}
	if err := p.d.Repo.SetUnseen(ctx, src.ID, out.UnseenCause, p.now); err != nil {
		return readOutcome{}, err
	}
	res.Records += len(out.Records)
	res.Rejected += out.Rejected
	res.Unseen += len(out.Unseen)
	// Everything above is kept, as for any read: the place in the files, the notes
	// and the list of what is unseen. What remains is to say that it failed.
	if err := sourceUnread(out); err != nil {
		p.audit(ctx, "failed", map[string]any{"source": src.ID, "reason": reasonOf(err)})
		return readOutcome{}, err
	}
	p.audit(ctx, "ok", map[string]any{
		"source": src.ID, "from": ts(lastRead), "to": ts(p.now),
		"volume": bytesRead(out, cursors), "skipped": skippedBytes(out), "records": len(out.Records),
		"occurrences": occurrences(out), "rejected": out.Rejected, "fingerprint": fingerprint(out.Records),
	})
	return readOutcome{opened: opened(out), whole: wholeRead(out)}, nil
}

// readOutcome says how well a source that did not fail was read. opened: a file
// of it was really opened. whole: it was seen entire, so that what is missing
// from it is gone (see wholeRead).
type readOutcome struct{ opened, whole bool }

// opened says whether a file of the answer was really opened: an F line with no
// U line. An absent file, a link or a folder opens nothing.
func opened(out Output) bool {
	for _, f := range out.Files {
		if _, unseen := out.UnseenCause[f.File]; !unseen {
			return true
		}
	}
	return false
}

// wholeRead says whether a source was seen entire: a file opened, none refused
// (rights, a tool, another failure), the list of files not cut and no part of a
// log skipped by the cap. Only then does the absence of an error mean anything.
func wholeRead(out Output) bool {
	if !opened(out) || out.TooManyFiles || skippedBytes(out) > 0 {
		return false
	}
	for _, cause := range out.UnseenCause {
		switch cause {
		case CauseDenied, CauseTools, CauseOther:
			return false
		}
	}
	return true
}

// sourceUnread says why a source failed although the filter ran well: no file of
// it could be opened in this read, and that is not simply because there is
// nothing to open. A file counts as opened when it has an F line and no U line:
// an unreadable file located by its metadata at the activation has both. A file
// that is absent, a link or a folder, and an activation that found nothing (N),
// are told on the sheet and are no failure on their own. One file read is enough
// for a good read, with its note for the others.
func sourceUnread(out Output) error {
	for _, f := range out.Files {
		if _, unseen := out.UnseenCause[f.File]; !unseen {
			return nil
		}
	}
	var denied, tools, other bool
	for _, cause := range out.UnseenCause {
		switch cause {
		case CauseDenied:
			denied = true
		case CauseTools:
			tools = true
		case CauseOther:
			other = true
		}
	}
	switch {
	case denied:
		return ErrSourceDenied
	case tools:
		return ErrSourceTools
	case other:
		return ErrSourceOther
	}
	return nil
}

// notes stores what was left unread or out, and a gap in the reading. The
// volume alert (a log that grows past the cap) follows the route of the error
// level; alert sends it at most once an hour per source.
func (p *onePass) notes(ctx context.Context, src Source, out Output, cursors []Cursor, lastRead time.Time) error {
	from := lastRead
	if from.IsZero() || from.After(p.now) {
		from = p.now
	}
	add := func(kind string, amount int64) error {
		return p.d.Repo.AddNote(ctx, Note{TargetID: p.t.ID, SourceID: src.ID, Kind: kind, From: from, To: p.now, Amount: amount})
	}
	state := func(kind string, amount int64) error {
		return p.d.Repo.RecordState(ctx, Note{TargetID: p.t.ID, SourceID: src.ID, Kind: kind, From: from, To: p.now, Amount: amount})
	}
	if n := skippedBytes(out); n > 0 {
		if p.st.Routes[LevelError] == RouteImmediate {
			p.volumes = append(p.volumes, AlertItem{Kind: AlertVolume, Level: LevelError, SourceID: src.ID, Count: n})
		}
		if err := add(NoteSkipped, n); err != nil {
			return err
		}
	}
	rotated := int64(0)
	for _, f := range out.Files {
		if f.Rotated {
			rotated++
		}
	}
	if rotated > 0 {
		if err := add(NoteRotated, rotated); err != nil {
			return err
		}
	}
	if out.Rejected > 0 {
		if err := add(NoteRejected, int64(out.Rejected)); err != nil {
			return err
		}
	}
	if len(out.Unseen) > 0 {
		if err := state(NoteUnseen, int64(len(out.Unseen))); err != nil {
			return err
		}
	}
	if out.TooManyFiles {
		if err := state(NoteTooManyFiles, 0); err != nil {
			return err
		}
	}
	// A read that follows a long silence: the poste was off, or the server
	// could not be reached. The note is one per source, even if the silence
	// began with an incident already noted.
	if p.afterGap(lastRead) {
		return p.d.Repo.RecordState(ctx, Note{TargetID: p.t.ID, SourceID: src.ID, Kind: NoteGap, From: lastRead, To: p.now})
	}
	return nil
}

// afterGap says whether a read that follows lastRead ends a gap in the reading.
func (p *onePass) afterGap(lastRead time.Time) bool {
	return !lastRead.IsZero() && p.st.Interval != ManualInterval && p.now.Sub(lastRead) >= gapAfter(p.st.Interval)
}

// gapAfter is the silence from which a read counts as the end of a gap: more
// than one missed read, and at least gapFloor.
func gapAfter(interval time.Duration) time.Duration {
	if g := 2 * interval; g > gapFloor {
		return g
	}
	return gapFloor
}

// queue keeps the errors of a source that the route of their level tells now. A
// spike of an hour that ended inside a gap in the reading is over and was not
// seen as it happened: it is counted, not told as current.
func (p *onePass) queue(ctx context.Context, src Source, fresh, reopened, spiked []Signature, lastRead time.Time) {
	add := func(kind AlertKind, sigs []Signature) {
		for _, g := range sigs {
			if p.st.Routes[g.Level] != RouteImmediate {
				continue
			}
			it := AlertItem{Kind: kind, Level: g.Level, Type: g.Type, Location: g.Location, Count: p.counts[g.ID]}
			if kind == AlertSpike {
				if p.afterGap(lastRead) && !g.SpikeHour.Add(time.Hour).After(p.now) {
					continue
				}
				n, err := p.d.Repo.HourCount(ctx, g.ID, g.SpikeHour)
				if err != nil {
					slog.Warn("serverlog: cannot read the count of the hour of a spike", "target", p.t.ID, "signature", g.ID, "err", err)
				} else if n > 0 {
					it.Count = n
				}
			}
			if p.st.AlertText && p.st.StoreText {
				if txt, ok := cleanedText(p.texts[g.ID]); ok {
					it.Text = txt
				}
			}
			p.cands = append(p.cands, candidate{id: g.ID, item: it})
		}
	}
	add(AlertNew, fresh)
	add(AlertReopened, reopened)
	add(AlertSpike, spiked)
}

// alert hands the queued errors to Deps.Alert: one alert for all of them, the
// most severe first, if the hourly cap of the server leaves room for a message.
// If not, they all wait for the digest, with one message saying so, at most
// once an hour. The volume alert goes apart, at most once an hour per source;
// neither it nor the "cap reached" message counts against the cap.
func (p *onePass) alert(ctx context.Context, res *PassResult) error {
	if p.d.Alert == nil || (len(p.cands) == 0 && len(p.volumes) == 0) {
		return nil
	}
	sort.SliceStable(p.cands, func(i, j int) bool {
		a, b := p.cands[i].item, p.cands[j].item
		if ra, rb := levelRank(a.Level), levelRank(b.Level); ra != rb {
			return ra < rb
		}
		return a.Count > b.Count
	})
	held := false
	var told []string
	var items []AlertItem
	if len(p.cands) > 0 {
		if alertSlots.take(p.t.ID, p.now, p.st.MaxAlertsPerHour) {
			for _, c := range p.cands {
				told = append(told, c.id)
				items = append(items, c.item)
			}
		} else {
			held = true
		}
	}
	if len(items) > 0 {
		p.d.Alert(ctx, AlertInput{Target: p.t, Kind: groupKind(items), Items: items})
		res.Alerts++
	}
	var volumes []AlertItem
	for _, it := range p.volumes {
		if volumeSent.due(it.SourceID, p.now) {
			volumes = append(volumes, it)
		}
	}
	if len(volumes) > 0 {
		p.d.Alert(ctx, AlertInput{Target: p.t, Kind: AlertVolume, Items: volumes})
		res.Alerts++
	}
	if held && capSent.due(p.t.ID, p.now) {
		p.d.Alert(ctx, AlertInput{Target: p.t, Kind: AlertCapReached})
		res.Alerts++
	}
	return p.d.Repo.MarkAlerted(ctx, told, p.now)
}

// groupKind is the kind of an alert that groups errors: the first present of
// new, reopened, spike.
func groupKind(items []AlertItem) AlertKind {
	for _, kind := range []AlertKind{AlertNew, AlertReopened} {
		for _, it := range items {
			if it.Kind == kind {
				return kind
			}
		}
	}
	return AlertSpike
}

func levelRank(l Level) int {
	for i, v := range Levels {
		if v == l {
			return i
		}
	}
	return len(Levels)
}

// audit writes log.read: the server, the source, the window, the volume read,
// the number of records and a fingerprint of the result. Never a content.
func (p *onePass) audit(ctx context.Context, result string, ev map[string]any) {
	if p.d.Audit == nil {
		return
	}
	// A failed audit write does not undo a read that happened, and the next read
	// goes on; the log says that this one has no trace.
	if _, err := p.d.Audit.Record(ctx, audit.Event{Actor: auditActorRead, Action: auditActionRead, Target: p.t.ID, Result: result, Evidence: ev}); err != nil {
		slog.Warn("serverlog: cannot write log.read to the audit log", "target", p.t.ID, "source", ev["source"], "result", result, "err", err)
	}
}

func latestRead(cs []Cursor) time.Time {
	var at time.Time
	for _, c := range cs {
		if c.ReadAt.After(at) {
			at = c.ReadAt
		}
	}
	return at
}

// bytesRead is the size read in this pass: the move of each position, the
// bytes jumped over by the cap left out.
func bytesRead(out Output, saved []Cursor) int64 {
	was := map[string]Cursor{}
	for _, c := range saved {
		was[c.File] = c
	}
	var n int64
	for _, f := range out.Files {
		if f.First {
			continue
		}
		d := f.Offset
		if c, ok := was[f.File]; ok && c.FileID == f.FileID && f.Offset >= c.Offset {
			d = f.Offset - c.Offset
		}
		if d -= f.Skipped; d > 0 {
			n += d
		}
	}
	return n
}

func skippedBytes(out Output) int64 {
	var n int64
	for _, f := range out.Files {
		n += f.Skipped
	}
	return n
}

func occurrences(out Output) int64 {
	var n int64
	for _, r := range out.Records {
		n += r.Count
	}
	return n
}

// fingerprint is the SHA-256 of the records read, by their fields without the
// text, in a fixed order: it says that two reads gave the same result without
// saying what it was.
func fingerprint(recs []Record) string {
	lines := make([]string, 0, len(recs))
	for _, r := range recs {
		lines = append(lines, fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%d", r.Level, r.Type, r.Location, r.Channel, r.Hour.UTC().Format(time.RFC3339), r.Count))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// reasonOf names why a connection or a read failed, without its text (which
// can carry the SSH user and the host).
func reasonOf(err error) string {
	var unk sshx.ErrHostKeyUnknown
	var chg sshx.ErrHostKeyChanged
	switch {
	case errors.As(err, &chg):
		return ReasonHostKeyChanged
	case errors.As(err, &unk):
		return ReasonHostKeyUnknown
	case errors.Is(err, sshx.ErrDenied):
		return ReasonPolicy
	case errors.Is(err, sshx.ErrNoAgent):
		return ReasonNoAgent
	case errors.Is(err, sshx.ErrNoKeyAccepted):
		return ReasonNoKeyAccepted
	case errors.Is(err, sshx.ErrConnectionRefused):
		return ReasonRefused
	case errors.Is(err, sshx.ErrCommandTimeout), errors.Is(err, sshx.ErrConnectTimeout), errors.Is(err, context.DeadlineExceeded):
		return ReasonTimeout
	case errors.Is(err, ErrOutputCut):
		return ReasonOutputCut
	case errors.Is(err, ErrSourceDenied):
		return ReasonDenied
	case errors.Is(err, ErrSourceTools):
		return ReasonTools
	case errors.Is(err, ErrInactive):
		return ReasonInactive
	case errors.Is(err, ErrPassRunning):
		return ReasonBusy
	}
	return ReasonError
}
