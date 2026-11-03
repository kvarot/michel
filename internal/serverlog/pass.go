package serverlog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	// AlertVolume: a log so big that the read cap was reached. One item per
	// source; Count is the bytes left unread. It follows the route of the
	// error level.
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
	ReasonOutputCut      = "output_cut"
	ReasonInactive       = "inactive"
	ReasonBusy           = "busy"
	ReasonError          = "error"
)

// AlertItem is one error in an alert. Text is set only when the server settings
// send the text of errors (it is the cleaned text, never a log line); Location
// is the project relative `file:line` (never a server path).
type AlertItem struct {
	Level                Level
	Type, Location, Text string
	Count                int64
}

// AlertInput is one alert, to be sent on the channels of the user. Channels
// live outside this package: they get it through Deps.Alert.
type AlertInput struct {
	Target target.Target
	Kind   AlertKind
	Items  []AlertItem
	Reason string
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
	Now   func() time.Time
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
	Reason                    string
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

// capSent remembers when the "cap reached" message was last sent for a server:
// one per hour (spec § 8.2).
var capSent struct {
	sync.Mutex
	at map[string]time.Time
}

// capWindow is the hour the cap is counted over.
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
// is read again next time. PassResult.Reason then names the cause.
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
	for _, s := range all {
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

	p := &onePass{d: d, t: t, st: st, now: now, texts: map[string]string{}, counts: map[string]int64{}, hours: map[string]time.Time{}}
	var res PassResult
	var firstErr error
	for _, src := range sources {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if err := p.readSource(ctx, client, src, o, &res); err != nil {
			if res.Reason == "" {
				res.Reason = reasonOf(err)
			}
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if err := p.alert(ctx, &res); err != nil && firstErr == nil {
		firstErr = err
	}
	if firstErr != nil {
		return res, firstErr
	}
	// A missing occurrence is no proof after a gap, but the delay is the user's
	// and the record is "resolved", never "fixed".
	if _, err := d.Repo.Resolve(ctx, now); err != nil {
		return res, err
	}
	return res, nil
}

// onePass is the state of one pass over the sources of a server.
type onePass struct {
	d   Deps
	t   target.Target
	st  Settings
	now time.Time

	cands   []candidate
	volumes []AlertItem
	// What the records of this pass said, by signature: the cleaned text, the
	// occurrences and the latest hour.
	texts  map[string]string
	counts map[string]int64
	hours  map[string]time.Time
}

// candidate is an error to tell now.
type candidate struct {
	kind AlertKind
	id   string
	item AlertItem
}

func (p *onePass) readSource(ctx context.Context, c *sshx.Client, src Source, o FilterOptions, res *PassResult) error {
	cursors, err := p.d.Repo.Cursors(ctx, src.ID)
	if err != nil {
		return err
	}
	lastRead := latestRead(cursors)
	out, next, err := Read(ctx, c, src, cursors, o, p.st.ReadTimeout, p.now)
	if err != nil {
		if ctx.Err() == nil {
			p.audit(ctx, "failed", map[string]any{"source": src.ID, "reason": reasonOf(err)})
		}
		return err
	}
	fresh, reopened, spiked, err := p.d.Repo.Apply(ctx, src, out.Records, p.now)
	if err != nil {
		return err
	}
	for _, r := range out.Records {
		id := SignatureID(src.ID, r.Level, r.Type, r.Location, r.Channel)
		p.counts[id] += r.Count
		if p.texts[id] == "" {
			p.texts[id] = r.Text
		}
		if r.Hour.After(p.hours[id]) {
			p.hours[id] = r.Hour
		}
	}
	if err := p.d.Repo.SaveCursors(ctx, next); err != nil {
		return err
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
			return err
		}
	}
	if err := p.d.Repo.TouchCursors(ctx, src.ID, p.now); err != nil {
		return err
	}
	if err := p.notes(ctx, src, out, cursors, lastRead); err != nil {
		return err
	}
	res.Records += len(out.Records)
	res.Rejected += out.Rejected
	p.audit(ctx, "ok", map[string]any{
		"source": src.ID, "from": ts(lastRead), "to": ts(p.now),
		"volume": bytesRead(out, cursors), "skipped": skippedBytes(out), "records": len(out.Records),
		"occurrences": occurrences(out), "rejected": out.Rejected, "fingerprint": fingerprint(out.Records),
	})
	p.queue(src, fresh, reopened, spiked)
	return nil
}

// notes stores what was left unread or out, and a gap in the reading. The
// volume alert (a log that grows past the cap) comes at most once an hour per
// source and follows the route of the error level.
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
		last, found, err := p.d.Repo.LatestNote(ctx, p.t.ID, src.ID, NoteSkipped)
		if err != nil {
			return err
		}
		if p.st.Routes[LevelError] == RouteImmediate && (!found || !last.To.After(p.now.Add(-capWindow))) {
			p.volumes = append(p.volumes, AlertItem{Level: LevelError, Count: n})
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
	if !lastRead.IsZero() && p.st.Interval != ManualInterval && p.now.Sub(lastRead) >= gapAfter(p.st.Interval) {
		return p.d.Repo.RecordState(ctx, Note{TargetID: p.t.ID, SourceID: src.ID, Kind: NoteGap, From: lastRead, To: p.now})
	}
	return nil
}

// gapAfter is the silence from which a read counts as the end of a gap: more
// than one missed read, and at least gapFloor.
func gapAfter(interval time.Duration) time.Duration {
	if g := 2 * interval; g > gapFloor {
		return g
	}
	return gapFloor
}

// queue keeps the errors of a source that the route of their level tells now.
func (p *onePass) queue(src Source, fresh, reopened, spiked []Signature) {
	add := func(kind AlertKind, sigs []Signature) {
		for _, g := range sigs {
			if p.st.Routes[g.Level] != RouteImmediate {
				continue
			}
			it := AlertItem{Level: g.Level, Type: g.Type, Location: g.Location, Count: p.counts[g.ID]}
			if p.st.AlertText && p.st.StoreText {
				if txt, ok := cleanedText(p.texts[g.ID]); ok {
					it.Text = txt
				}
			}
			p.cands = append(p.cands, candidate{kind: kind, id: g.ID, item: it})
		}
	}
	add(AlertNew, fresh)
	add(AlertReopened, reopened)
	add(AlertSpike, spiked)
}

// alert hands the queued errors to Deps.Alert: one alert per kind, the most
// severe first, within the hourly cap of the server; what the cap leaves out
// waits for the digest, with one message saying so.
func (p *onePass) alert(ctx context.Context, res *PassResult) error {
	if p.d.Alert == nil || (len(p.cands) == 0 && len(p.volumes) == 0) {
		return nil
	}
	for i := range p.cands {
		if p.cands[i].kind == AlertSpike {
			c := &p.cands[i]
			if n, err := p.d.Repo.HourCount(ctx, c.id, p.hours[c.id]); err == nil && n > 0 {
				c.item.Count = n
			}
		}
	}
	sort.SliceStable(p.cands, func(i, j int) bool {
		a, b := p.cands[i].item, p.cands[j].item
		if ra, rb := levelRank(a.Level), levelRank(b.Level); ra != rb {
			return ra < rb
		}
		return a.Count > b.Count
	})
	used, err := p.d.Repo.AlertedSince(ctx, p.t.ID, p.now.Add(-capWindow))
	if err != nil {
		return err
	}
	room := p.st.MaxAlertsPerHour - used
	if room < 0 {
		room = 0
	}
	send, held := p.cands, false
	if len(send) > room {
		send, held = send[:room], true
	}
	var told []string
	for _, kind := range []AlertKind{AlertNew, AlertReopened, AlertSpike} {
		var items []AlertItem
		for _, c := range send {
			if c.kind == kind {
				items = append(items, c.item)
				told = append(told, c.id)
			}
		}
		if len(items) > 0 {
			p.d.Alert(ctx, AlertInput{Target: p.t, Kind: kind, Items: items})
			res.Alerts++
		}
	}
	if len(p.volumes) > 0 {
		p.d.Alert(ctx, AlertInput{Target: p.t, Kind: AlertVolume, Items: p.volumes})
		res.Alerts++
	}
	if held && capMessageDue(p.t.ID, p.now) {
		p.d.Alert(ctx, AlertInput{Target: p.t, Kind: AlertCapReached})
		res.Alerts++
	}
	return p.d.Repo.MarkAlerted(ctx, told, p.now)
}

// capMessageDue says whether the "cap reached" message of a server may go now,
// and remembers it.
func capMessageDue(targetID string, now time.Time) bool {
	capSent.Lock()
	defer capSent.Unlock()
	if capSent.at == nil {
		capSent.at = map[string]time.Time{}
	}
	if at, ok := capSent.at[targetID]; ok && now.Sub(at) < capWindow && !now.Before(at) {
		return false
	}
	capSent.at[targetID] = now
	return true
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
	// A failed audit write must not lose a read that happened: it is the one
	// trace left, and the next read goes on.
	_, _ = p.d.Audit.Record(ctx, audit.Event{Actor: auditActorRead, Action: auditActionRead, Target: p.t.ID, Result: result, Evidence: ev})
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
		return ReasonDenied
	case errors.Is(err, sshx.ErrNoAgent):
		return ReasonNoAgent
	case errors.Is(err, sshx.ErrNoKeyAccepted):
		return ReasonNoKeyAccepted
	case errors.Is(err, sshx.ErrCommandTimeout), errors.Is(err, context.DeadlineExceeded):
		return ReasonTimeout
	case errors.Is(err, ErrOutputCut):
		return ReasonOutputCut
	case errors.Is(err, ErrInactive):
		return ReasonInactive
	case errors.Is(err, ErrPassRunning):
		return ReasonBusy
	}
	return ReasonError
}
