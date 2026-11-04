package digest

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/serverlog"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

// MaxLogTop is the most errors listed for one server; the counters say the rest.
const MaxLogTop = 5

// LogReadLag is how far back the period of the log errors is shifted (see serverLogs).
const LogReadLag = 5 * time.Second

// DeviationReminder is how often the digest recalls that the log settings of a
// server are not the recommended ones.
const DeviationReminder = 7 * 24 * time.Hour

// UnopenedSource is a source of which Count files cannot be opened. It is named
// by its number on the sheet of the server and its format, never by a path; the
// files are not named: the sheet does.
type UnopenedSource struct {
	Rank   int              `json:"rank"`
	Format serverlog.Format `json:"format"`
	Count  int              `json:"count"`
}

// SourceLabel names a source in a message without its path: its number on the
// sheet of the server and, for the formats a beginner knows by name, its format
// ("log no. 2 on the sheet (PHP)"). A plain text log or another format has no
// name worth a bracket: "log no. 3 on the sheet".
func SourceLabel(lang i18n.Lang, ref serverlog.SourceRef) string {
	if f := sourceFormat(lang, ref.Format); f != "" {
		return i18n.T(lang, "digest.serverlogs.source", ref.Rank, f)
	}
	return i18n.T(lang, "digest.serverlogs.source_plain", ref.Rank)
}

// sourceOf is SourceLabel in the form "of log no. 2 on the sheet (PHP)", for a
// sentence about the files of a source.
func sourceOf(lang i18n.Lang, rank int, format serverlog.Format) string {
	if f := sourceFormat(lang, format); f != "" {
		return i18n.T(lang, "digest.serverlogs.source_of", rank, f)
	}
	return i18n.T(lang, "digest.serverlogs.source_of_plain", rank)
}

// sourceFormat is the format of a source in a word or two, "" for the formats
// that are not worth naming (plain text, other).
func sourceFormat(lang i18n.Lang, f serverlog.Format) string {
	switch f {
	case serverlog.FormatPHP, serverlog.FormatPostgres, serverlog.FormatMonolog, serverlog.FormatJSON:
		return i18n.T(lang, "digest.serverlogs.format."+string(f))
	}
	return ""
}

// deviationKey is the key of Run.Summary that marks a digest which carried the
// reminder: the weekly rhythm is read from the runs, nothing else is stored.
const deviationKey = "deviation_reminded"

// ServerLogDigest is the part of the digest about the logs of one server:
// the errors that are new or came back in the window, the frequent ones, the
// holes in the reading, and, once a week, the reminder about its settings.
// New and Reopened count every such error; Top lists the most severe ones.
// Items hold no source id; a Text is there only when the server settings send
// the text of errors in alerts, and it is the cleaned text, never a log line.
type ServerLogDigest struct {
	Name     string                `json:"name"`
	New      int                   `json:"new"`
	Reopened int                   `json:"reopened"`
	Top      []serverlog.AlertItem `json:"top,omitempty"`
	// Gaps are the periods the logs were not read; the notes of the sources of the
	// server that overlap are joined into one, which says which logs were behind.
	Gaps []LogGap `json:"gaps,omitempty"`
	// Skipped is the volume in bytes left unread in the period because a log grew
	// past the read cap, all sources of the server together. It is left out when
	// errors of level error go nowhere on this server.
	Skipped int64 `json:"skipped,omitempty"`
	// Unopened are the sources of a pattern some of whose files Michel cannot open
	// (the rights are refused) while another file of it is read: at most MaxLogTop
	// of them. It is a state, listed as long as it lasts, and no alert of its own.
	Unopened []UnopenedSource `json:"unopened,omitempty"`
	// UnopenedMore counts the sources in the same case that the list left out. Like
	// Unopened it is left out when errors of level error go nowhere on this server.
	UnopenedMore int `json:"unopened_more,omitempty"`
	// Deviations are the keys of the settings that are not the recommended
	// ones (serverlog.Deviation*), set once a week only.
	Deviations []string `json:"deviations,omitempty"`
}

// deviationDue says whether the weekly reminder is due: no digest of the last
// DeviationReminder carried it.
func deviationDue(ctx context.Context, s *store.Store, now time.Time) (bool, error) {
	runs, err := NewRepo(s).List(ctx, 60)
	if err != nil {
		return false, err
	}
	for _, r := range runs {
		if r.Summary[deviationKey] == 1 {
			return now.Sub(r.CreatedAt) >= DeviationReminder, nil
		}
	}
	return true, nil
}

// carriesDeviation says whether any server of d has the reminder.
func carriesDeviation(d Digest) bool {
	for _, s := range d.ServerLogs {
		if len(s.Deviations) > 0 {
			return true
		}
	}
	return false
}

func levelRank(l serverlog.Level) int {
	for i, v := range serverlog.Levels {
		if v == l {
			return i
		}
	}
	return len(serverlog.Levels)
}

// serverLogs lists the active servers with something to say about their logs.
// An error is told here when it is new in the window, back after being
// resolved, or far more frequent than before; whether an alert already told it
// changes nothing. Errors of a level sent nowhere, and ignored ones, are left
// out. remind adds the settings reminder.
func (c computer) serverLogs(ctx context.Context, remind bool) ([]ServerLogDigest, error) {
	targets, err := target.NewRepo(c.s).List(ctx)
	if err != nil {
		return nil, err
	}
	repo := serverlog.NewRepo(c.s)
	// The period is counted by the time of reading, shifted by LogReadLag so that a
	// pass that is still saving its reading when the digest is computed falls in
	// the next period, not in none.
	since, until := c.since.Add(-LogReadLag), c.now.Add(-LogReadLag)
	var out []ServerLogDigest
	for _, t := range targets {
		if !t.Active {
			continue
		}
		st, err := repo.Settings(ctx, t.ID)
		if err != nil {
			return nil, err
		}
		sl := ServerLogDigest{Name: scan.SanitizeText(t.Name)}
		errs, err := repo.Window(ctx, t.ID, since, until)
		if err != nil {
			return nil, err
		}
		type entry struct {
			item  serverlog.AlertItem
			id    string
			level int
			// told first: new and back, before the frequent ones
			news bool
		}
		var list []entry
		for _, w := range errs {
			if st.Routes[w.Level] == serverlog.RouteIgnored {
				continue
			}
			var kind serverlog.AlertKind
			switch {
			case w.FirstAt.After(since) && !w.FirstAt.After(until):
				kind = serverlog.AlertNew
				sl.New++
			// Back only if it came back in the period: an error that came back days
			// ago and keeps coming is not told as back again.
			case w.Status == serverlog.StatusReopened && w.ReopenedAt.After(since) && !w.ReopenedAt.After(until):
				kind = serverlog.AlertReopened
				sl.Reopened++
			case w.Spiked:
				kind = serverlog.AlertSpike
			default:
				// No floor: after the new and back ones, the most frequent of the
				// period fill the list, which the cap bounds.
				kind = serverlog.AlertFrequent
			}
			list = append(list, entry{id: w.ID, level: levelRank(w.Level), news: kind == serverlog.AlertNew || kind == serverlog.AlertReopened, item: serverlog.AlertItem{Kind: kind, Level: w.Level,
				Type: scan.SanitizeText(w.Type), Location: scan.SanitizeText(w.Location), Count: w.Count}})
		}
		sort.SliceStable(list, func(i, j int) bool {
			a, b := list[i], list[j]
			if a.news != b.news {
				return a.news
			}
			// New and back: the most severe first. The others: the most frequent first.
			if a.news && a.level != b.level {
				return a.level < b.level
			}
			if a.item.Count != b.item.Count {
				return a.item.Count > b.item.Count
			}
			return a.item.Type+a.item.Location < b.item.Type+b.item.Location
		})
		if len(list) > MaxLogTop {
			list = list[:MaxLogTop]
		}
		for _, e := range list {
			it := e.item
			// The text follows the setting of the alerts: kept and allowed in alerts.
			if st.StoreText && st.AlertText {
				txt, ok, err := repo.Text(ctx, e.id)
				if err != nil {
					return nil, err
				}
				if ok {
					it.Text = scan.SanitizeText(txt)
				}
			}
			sl.Top = append(sl.Top, it)
		}
		notes, err := repo.Notes(ctx, t.ID)
		if err != nil {
			return nil, err
		}
		srcs, err := repo.Sources(ctx, t.ID)
		if err != nil {
			return nil, err
		}
		kept, err := repo.KeptFailures(ctx, t.ID)
		if err != nil {
			return nil, err
		}
		sl.Gaps = gapsSince(notes, c.since, srcs, kept)
		// A log that swells counts as a signal, with the rule of the level error.
		if st.Routes[serverlog.LevelError] != serverlog.RouteIgnored {
			sl.Skipped = skippedIn(notes, since, until)
		}
		// Files refused, with the rule of the level error like the volume left unread.
		if st.Routes[serverlog.LevelError] != serverlog.RouteIgnored {
			if sl.Unopened, sl.UnopenedMore, err = unopenedSources(ctx, repo, t.ID, c.since); err != nil {
				return nil, err
			}
		}
		if remind {
			sl.Deviations = serverlog.Deviations(st)
		}
		if int64(sl.New+sl.Reopened+len(sl.Top)+len(sl.Gaps)+len(sl.Deviations)+len(sl.Unopened)+sl.UnopenedMore)+sl.Skipped > 0 {
			out = append(out, sl)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// unopenedSources lists the active sources of a server with files Michel cannot
// open because the server refuses the rights, while another file of the source
// was read in the same read: the unseen list holds the refused ones, and a file
// of the source outside it has the date of that read. A source with no file read
// is a failed read, told as a gap and an alert; an absent file, a link, a folder
// or a missing tool is not about rights, and neither is the pattern itself when
// its folder is refused. A state that Michel has not seen again since the window
// began (a server not read any more) is not told as present. At most MaxLogTop
// sources are listed, the others counted in more; the files are not named, and
// neither is the path: a source is its number on the sheet and its format.
func unopenedSources(ctx context.Context, repo *serverlog.Repo, targetID string, since time.Time) (out []UnopenedSource, more int, err error) {
	srcs, err := repo.Sources(ctx, targetID)
	if err != nil {
		return nil, 0, err
	}
	unseen, err := repo.Unseen(ctx, targetID)
	if err != nil {
		return nil, 0, err
	}
	for i, src := range srcs {
		if !src.Active {
			continue
		}
		wild := strings.ContainsAny(src.Path, "*?")
		refused := map[string]bool{}
		listed := map[string]bool{}
		var at time.Time
		for _, u := range unseen[src.ID] {
			listed[u.File] = true
			if u.Cause == serverlog.CauseDenied && !(wild && u.File == src.Path) && !u.At.Before(since) {
				refused[u.File] = true
				at = u.At
			}
		}
		if len(refused) == 0 {
			continue
		}
		cursors, err := repo.Cursors(ctx, src.ID)
		if err != nil {
			return nil, 0, err
		}
		read := false
		for _, c := range cursors {
			// The placeholder of an activation is no file; a file read in an earlier
			// pass, or only located, has another date than the read that listed the
			// refused ones.
			if !strings.HasSuffix(c.File, "/") && !listed[c.File] && c.ReadAt.Equal(at) {
				read = true
				break
			}
		}
		if !read {
			continue
		}
		if len(out) == MaxLogTop {
			more++
			continue
		}
		out = append(out, UnopenedSource{Rank: i + 1, Format: src.Format, Count: len(refused)})
	}
	return out, more, nil
}

// LogGap is a period the logs of a server were not read. All says that every log
// of the server was behind; otherwise Sources names the ones that were, by their
// number on the sheet and their format (never a path or an id). Both empty: one
// of the logs, which the data cannot name. Reason is the cause the pass kept for
// the failure that made the gap, a key of serverlog.Reason*, empty when it kept
// none or only the general one.
type LogGap struct {
	From    time.Time             `json:"from"`
	To      time.Time             `json:"to"`
	All     bool                  `json:"all,omitempty"`
	Sources []serverlog.SourceRef `json:"sources,omitempty"`
	Reason  string                `json:"reason,omitempty"`
}

// failureSlack is how far from the end of a gap the date of a kept failure may
// be and still explain it: the note and the failure come from the same pass.
const failureSlack = time.Minute

// gapsSince joins the gap notes that reach into the window: periods of
// several sources that overlap are one period of the server, which names the
// sources that were behind (or says all of them were). The cause comes from the
// failures the pass kept, when one of them is of that period and of one of these
// sources or of the whole server, and only when they all agree.
func gapsSince(notes []serverlog.Note, since time.Time, srcs []serverlog.Source, kept []serverlog.KeptFailure) []LogGap {
	type part struct {
		from, to time.Time
		ids      map[string]bool
	}
	var parts []part
	for _, n := range notes {
		if n.Kind == serverlog.NoteGap && n.To.After(since) {
			parts = append(parts, part{from: n.From, to: n.To, ids: map[string]bool{n.SourceID: true}})
		}
	}
	sort.SliceStable(parts, func(i, j int) bool { return parts[i].from.Before(parts[j].from) })
	var merged []part
	for _, g := range parts {
		if last := len(merged) - 1; last >= 0 && !g.from.After(merged[last].to) {
			if g.to.After(merged[last].to) {
				merged[last].to = g.to
			}
			for id := range g.ids {
				merged[last].ids[id] = true
			}
			continue
		}
		merged = append(merged, g)
	}
	var out []LogGap
	for _, g := range merged {
		gap := LogGap{From: g.from, To: g.to}
		all := true
		for i, src := range srcs {
			switch {
			case g.ids[src.ID]:
				gap.Sources = append(gap.Sources, serverlog.SourceRef{Rank: i + 1, Format: src.Format})
			case src.Active:
				all = false
			}
		}
		// All the active logs were behind (and the one log of a server is the logs).
		if gap.All = all && len(gap.Sources) > 0; gap.All {
			gap.Sources = nil
		}
		reasons := map[string]bool{}
		for _, f := range kept {
			if (f.SourceID == "" || g.ids[f.SourceID]) && !f.At.Before(g.from) && !f.At.After(g.to.Add(failureSlack)) {
				reasons[f.Reason] = true
			}
		}
		if len(reasons) == 1 {
			for r := range reasons {
				if r != serverlog.ReasonError {
					gap.Reason = r
				}
			}
		}
		out = append(out, gap)
	}
	return out
}

// skippedIn adds up the volume left unread in the period: each note counts in the
// one period where its read ended, like the errors of that read.
func skippedIn(notes []serverlog.Note, since, until time.Time) int64 {
	var n int64
	for _, note := range notes {
		if note.Kind == serverlog.NoteSkipped && note.To.After(since) && !note.To.After(until) {
			n += note.Amount
		}
	}
	return n
}

// serverLogHead is the line of a server: its name and the counts.
func serverLogHead(lang i18n.Lang, s ServerLogDigest) string {
	var parts []string
	if s.New > 0 {
		parts = append(parts, i18n.N(lang, "digest.serverlogs.new", s.New))
	}
	if s.Reopened > 0 {
		parts = append(parts, i18n.N(lang, "digest.serverlogs.reopened", s.Reopened))
	}
	if len(parts) == 0 {
		return s.Name
	}
	sep := ": "
	if lang == i18n.FR {
		sep = " : "
	}
	return s.Name + sep + strings.Join(parts, ", ")
}

// serverLogItem is one error of the list: its type, where, how many times and
// why it is told. No dash: the template adds the bullet. The source of a log is never shown.
func serverLogItem(lang i18n.Lang, it serverlog.AlertItem) string {
	label := scan.SanitizeText(it.Type)
	if loc := scan.SanitizeText(it.Location); loc != "" {
		if label != "" {
			label += ", "
		}
		label += loc
	}
	if label == "" {
		label = i18n.T(lang, "notify.log.unnamed")
	}
	line := label
	if it.Count > 0 {
		line = i18n.N(lang, "notify.log.times", int(it.Count), label)
	}
	if it.Kind == serverlog.AlertFrequent {
		// Neither new nor back: the count says enough.
		return line
	}
	return line + " (" + i18n.T(lang, "notify.log.why."+string(it.Kind)) + ")"
}

// serverLogGap says from when to when the logs were not read, which of them, and
// why when the pass kept the cause. The hours are the computer's own, like the
// rest of what the person reads; none says "UTC".
func serverLogGap(lang i18n.Lang, g LogGap) string {
	layout := i18n.T(lang, "digest.serverlogs.moment_layout")
	var what string
	switch {
	case g.All:
		what = i18n.T(lang, "digest.serverlogs.gap_what.all")
	case len(g.Sources) > 0:
		labels := make([]string, len(g.Sources))
		for i, s := range g.Sources {
			labels[i] = SourceLabel(lang, s)
		}
		what = strings.Join(labels[:len(labels)-1], ", ")
		if what != "" {
			what += " " + i18n.T(lang, "digest.serverlogs.and") + " "
		}
		what += labels[len(labels)-1]
	default:
		what = i18n.T(lang, "digest.serverlogs.gap_what.one")
	}
	why := i18n.T(lang, "digest.serverlogs.gap_unknown")
	if g.Reason != "" && g.Reason != serverlog.ReasonError {
		why = i18n.T(lang, "notify.log.reason."+g.Reason)
	}
	return i18n.T(lang, "digest.serverlogs.gap", g.From.In(time.Local).Format(layout), g.To.In(time.Local).Format(layout), what, why)
}

// serverLogSkipped says how much of the logs of a server was left unread.
func serverLogSkipped(lang i18n.Lang, n int64) string {
	size := serverlog.ByteSize(n)
	if lang == i18n.FR {
		size = strings.NewReplacer("GiB", "Gio", "MiB", "Mio", "KiB", "Kio", " B", " o").Replace(size)
	}
	return i18n.T(lang, "digest.serverlogs.skipped", size)
}

// serverLogUnopened says that some files of a source cannot be opened.
func serverLogUnopened(lang i18n.Lang, u UnopenedSource) string {
	of := sourceOf(lang, u.Rank, u.Format)
	return i18n.N(lang, "digest.serverlogs.unopened", u.Count, of)
}

// serverLogUnopenedMore counts the sources in that case that the list left out.
func serverLogUnopenedMore(lang i18n.Lang, n int) string {
	return i18n.N(lang, "digest.serverlogs.unopened_more", n)
}

// serverLogDeviations is the weekly reminder about the settings of a server.
func serverLogDeviations(lang i18n.Lang, s ServerLogDigest) string {
	var parts []string
	for _, k := range s.Deviations {
		switch k {
		case serverlog.DeviationStoreText:
			parts = append(parts, i18n.T(lang, "digest.serverlogs.deviation.store_text"))
		case serverlog.DeviationAlertText:
			parts = append(parts, i18n.T(lang, "digest.serverlogs.deviation.alert_text"))
		case serverlog.DeviationRetention:
			parts = append(parts, i18n.T(lang, "digest.serverlogs.deviation.retention"))
		}
	}
	return i18n.T(lang, "digest.serverlogs.deviations", strings.Join(parts, " "))
}
