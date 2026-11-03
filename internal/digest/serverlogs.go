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
	// Gaps are the periods the logs were not read; the notes of the sources
	// of the server that overlap are joined into one.
	Gaps []serverlog.Note `json:"gaps,omitempty"`
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
			case w.Count >= serverlog.FrequentMin:
				kind = serverlog.AlertFrequent
			default:
				continue
			}
			list = append(list, entry{id: w.ID, level: levelRank(w.Level), news: kind == serverlog.AlertNew || kind == serverlog.AlertReopened, item: serverlog.AlertItem{Kind: kind, Level: w.Level,
				Type: scan.SanitizeText(w.Type), Location: scan.SanitizeText(w.Location), Count: w.Count}})
		}
		sort.SliceStable(list, func(i, j int) bool {
			a, b := list[i], list[j]
			if a.news != b.news {
				return a.news
			}
			if a.level != b.level {
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
		sl.Gaps = gapsSince(notes, c.since)
		if remind {
			sl.Deviations = serverlog.Deviations(st)
		}
		if sl.New+sl.Reopened+len(sl.Top)+len(sl.Gaps)+len(sl.Deviations) > 0 {
			out = append(out, sl)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// gapsSince joins the gap notes that reach into the window: periods of
// several sources that overlap are one period of the server.
func gapsSince(notes []serverlog.Note, since time.Time) []serverlog.Note {
	var gaps []serverlog.Note
	for _, n := range notes {
		if n.Kind == serverlog.NoteGap && n.To.After(since) {
			gaps = append(gaps, serverlog.Note{Kind: serverlog.NoteGap, From: n.From, To: n.To})
		}
	}
	sort.SliceStable(gaps, func(i, j int) bool { return gaps[i].From.Before(gaps[j].From) })
	var out []serverlog.Note
	for _, g := range gaps {
		if last := len(out) - 1; last >= 0 && !g.From.After(out[last].To) {
			if g.To.After(out[last].To) {
				out[last].To = g.To
			}
			continue
		}
		out = append(out, g)
	}
	return out
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
	return line + " (" + i18n.T(lang, "notify.log.why."+string(it.Kind)) + ")"
}

// serverLogGap says from when to when the logs were not read.
func serverLogGap(lang i18n.Lang, g serverlog.Note) string {
	layout := i18n.T(lang, "digest.serverlogs.moment_layout")
	return i18n.T(lang, "digest.serverlogs.gap", g.From.UTC().Format(layout), g.To.UTC().Format(layout))
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
