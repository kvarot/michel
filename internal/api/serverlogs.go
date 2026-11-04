package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/serverlog"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/target"
)

// The routes of the server logs (spec § 11). Nothing here returns a log line:
// the errors are fields of known form, and their text only when the settings
// of the server allow it. An answer never repeats what a server printed.
func (s *server) logRoutes() {
	m := s.mux
	m.HandleFunc("GET /api/v1/targets/{id}/logs/sources", s.logSources)
	m.HandleFunc("POST /api/v1/targets/{id}/logs/sources", s.logSourceAdd)
	m.HandleFunc("POST /api/v1/targets/{id}/logs/sources/discover", s.logSourceDiscover)
	m.HandleFunc("POST /api/v1/targets/{id}/logs/sources/try", s.logSourceTry)
	m.HandleFunc("PATCH /api/v1/targets/{id}/logs/sources/{source}", s.logSourcePatch)
	m.HandleFunc("DELETE /api/v1/targets/{id}/logs/sources/{source}", s.logSourceDelete)
	m.HandleFunc("GET /api/v1/targets/{id}/logs/errors", s.logErrors)
	m.HandleFunc("PATCH /api/v1/targets/{id}/logs/errors/{signature}", s.logErrorPatch)
	m.HandleFunc("GET /api/v1/targets/{id}/logs/settings", s.logSettings)
	m.HandleFunc("PATCH /api/v1/targets/{id}/logs/settings", s.logSettingsPatch)
	m.HandleFunc("POST /api/v1/targets/{id}/logs/purge", s.logPurge)
}

// ---- views -----------------------------------------------------------------

// LogSourceView is a declared log source. NoChannel and Warning say that it is
// read but nobody could be told about its errors.
type LogSourceView struct {
	ID           string        `json:"id"`
	Path         string        `json:"path"`
	Format       string        `json:"format"`
	LevelField   string        `json:"level_field"`
	ChannelField string        `json:"channel_field"`
	Pattern      string        `json:"pattern"`
	Active       bool          `json:"active"`
	CreatedAt    string        `json:"created_at"`
	LastReadAt   string        `json:"last_read_at"`
	Notes        []LogNoteView `json:"notes"`
	// Unseen lists the files of the source that the last read could not open,
	// by path and why. LastReadAt leaves them out.
	Unseen []TargetUnseenView `json:"unseen"`
	// Failure is why the last read of the source failed, in a sentence ("" when
	// the last read did not fail, or the source is turned off). The cause of a
	// connection that failed is the server's, so every active source carries it.
	Failure string `json:"failure,omitempty"`
	// Note is a word of advice for the format (PostgreSQL's %e), when it has one.
	Note      string `json:"note,omitempty"`
	NoChannel bool   `json:"no_channel"`
	Warning   string `json:"warning,omitempty"`
}

// LogNoteView is what Michel could not read, or left out, in a source: the
// latest note of each kind, in a sentence.
type LogNoteView struct {
	Kind   string `json:"kind"`
	Text   string `json:"text"`
	From   string `json:"from"`
	To     string `json:"to"`
	Amount int64  `json:"amount,omitempty"`
}

// LogCandidateView is a log Michel proposes; nothing is created. Note is set
// when the format needs a word of advice (PostgreSQL's %e).
type LogCandidateView struct {
	Path   string `json:"path"`
	Format string `json:"format"`
	Why    string `json:"why"`
	Text   string `json:"text"`
	Known  bool   `json:"known"`
	Note   string `json:"note,omitempty"`
}

// LogRecordView is a group of identical errors the filter returned: fields of
// known form, the cleaned text only when the settings keep it.
type LogRecordView struct {
	Level    string `json:"level"`
	Type     string `json:"type"`
	Location string `json:"location"`
	Channel  string `json:"channel"`
	Text     string `json:"text,omitempty"`
	Hour     string `json:"hour"`
	Count    int64  `json:"count"`
}

// LogTryView is exactly what a read of a source would bring back, from the
// start of its files and within the caps. Unseen lists the files Michel could
// not open, by path (the paths of the declared source) and why. Nothing of it
// is stored.
type LogTryView struct {
	Records      []LogRecordView    `json:"records"`
	Rejected     int                `json:"rejected"`
	Files        int                `json:"files"`
	SkippedBytes int64              `json:"skipped_bytes"`
	TooManyFiles bool               `json:"too_many_files"`
	None         bool               `json:"none"`
	Unseen       []TargetUnseenView `json:"unseen"`
	Message      string             `json:"message,omitempty"`
	Note         string             `json:"note,omitempty"`
}

// LogErrorView is a recurring error. Detail is the SSH command to run to see
// the lines yourself: the file and the date, no content.
type LogErrorView struct {
	ID       string `json:"id"`
	SourceID string `json:"source_id"`
	Level    string `json:"level"`
	Type     string `json:"type"`
	Location string `json:"location"`
	Channel  string `json:"channel"`
	Status   string `json:"status"`
	FirstAt  string `json:"first_at"`
	LastAt   string `json:"last_at"`
	Total    int64  `json:"total"`
	Text     string `json:"text,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// LogErrorsView is the answer of GET /logs/errors: the latest errors, and whether
// the list was cut (Total is how many there are).
type LogErrorsView struct {
	Errors    []LogErrorView `json:"errors"`
	Total     int            `json:"total"`
	Truncated bool           `json:"truncated"`
}

// LogDeviationView is a setting away from the recommended choice, with the
// risk in plain words.
type LogDeviationView struct {
	Code string `json:"code"`
	Text string `json:"text"`
}

// LogRecommendedView is the recommended choice of the privacy settings.
type LogRecommendedView struct {
	StoreText     bool `json:"store_text"`
	AlertText     bool `json:"alert_text"`
	RetentionDays int  `json:"retention_days"`
}

// LogSettingsView is the log settings of a server. Interval is "manual" or a
// duration like 5m or 2h.
type LogSettingsView struct {
	Interval           string             `json:"interval"`
	IntervalNote       string             `json:"interval_note,omitempty"`
	StoreText          bool               `json:"store_text"`
	AlertText          bool               `json:"alert_text"`
	RetentionDays      int                `json:"retention_days"`
	ResolveAfterDays   int                `json:"resolve_after_days"`
	ReadCapBytes       int64              `json:"read_cap_bytes"`
	ReadTimeoutSeconds int                `json:"read_timeout_seconds"`
	MaxAlertsPerHour   int                `json:"max_alerts_per_hour"`
	SMS                bool               `json:"sms"`
	Routes             map[string]string  `json:"routes"`
	SpikeFactor        int                `json:"spike_factor"`
	SpikeMin           int64              `json:"spike_min"`
	Recommended        LogRecommendedView `json:"recommended"`
	Deviations         []LogDeviationView `json:"deviations"`
	// Health is the stronger warning of a server that holds health data, set
	// while a setting is away from the recommended choice.
	Health string `json:"health,omitempty"`
}

// LogConfirmBody answers 409 when a setting moves away from the recommended
// choice and the request did not say confirmed. Deviations are the new steps
// away, with the risk of each.
type LogConfirmBody struct {
	Error      string             `json:"error"`
	Hint       string             `json:"hint,omitempty"`
	Code       string             `json:"code"`
	Deviations []LogDeviationView `json:"deviations"`
	Health     string             `json:"health,omitempty"`
}

// logConfirmCode is the code of LogConfirmBody, a contract of the page.
const logConfirmCode = "logs.confirm_needed"

// LogSourceBody is the body of POST /logs/sources and /logs/sources/try.
// Active defaults to true.
type LogSourceBody struct {
	Path         string `json:"path"`
	Format       string `json:"format"`
	LevelField   string `json:"level_field"`
	ChannelField string `json:"channel_field"`
	Pattern      string `json:"pattern"`
	Active       *bool  `json:"active"`
}

// LogSourcePatch is the body of PATCH /logs/sources/{source}.
type LogSourcePatch struct {
	Path         *string `json:"path"`
	Format       *string `json:"format"`
	LevelField   *string `json:"level_field"`
	ChannelField *string `json:"channel_field"`
	Pattern      *string `json:"pattern"`
	Active       *bool   `json:"active"`
}

// LogErrorPatch is the body of PATCH /logs/errors/{signature}: seen or ignored.
type LogErrorPatch struct {
	Status string `json:"status"`
}

// LogSettingsPatch is the body of PATCH /logs/settings. Confirmed must be true
// for a step away from the recommended choice.
type LogSettingsPatch struct {
	Interval           *string           `json:"interval"`
	StoreText          *bool             `json:"store_text"`
	AlertText          *bool             `json:"alert_text"`
	RetentionDays      *int              `json:"retention_days"`
	ResolveAfterDays   *int              `json:"resolve_after_days"`
	ReadCapBytes       *int64            `json:"read_cap_bytes"`
	ReadTimeoutSeconds *int              `json:"read_timeout_seconds"`
	MaxAlertsPerHour   *int              `json:"max_alerts_per_hour"`
	SMS                *bool             `json:"sms"`
	SpikeFactor        *int              `json:"spike_factor"`
	SpikeMin           *int64            `json:"spike_min"`
	Routes             map[string]string `json:"routes"`
	Confirmed          bool              `json:"confirmed"`
}

// LogPurgeBody is the body of POST /logs/purge: scope "all" (the default, the
// ignored choices included) or "text".
type LogPurgeBody struct {
	Scope string `json:"scope"`
}

// ---- helpers ------------------------------------------------------------------

func (s *server) serverLogs() *serverlog.Repo { return serverlog.NewRepo(s.deps.Store) }

// logTarget reads the language and the server of the route; it answers 400 or
// 404 itself.
func (s *server) logTarget(w http.ResponseWriter, r *http.Request) (i18n.Lang, target.Target, bool) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return lang, target.Target{}, false
	}
	t, ok := s.targetOf(w, r, lang)
	return lang, t, ok
}

// logRefused answers a coded refusal; the key's _hint, when there is one, is
// the hint. Nothing of the request is repeated.
func (s *server) logRefused(w http.ResponseWriter, status int, lang i18n.Lang, key string) {
	s.failedBody(w, status, lang, key, key+"_hint")
}

// logAudit records a change of the log routes; it never carries a log content.
func (s *server) logAudit(ctx context.Context, action, targetID string, ev map[string]any) error {
	return s.targetAudit(ctx, action, targetID, "ok", ev)
}

// LogChannelHears says whether some channel can tell about the errors of a
// server: enabled, not limited to some projects (those never hear about
// servers), and an SMS only if the server ticks it and the channel is urgent.
func LogChannelHears(p policy.Policy, st serverlog.Settings) bool {
	for _, c := range p.Notify.Channels {
		if !c.IsEnabled() || len(c.Projects) > 0 {
			continue
		}
		if c.Type == policy.ChannelSMS && !(st.SMS && c.Urgent) {
			continue
		}
		return true
	}
	return false
}

// LogPath writes a declared path for the page: no control character, no path of
// this computer. The user's own declaration is otherwise shown as it is, since
// it is what the page sends back.
func LogPath(p string) string { return localPaths(srvText("", p)) }

func noteTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

// noteText is the sentence of a note.
func noteText(lang i18n.Lang, n serverlog.Note) string {
	switch n.Kind {
	case serverlog.NoteGap:
		return i18n.T(lang, "api.logs.note.gap", noteTime(n.From), noteTime(n.To))
	case serverlog.NoteSkipped:
		return i18n.T(lang, "api.logs.note.skipped", serverlog.ByteSize(n.Amount))
	case serverlog.NoteRotated:
		return i18n.T(lang, "api.logs.note.rotated")
	case serverlog.NoteUnseen:
		return i18n.N(lang, "api.logs.note.unseen", int(n.Amount))
	case serverlog.NoteRejected:
		return i18n.T(lang, "api.logs.note.rejected")
	case serverlog.NoteTooManyFiles:
		return i18n.T(lang, "api.logs.note.too_many_files")
	}
	return ""
}

// whyText is the sentence of a proposal, by the reason Discover gives.
func whyText(lang i18n.Lang, why string) string {
	switch why {
	case serverlog.WhyPHPCLI:
		return i18n.T(lang, "api.logs.why.php_error_log_cli")
	case serverlog.WhyPHPFPM:
		return i18n.T(lang, "api.logs.why.php_error_log_fpm")
	case serverlog.WhyPHPPool:
		return i18n.T(lang, "api.logs.why.php_error_log_pool")
	case serverlog.WhyPostgres:
		return i18n.T(lang, "api.logs.why.postgresql_default_folder")
	case serverlog.WhyAppStorage:
		return i18n.T(lang, "api.logs.why.project_storage_logs")
	case serverlog.WhyAppVarLog:
		return i18n.T(lang, "api.logs.why.project_var_log")
	}
	return ""
}

// formatNote is the word of advice a format needs, "" for the others: the
// PostgreSQL error code is read only when %e is the last part of the prefix.
func formatNote(lang i18n.Lang, f serverlog.Format) string {
	if f == serverlog.FormatPostgres {
		return i18n.T(lang, "api.logs.postgres_prefix")
	}
	return ""
}

func validFormat(f serverlog.Format) bool {
	switch f {
	case serverlog.FormatPHP, serverlog.FormatPostgres, serverlog.FormatMonolog, serverlog.FormatJSON, serverlog.FormatText:
		return true
	}
	return false
}

// checkLogSource refuses a source the filter would refuse, with a coded
// answer that does not repeat it (400); false when it answered.
func (s *server) checkLogSource(w http.ResponseWriter, lang i18n.Lang, src serverlog.Source) bool {
	switch {
	case !validFormat(src.Format):
		s.logRefused(w, http.StatusBadRequest, lang, "api.logs.bad_format")
	case serverlog.ValidatePath(src.Path) != nil:
		s.logRefused(w, http.StatusBadRequest, lang, "api.logs.bad_path")
	default:
		// The script is what reads: whatever it would refuse (a JSON source without
		// its level field, a pattern with odd characters) is refused now.
		if _, err := serverlog.Script(src, nil, serverlog.FilterOptions{}); err != nil {
			s.logRefused(w, http.StatusBadRequest, lang, "api.logs.bad_source")
			return false
		}
		return true
	}
	return false
}

// logSourceOf finds the source of the route's {source} among those of t.
func (s *server) logSourceOf(w http.ResponseWriter, r *http.Request, lang i18n.Lang, t target.Target) (serverlog.Source, []serverlog.Source, bool) {
	all, err := s.serverLogs().Sources(r.Context(), t.ID)
	if err != nil {
		s.internal(w, r)
		return serverlog.Source{}, nil, false
	}
	for _, src := range all {
		if src.ID == r.PathValue("source") {
			return src, all, true
		}
	}
	s.logRefused(w, http.StatusNotFound, lang, "api.logs.source_not_found")
	return serverlog.Source{}, nil, false
}

// LogUnseenReason is the sentence for why a file was not read, by the cause code
// the filter wrote (serverlog.Cause*): the real cause, in plain words, so that a
// refused link does not read as a rights problem.
func LogUnseenReason(lang i18n.Lang, cause string) string {
	switch cause {
	case serverlog.CauseDenied:
		return i18n.T(lang, "api.logs.unseen.denied")
	case serverlog.CauseLink:
		return i18n.T(lang, "api.logs.unseen.link")
	case serverlog.CauseAbsent:
		return i18n.T(lang, "api.logs.unseen.absent")
	case serverlog.CauseNotFile:
		return i18n.T(lang, "api.logs.unseen.not_file")
	case serverlog.CauseTools:
		return i18n.T(lang, "api.logs.unseen.tools")
	}
	return i18n.T(lang, "api.logs.unseen.other")
}

// LogFailureText is the sentence for why a read failed, by the key the pass kept
// (serverlog.Reason*). A key this page does not know reads as the general
// cause, which says what can be tried.
func LogFailureText(lang i18n.Lang, reason string) string {
	switch reason {
	case serverlog.ReasonNoAgent, serverlog.ReasonNoKeyAccepted, serverlog.ReasonHostKeyUnknown, serverlog.ReasonHostKeyChanged,
		serverlog.ReasonDenied, serverlog.ReasonTimeout, serverlog.ReasonRefused, serverlog.ReasonPolicy, serverlog.ReasonOutputCut, serverlog.ReasonTools:
		return i18n.T(lang, "api.logs.failure."+reason)
	}
	return i18n.T(lang, "api.logs.failure."+serverlog.ReasonError)
}

// LogNoteText is the sentence of a note of a source.
func LogNoteText(lang i18n.Lang, n serverlog.Note) string { return noteText(lang, n) }

// LogStateNotes are the notes of a source worth showing now, oldest kind first:
// the latest of each kind. A note about a state (too many files) shows only
// while the last read still found it: touched is the date of the last read of
// the source. The unseen files have their own list, so their note is left out.
func LogStateNotes(notes []serverlog.Note, sourceID string, touched time.Time) []serverlog.Note {
	latest := map[string]serverlog.Note{}
	for _, n := range notes {
		if n.SourceID == sourceID {
			latest[n.Kind] = n
		}
	}
	var out []serverlog.Note
	for _, kind := range []string{serverlog.NoteGap, serverlog.NoteSkipped, serverlog.NoteRotated, serverlog.NoteRejected, serverlog.NoteTooManyFiles} {
		n, ok := latest[kind]
		if !ok || (kind == serverlog.NoteTooManyFiles && n.To.Before(touched)) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// LogLastRead is when a source was last read for real: the latest read date of
// its files. A pass that opened nothing moves no date (the reader leaves them), a
// file located but never opened has none, and the placeholder of an activation
// is no file.
func LogLastRead(cursors []serverlog.Cursor) time.Time {
	var last time.Time
	for _, c := range cursors {
		if !strings.HasSuffix(c.File, "/") && c.ReadAt.After(last) {
			last = c.ReadAt
		}
	}
	return last
}

// sourceViews builds the views of the sources of t.
func (s *server) sourceViews(ctx context.Context, lang i18n.Lang, t target.Target, srcs []serverlog.Source) ([]LogSourceView, error) {
	repo := s.serverLogs()
	st, err := repo.Settings(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	notes, err := repo.Notes(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	unseen, err := repo.Unseen(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	failures, err := repo.Failures(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	hears := LogChannelHears(s.currentPolicy(), st)
	out := make([]LogSourceView, 0, len(srcs))
	for _, src := range srcs {
		cursors, err := repo.Cursors(ctx, src.ID)
		if err != nil {
			return nil, err
		}
		var touched time.Time
		for _, c := range cursors {
			if c.ReadAt.After(touched) {
				touched = c.ReadAt
			}
		}
		v := LogSourceView{ID: src.ID, Path: LogPath(src.Path), Format: string(src.Format), LevelField: srvText("", src.LevelField),
			ChannelField: srvText("", src.ChannelField), Pattern: srvText("", src.Pattern), Active: src.Active,
			CreatedAt: stamp(src.CreatedAt), LastReadAt: stamp(LogLastRead(cursors)), Notes: []LogNoteView{},
			Unseen: []TargetUnseenView{}, Note: formatNote(lang, src.Format)}
		for _, n := range LogStateNotes(notes, src.ID, touched) {
			v.Notes = append(v.Notes, LogNoteView{Kind: n.Kind, Text: noteText(lang, n), From: stamp(n.From), To: stamp(n.To), Amount: n.Amount})
		}
		for _, u := range unseen[src.ID] {
			v.Unseen = append(v.Unseen, TargetUnseenView{What: LogPath(u.File), Reason: LogUnseenReason(lang, u.Cause)})
		}
		if src.Active {
			reason, failed := failures[src.ID]
			if !failed {
				reason, failed = failures[""]
			}
			if failed {
				v.Failure = LogFailureText(lang, reason)
			}
		}
		if src.Active && !hears {
			v.NoChannel, v.Warning = true, i18n.T(lang, "api.logs.no_channel")
		}
		out = append(out, v)
	}
	return out, nil
}

// logSummary fills the log fields of a server's view: the errors not seen, the
// settings away from the recommended choice, and a server read with no way to
// tell anyone.
func (s *server) logSummary(ctx context.Context, t target.Target, v *TargetView) error {
	repo := s.serverLogs()
	st, err := repo.Settings(ctx, t.ID)
	if err != nil {
		return err
	}
	v.LogDeviations = append([]string{}, serverlog.Deviations(st)...)
	srcs, err := repo.Sources(ctx, t.ID)
	if err != nil {
		return err
	}
	if len(srcs) == 0 {
		return nil
	}
	for _, src := range srcs {
		if src.Active {
			v.LogNoChannel = !LogChannelHears(s.currentPolicy(), st)
		}
	}
	if v.LogNew, err = repo.CountNew(ctx, t.ID); err != nil {
		return err
	}
	return nil
}

// ---- the SSH command that shows the lines ---------------------------------------

var (
	safeWordRe = regexp.MustCompile(`^[A-Za-z0-9._@:/+=,~%-]+$`)
	// plainArgRe is a name given to ssh (an alias, a user, a host): it cannot start with
	// a dash, or ssh would read it as an option (-oProxyCommand=...).
	plainArgRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._@:/+=,~%-]*$`)
	termTypeRe  = regexp.MustCompile(`^[A-Za-z_\\][A-Za-z0-9_\\]{0,127}$`)
	termPlaceRe = regexp.MustCompile(`^[A-Za-z0-9_.-][A-Za-z0-9_./-]{0,199}\.[A-Za-z]+:[0-9]{1,6}$`)
)

// shq writes s as one shell word: as it is when plain, else in single quotes.
func shq(s string) string {
	if s != "" && safeWordRe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// globWord writes a path as shell words, quoting all of it except its
// wildcards, which must stay wildcards.
func globWord(p string) string {
	var b strings.Builder
	start := 0
	for i := 0; i < len(p); i++ {
		if p[i] != '*' && p[i] != '?' {
			continue
		}
		if i > start {
			b.WriteString(shq(p[start:i]))
		}
		b.WriteByte(p[i])
		start = i + 1
	}
	if start < len(p) {
		b.WriteString(shq(p[start:]))
	}
	return b.String()
}

// detailCommand is the SSH command to run oneself to see the lines of an
// error: the lines of its day in the file (or the files) of its source, the
// ones that hold its type or its file, the last 50. It holds the file and the
// date, never a line of the log: the search words are the extracted fields, and
// only if they have the plain form of the filter's own output.
func detailCommand(t target.Target, src serverlog.Source, g serverlog.Signature) string {
	var ssh string
	switch {
	case t.Alias != "" && plainArgRe.MatchString(t.Alias):
		ssh = "ssh " + t.Alias
	case t.Host != "" && plainArgRe.MatchString(t.Host) && (t.User == "" || plainArgRe.MatchString(t.User)):
		ssh = "ssh"
		if t.Port != 0 && t.Port != 22 {
			ssh += fmt.Sprintf(" -p %d", t.Port)
		}
		host := t.Host
		if t.User != "" {
			host = t.User + "@" + host
		}
		ssh += " " + host
	default:
		return ""
	}
	layout := "2006-01-02"
	if src.Format == serverlog.FormatPHP {
		layout = "02-Jan-2006"
	}
	remote := "grep -a -h -F -e " + shq(g.LastAt.UTC().Format(layout)) + " " + globWord(src.Path)
	term := ""
	switch {
	case g.Type != "" && termTypeRe.MatchString(g.Type):
		term = g.Type
	case termPlaceRe.MatchString(g.Location):
		term = path.Base(g.Location[:strings.LastIndexByte(g.Location, ':')])
	}
	if term != "" {
		remote += " | grep -a -F -e " + shq(term)
	}
	remote += " | tail -n 50"
	return ssh + " " + shq(remote)
}

// ---- sources --------------------------------------------------------------------

func (s *server) logSources(w http.ResponseWriter, r *http.Request) {
	lang, t, ok := s.logTarget(w, r)
	if !ok {
		return
	}
	srcs, err := s.serverLogs().Sources(r.Context(), t.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	out, err := s.sourceViews(r.Context(), lang, t, srcs)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) logSourceAdd(w http.ResponseWriter, r *http.Request) {
	lang, t, ok := s.logTarget(w, r)
	if !ok {
		return
	}
	var b LogSourceBody
	if !s.readJSON(w, r, &b) {
		return
	}
	src := serverlog.Source{TargetID: t.ID, Path: strings.TrimSpace(b.Path), Format: serverlog.Format(strings.TrimSpace(b.Format)),
		LevelField: strings.TrimSpace(b.LevelField), ChannelField: strings.TrimSpace(b.ChannelField), Pattern: strings.TrimSpace(b.Pattern),
		Active: b.Active == nil || *b.Active}
	if !s.checkLogSource(w, lang, src) {
		return
	}
	ctx := r.Context()
	repo := s.serverLogs()
	existing, err := repo.Sources(ctx, t.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	for _, e := range existing {
		if e.Path == src.Path {
			s.logRefused(w, http.StatusConflict, lang, "api.logs.duplicate_source")
			return
		}
	}
	added, err := repo.AddSource(ctx, src)
	if err != nil {
		s.internal(w, r)
		return
	}
	if err := s.logAudit(ctx, "log.source_add", t.ID, map[string]any{"source": added.ID, "path": added.Path, "format": string(added.Format), "active": added.Active}); err != nil {
		s.internal(w, r)
		return
	}
	views, err := s.sourceViews(ctx, lang, t, []serverlog.Source{added})
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusCreated, views[0])
}

func (s *server) logSourcePatch(w http.ResponseWriter, r *http.Request) {
	lang, t, ok := s.logTarget(w, r)
	if !ok {
		return
	}
	var p LogSourcePatch
	if !s.readJSON(w, r, &p) {
		return
	}
	src, all, ok := s.logSourceOf(w, r, lang, t)
	if !ok {
		return
	}
	old := src
	var changed []string
	str := func(v *string, name string, dst *string) {
		if v != nil {
			*dst = strings.TrimSpace(*v)
			changed = append(changed, name)
		}
	}
	str(p.Path, "path", &src.Path)
	str(p.LevelField, "level_field", &src.LevelField)
	str(p.ChannelField, "channel_field", &src.ChannelField)
	str(p.Pattern, "pattern", &src.Pattern)
	if p.Format != nil {
		src.Format = serverlog.Format(strings.TrimSpace(*p.Format))
		changed = append(changed, "format")
	}
	if p.Active != nil {
		src.Active = *p.Active
		changed = append(changed, "active")
	}
	if !s.checkLogSource(w, lang, src) {
		return
	}
	for _, e := range all {
		if e.ID != src.ID && e.Path == src.Path {
			s.logRefused(w, http.StatusConflict, lang, "api.logs.duplicate_source")
			return
		}
	}
	ctx := r.Context()
	repo := s.serverLogs()
	// Another file, or a source turned on again after being off, is a first
	// reading: Michel starts from the end of the files and does not replay what
	// was written meanwhile (spec § 5.2). The positions are forgotten with the
	// change, in one step, and not while a read runs (it would write them back).
	reset := src.Path != old.Path || (src.Active && !old.Active)
	if reset {
		unlock, free := serverlog.TryLock(t.ID)
		if !free {
			s.logRefused(w, http.StatusConflict, lang, "api.logs.busy")
			return
		}
		defer unlock()
	}
	if err := repo.UpdateSourceReset(ctx, src, reset, s.deps.Now()); err != nil {
		s.internal(w, r)
		return
	}
	ev := map[string]any{"source": src.ID, "changed": changed, "active": src.Active}
	if src.Path != old.Path {
		ev["path"] = src.Path
	}
	if err := s.logAudit(ctx, "log.source_update", t.ID, ev); err != nil {
		s.internal(w, r)
		return
	}
	views, err := s.sourceViews(ctx, lang, t, []serverlog.Source{src})
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, views[0])
}

// logSourceDelete takes the source out of Michel, with its errors and counts.
// Nothing is done on the server.
func (s *server) logSourceDelete(w http.ResponseWriter, r *http.Request) {
	lang, t, ok := s.logTarget(w, r)
	if !ok {
		return
	}
	src, _, ok := s.logSourceOf(w, r, lang, t)
	if !ok {
		return
	}
	unlock, free := serverlog.TryLock(t.ID)
	if !free {
		s.logRefused(w, http.StatusConflict, lang, "api.logs.busy")
		return
	}
	defer unlock()
	if err := s.serverLogs().DeleteSource(r.Context(), src.ID); err != nil {
		if errors.Is(err, serverlog.ErrNotFound) {
			s.logRefused(w, http.StatusNotFound, lang, "api.logs.source_not_found")
			return
		}
		s.internal(w, r)
		return
	}
	if err := s.logAudit(r.Context(), "log.source_remove", t.ID, map[string]any{"source": src.ID, "format": string(src.Format)}); err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"removed": true})
}

// logSourceDiscover proposes sources from what the last collection saw and
// from the usual places. It reads the database only and creates nothing.
func (s *server) logSourceDiscover(w http.ResponseWriter, r *http.Request) {
	lang, t, ok := s.logTarget(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	cands, err := serverlog.Discover(ctx, s.targets(), t)
	if err != nil {
		s.internal(w, r)
		return
	}
	existing, err := s.serverLogs().Sources(ctx, t.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	known := map[string]bool{}
	for _, e := range existing {
		known[e.Path] = true
	}
	out := []LogCandidateView{}
	for _, c := range cands {
		out = append(out, LogCandidateView{Path: LogPath(c.Path), Format: string(c.Format), Why: c.Why, Text: whyText(lang, c.Why),
			Known: known[c.Path], Note: formatNote(lang, c.Format)})
	}
	writeJSON(w, http.StatusOK, out)
}

// logSourceTry runs the filter once on the server and shows exactly what would
// come back. It stores nothing and moves no position.
func (s *server) logSourceTry(w http.ResponseWriter, r *http.Request) {
	lang, t, ok := s.logTarget(w, r)
	if !ok || !s.reachable(w, lang) {
		return
	}
	var b LogSourceBody
	if !s.readJSON(w, r, &b) {
		return
	}
	src := serverlog.Source{ID: "try", TargetID: t.ID, Path: strings.TrimSpace(b.Path), Format: serverlog.Format(strings.TrimSpace(b.Format)),
		LevelField: strings.TrimSpace(b.LevelField), ChannelField: strings.TrimSpace(b.ChannelField), Pattern: strings.TrimSpace(b.Pattern), Active: true}
	if !s.checkLogSource(w, lang, src) {
		return
	}
	if !t.Active {
		s.targetRefused(w, r, lang, servercheck.ErrInactive, false)
		return
	}
	ctx := r.Context()
	st, err := s.serverLogs().Settings(ctx, t.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	links, err := s.targets().Links(ctx, t.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	o := serverlog.FilterOptions{Text: st.StoreText, ReadCap: st.ReadCap}
	for _, l := range links {
		o.RemoteDirs = append(o.RemoteDirs, l.RemoteDir)
	}
	extend(w)
	dctx, cancel := s.detached(r)
	defer cancel()
	// Every try is one audit row, success or failure: the path read (it is not a
	// declared source), the format, and numbers. The detached context writes it
	// even when the page has gone.
	trace := func(result string, ev map[string]any) error {
		ev["try"], ev["path"], ev["format"] = true, src.Path, string(src.Format)
		return s.targetAudit(dctx, "log.read", t.ID, result, ev)
	}
	client, err := sshx.Dial(dctx, s.deps.Servers.Check.SSH, t)
	if err != nil {
		_ = trace("failed", map[string]any{"reason": serverlog.ReasonOf(err)})
		s.targetRefused(w, r, lang, err, true)
		return
	}
	defer client.Close()
	now := s.deps.Now()
	out, err := serverlog.Try(dctx, client, src, o, st.ReadTimeout, now)
	if err != nil {
		_ = trace("failed", map[string]any{"reason": serverlog.ReasonOf(err)})
		// What the server printed is not repeated: only the sentence.
		s.logRefused(w, http.StatusBadGateway, lang, "api.logs.try_failed")
		return
	}
	v := LogTryView{Records: []LogRecordView{}, Unseen: []TargetUnseenView{}, Rejected: out.Rejected, Files: len(out.Files),
		TooManyFiles: out.TooManyFiles, None: out.None, Note: formatNote(lang, src.Format)}
	var occurrences int64
	for _, rec := range out.Records {
		rv := LogRecordView{Level: string(rec.Level), Type: s.logText(t.User, rec.Type), Location: s.logText(t.User, rec.Location),
			Channel: s.logText(t.User, rec.Channel), Hour: stamp(rec.Hour), Count: rec.Count}
		// The text goes through the cleaner a real read goes through (the check, the
		// masker, the cap): what is shown is what would be stored. What it refuses
		// is left out.
		if o.Text && rec.Text != "" {
			if txt, ok := serverlog.CleanedText(rec.Text); ok {
				rv.Text = s.logText(t.User, txt)
			}
		}
		occurrences += rec.Count
		v.Records = append(v.Records, rv)
	}
	for _, f := range out.Files {
		v.SkippedBytes += f.Skipped
	}
	for _, u := range out.Unseen {
		v.Unseen = append(v.Unseen, TargetUnseenView{What: LogPath(u), Reason: LogUnseenReason(lang, out.UnseenCause[u])})
	}
	switch {
	case len(v.Records) > 0 || len(v.Unseen) > 0:
	case out.Rejected > 0:
		v.Message = i18n.T(lang, "api.logs.try.unreadable")
	default:
		v.Message = i18n.T(lang, "api.logs.try.empty")
	}
	if err := trace("ok", map[string]any{"from": "start", "to": stamp(now), "volume": serverlog.ReadVolume(out), "skipped": v.SkippedBytes,
		"records": len(out.Records), "occurrences": occurrences, "rejected": out.Rejected, "unseen": len(out.Unseen),
		"fingerprint": serverlog.Fingerprint(out.Records)}); err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// ---- errors ---------------------------------------------------------------------

// maxLogErrors bounds the errors one answer lists (the latest first).
const maxLogErrors = 500

// errorView builds the view of an error. The cleaned text is decrypted and
// returned only when the settings of the server keep it.
func (s *server) errorView(ctx context.Context, t target.Target, st serverlog.Settings, srcs map[string]serverlog.Source, g serverlog.Signature) (LogErrorView, error) {
	v := LogErrorView{ID: g.ID, SourceID: g.SourceID, Level: string(g.Level), Type: s.logText(t.User, g.Type), Location: s.logText(t.User, g.Location),
		Channel: s.logText(t.User, g.Channel), Status: string(g.Status), FirstAt: stamp(g.FirstAt), LastAt: stamp(g.LastAt), Total: g.Total}
	// An error last seen before its source changed file came from another file.
	if src, ok := srcs[g.SourceID]; ok && !g.LastAt.Before(src.PathAt) {
		// The command looks for the day of the line: LastAt is when Michel read it,
		// which can be days later (a computer off, a late read).
		line := g
		hour, known, err := s.serverLogs().LastLineHour(ctx, g.ID)
		if err != nil {
			return LogErrorView{}, err
		}
		if known {
			line.LastAt = hour
		}
		v.Detail = detailCommand(t, src, line)
	}
	if st.StoreText {
		txt, ok, err := s.serverLogs().Text(ctx, g.ID)
		if err != nil {
			return LogErrorView{}, err
		}
		if ok {
			v.Text = s.logText(t.User, txt)
		}
	}
	return v, nil
}

// errorContext reads what the views of the errors of t need.
func (s *server) errorContext(ctx context.Context, t target.Target) (serverlog.Settings, map[string]serverlog.Source, error) {
	repo := s.serverLogs()
	st, err := repo.Settings(ctx, t.ID)
	if err != nil {
		return st, nil, err
	}
	all, err := repo.Sources(ctx, t.ID)
	if err != nil {
		return st, nil, err
	}
	srcs := map[string]serverlog.Source{}
	for _, src := range all {
		srcs[src.ID] = src
	}
	return st, srcs, nil
}

func (s *server) logErrors(w http.ResponseWriter, r *http.Request) {
	_, t, ok := s.logTarget(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	st, srcs, err := s.errorContext(ctx, t)
	if err != nil {
		s.internal(w, r)
		return
	}
	sigs, err := s.serverLogs().Signatures(ctx, t.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	total := len(sigs)
	if len(sigs) > maxLogErrors {
		sigs = sigs[:maxLogErrors]
	}
	out := make([]LogErrorView, 0, len(sigs))
	for _, g := range sigs {
		v, err := s.errorView(ctx, t, st, srcs, g)
		if err != nil {
			s.internal(w, r)
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, LogErrorsView{Errors: out, Total: total, Truncated: total > len(out)})
}

// logErrorPatch marks an error seen, or ignored ("do not warn me about this one
// again"); seen also takes an ignored error back.
func (s *server) logErrorPatch(w http.ResponseWriter, r *http.Request) {
	lang, t, ok := s.logTarget(w, r)
	if !ok {
		return
	}
	var p LogErrorPatch
	if !s.readJSON(w, r, &p) {
		return
	}
	status := serverlog.Status(p.Status)
	if status != serverlog.StatusSeen && status != serverlog.StatusIgnored {
		s.logRefused(w, http.StatusBadRequest, lang, "api.logs.bad_status")
		return
	}
	ctx := r.Context()
	repo := s.serverLogs()
	sigs, err := repo.Signatures(ctx, t.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	var found *serverlog.Signature
	for i := range sigs {
		if sigs[i].ID == r.PathValue("signature") {
			found = &sigs[i]
		}
	}
	if found == nil {
		s.logRefused(w, http.StatusNotFound, lang, "api.logs.error_not_found")
		return
	}
	if err := repo.SetStatus(ctx, found.ID, status); err != nil {
		s.internal(w, r)
		return
	}
	if err := s.logAudit(ctx, "log.error_status", t.ID, map[string]any{"error": found.ID, "level": string(found.Level), "status": string(status), "was": string(found.Status)}); err != nil {
		s.internal(w, r)
		return
	}
	found.Status = status
	st, srcs, err := s.errorContext(ctx, t)
	if err != nil {
		s.internal(w, r)
		return
	}
	v, err := s.errorView(ctx, t, st, srcs, *found)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// ---- settings -------------------------------------------------------------------

// riskText is the risk of a step away from the recommended choice, in words.
func riskText(lang i18n.Lang, code string) string {
	switch code {
	case serverlog.DeviationStoreText:
		return i18n.T(lang, "api.logs.risk.store_text")
	case serverlog.DeviationAlertText:
		return i18n.T(lang, "api.logs.risk.alert_text")
	case serverlog.DeviationRetention:
		return i18n.T(lang, "api.logs.risk.retention")
	}
	return ""
}

func deviationViews(lang i18n.Lang, codes []string) []LogDeviationView {
	out := make([]LogDeviationView, 0, len(codes))
	for _, c := range codes {
		out = append(out, LogDeviationView{Code: c, Text: riskText(lang, c)})
	}
	return out
}

// intervalText writes a reading interval as the page sends it back: manual,
// or 5m, 2h.
func intervalText(d time.Duration) string { return target.IntervalText(d) }

// parseLogInterval reads "manual" or a duration from 1 minute to 24 hours; ""
// is the default.
func parseLogInterval(in string) (time.Duration, error) {
	in = strings.TrimSpace(strings.ToLower(in))
	switch in {
	case "":
		return serverlog.DefaultSettings(target.EnvProd).Interval, nil
	case target.ManualText:
		return serverlog.ManualInterval, nil
	}
	d, err := time.ParseDuration(in)
	if err != nil || d < serverlog.MinInterval || d > serverlog.MaxInterval {
		return 0, errors.New("bad interval")
	}
	return d, nil
}

func (s *server) settingsView(lang i18n.Lang, t target.Target, st serverlog.Settings) LogSettingsView {
	devs := serverlog.Deviations(st)
	v := LogSettingsView{Interval: intervalText(st.Interval), StoreText: st.StoreText, AlertText: st.AlertText, RetentionDays: st.RetentionDays,
		ResolveAfterDays: int(st.ResolveAfter / (24 * time.Hour)), ReadCapBytes: st.ReadCap, ReadTimeoutSeconds: int(st.ReadTimeout / time.Second),
		MaxAlertsPerHour: st.MaxAlertsPerHour, SMS: st.SMS, SpikeFactor: st.SpikeFactor, SpikeMin: st.SpikeMin, Routes: map[string]string{},
		Recommended: LogRecommendedView{StoreText: false, AlertText: false, RetentionDays: serverlog.RecommendedRetentionDays},
		Deviations:  deviationViews(lang, devs)}
	for _, l := range serverlog.Levels {
		v.Routes[string(l)] = string(st.Routes[l])
	}
	switch {
	case st.Interval == serverlog.ManualInterval:
		v.IntervalNote = i18n.T(lang, "api.logs.interval.manual")
	case st.Interval > 10*time.Minute:
		v.IntervalNote = i18n.T(lang, "api.logs.interval.slow")
	}
	if len(devs) > 0 && t.Classification == policy.ClassHealth {
		v.Health = i18n.T(lang, "api.logs.risk.health")
	}
	return v
}

func (s *server) logSettings(w http.ResponseWriter, r *http.Request) {
	lang, t, ok := s.logTarget(w, r)
	if !ok {
		return
	}
	st, err := s.serverLogs().Settings(r.Context(), t.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, s.settingsView(lang, t, st))
}

func (s *server) logSettingsPatch(w http.ResponseWriter, r *http.Request) {
	lang, t, ok := s.logTarget(w, r)
	if !ok {
		return
	}
	var p LogSettingsPatch
	if !s.readJSON(w, r, &p) {
		return
	}
	ctx := r.Context()
	repo := s.serverLogs()
	cur, err := repo.Settings(ctx, t.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	next := cur
	next.Routes = map[serverlog.Level]serverlog.Route{}
	for l, rt := range cur.Routes {
		next.Routes[l] = rt
	}
	if p.Interval != nil {
		if next.Interval, err = parseLogInterval(*p.Interval); err != nil {
			s.logRefused(w, http.StatusBadRequest, lang, "api.logs.bad_interval")
			return
		}
	}
	if p.StoreText != nil {
		next.StoreText = *p.StoreText
		// The text of alerts needs the text to be kept: turning the one off turns
		// the other off, unless the request says otherwise.
		if !next.StoreText && p.AlertText == nil {
			next.AlertText = false
		}
	}
	if p.AlertText != nil {
		next.AlertText = *p.AlertText
	}
	if p.RetentionDays != nil {
		next.RetentionDays = *p.RetentionDays
	}
	if p.ResolveAfterDays != nil {
		next.ResolveAfter = time.Duration(*p.ResolveAfterDays) * 24 * time.Hour
	}
	if p.ReadCapBytes != nil {
		next.ReadCap = *p.ReadCapBytes
	}
	if p.ReadTimeoutSeconds != nil {
		next.ReadTimeout = time.Duration(*p.ReadTimeoutSeconds) * time.Second
	}
	if p.MaxAlertsPerHour != nil {
		next.MaxAlertsPerHour = *p.MaxAlertsPerHour
	}
	if p.SMS != nil {
		next.SMS = *p.SMS
	}
	if p.SpikeFactor != nil {
		next.SpikeFactor = *p.SpikeFactor
	}
	if p.SpikeMin != nil {
		next.SpikeMin = *p.SpikeMin
	}
	for name, route := range p.Routes {
		level := serverlog.Level(name)
		known := false
		for _, l := range serverlog.Levels {
			known = known || l == level
		}
		rt := serverlog.Route(route)
		if !known || (rt != serverlog.RouteImmediate && rt != serverlog.RouteDigest && rt != serverlog.RouteIgnored) {
			s.logRefused(w, http.StatusBadRequest, lang, "api.logs.bad_settings")
			return
		}
		next.Routes[level] = rt
	}
	err = serverlog.ChangeSettings(ctx, repo, s.deps.Audit, t, next, p.Confirmed)
	switch {
	case errors.Is(err, serverlog.ErrConfirmationNeeded):
		s.logConfirm(w, lang, t, cur, next)
		return
	case errors.Is(err, serverlog.ErrInvalidSettings):
		s.logRefused(w, http.StatusBadRequest, lang, "api.logs.bad_settings")
		return
	case err != nil:
		s.internal(w, r)
		return
	}
	saved, err := repo.Settings(ctx, t.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, s.settingsView(lang, t, saved))
}

// logConfirm answers 409: the new steps away from the recommended choice, each
// with its risk, and the stronger word for a server that holds health data.
func (s *server) logConfirm(w http.ResponseWriter, lang i18n.Lang, t target.Target, cur, next serverlog.Settings) {
	fresh := serverlog.NewDeviations(cur, next)
	body := LogConfirmBody{Error: i18n.T(lang, "api.logs.confirm_needed"), Hint: i18n.T(lang, "api.logs.confirm_needed_hint"), Code: logConfirmCode,
		Deviations: deviationViews(lang, fresh)}
	if t.Classification == policy.ClassHealth {
		body.Health = i18n.T(lang, "api.logs.risk.health")
	}
	writeJSON(w, http.StatusConflict, body)
}

// ---- erasing --------------------------------------------------------------------

// logPurge erases the log data of a server held by Michel, on the user's
// demand: everything (the ignored choices too) or the stored text only.
// Nothing is erased on the server. Both are audited.
func (s *server) logPurge(w http.ResponseWriter, r *http.Request) {
	lang, t, ok := s.logTarget(w, r)
	if !ok {
		return
	}
	var b LogPurgeBody
	if !s.readBody(w, r, &b, true) {
		return
	}
	// A read that runs would write rows back behind the erasure.
	unlock, free := serverlog.TryLock(t.ID)
	if !free {
		s.logRefused(w, http.StatusConflict, lang, "api.logs.busy")
		return
	}
	defer unlock()
	ctx := r.Context()
	repo := s.serverLogs()
	switch b.Scope {
	case "", "all":
		b.Scope = "all"
		if err := serverlog.EraseTargetAudited(ctx, repo, s.deps.Audit, targetActor, t.ID); err != nil {
			s.internal(w, r)
			return
		}
	case "text":
		if _, err := serverlog.EraseTextAudited(ctx, repo, s.deps.Audit, targetActor, t.ID); err != nil {
			s.internal(w, r)
			return
		}
	default:
		s.logRefused(w, http.StatusBadRequest, lang, "api.logs.bad_scope")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"erased": true, "scope": b.Scope})
}
