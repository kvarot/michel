// Package serverlog stores what Michel reads in server logs: the sources a
// user declares, the read positions, and the recurring errors (signatures)
// with their hourly counts. It is storage only: no SSH and no log parsing.
package serverlog

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/kvarot/michel/internal/target"
)

// Format is the sort of log a source holds.
type Format string

const (
	FormatPHP      Format = "php"
	FormatPostgres Format = "postgres"
	FormatMonolog  Format = "monolog"
	FormatJSON     Format = "json"
	FormatText     Format = "text"
)

// Level is the severity of an error.
type Level string

const (
	LevelCritical Level = "critical"
	LevelError    Level = "error"
	LevelWarning  Level = "warning"
	LevelInfo     Level = "info"
)

// Levels lists the levels from the most to the least severe.
var Levels = []Level{LevelCritical, LevelError, LevelWarning, LevelInfo}

// Status is where an error stands in its life.
type Status string

const (
	StatusNew      Status = "new"
	StatusSeen     Status = "seen"
	StatusResolved Status = "resolved"
	StatusReopened Status = "reopened"
	StatusIgnored  Status = "ignored"
)

// Route is what happens when an error of a given level appears.
type Route string

const (
	RouteImmediate Route = "immediate"
	RouteDigest    Route = "digest"
	RouteIgnored   Route = "ignored"
)

// Source is one declared log path on a server.
type Source struct {
	ID, TargetID, Path string
	Format             Format
	LevelField         string
	ChannelField       string
	Pattern            string
	Active             bool
	CreatedAt          time.Time
}

// Cursor is the read position in one file of a source.
type Cursor struct {
	SourceID, File, FileID string
	Offset                 int64
	ReadAt                 time.Time
}

// Signature is one recurring error. Its text is not part of it: the cleaned
// text, when kept, stays encrypted in the database.
type Signature struct {
	ID, TargetID, SourceID string
	Level                  Level
	Type, Location         string
	Channel                string
	Status                 Status
	FirstAt, LastAt        time.Time
	LastAlertAt            time.Time
	Total                  int64
	// SpikeHour is the hour that spiked, on what Apply returns as spiked only.
	// It is not stored.
	SpikeHour time.Time
}

// Record is a batch of identical occurrences read in one hour. Text is the
// cleaned message (never a raw log line) and has no part in the identity.
type Record struct {
	Level                   Level
	Type, Location, Channel string
	Text                    string
	Hour                    time.Time
	Count                   int64
}

// Note kinds.
const (
	NoteGap          = "gap"
	NoteSkipped      = "skipped"
	NoteRotated      = "rotated"
	NoteUnseen       = "unseen"
	NoteRejected     = "rejected"
	NoteTooManyFiles = "too_many_files"
)

// Note says what Michel could not read, or left out, between From and To.
type Note struct {
	// The ids never leave the process (the digest carries notes).
	TargetID string    `json:"-"`
	SourceID string    `json:"-"`
	Kind     string    `json:"kind"`
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	Amount   int64     `json:"amount,omitempty"`
}

// Settings are the log settings of one server.
type Settings struct {
	TargetID         string
	Interval         time.Duration
	StoreText        bool
	AlertText        bool
	RetentionDays    int
	ResolveAfter     time.Duration
	ReadCap          int64
	ReadTimeout      time.Duration
	MaxAlertsPerHour int
	SMS              bool
	Routes           map[Level]Route
}

// Bounds of the settings. Interval is between MinInterval and MaxInterval, or
// ManualInterval.
const (
	MinRetentionDays = 7
	MaxRetentionDays = 365
	MinInterval      = time.Minute
	MaxInterval      = 24 * time.Hour
	// ManualInterval is the interval of a server read by hand only: the
	// scheduler never reads it. It mirrors target.ManualOnly.
	ManualInterval = -time.Second
)

// DefaultSettings returns the recommended settings for a server of env: no
// text kept or sent, 90 days of retention, an error becomes resolved after 7
// days without occurrence, and only critical errors of a prod server alert at
// once.
func DefaultSettings(env target.Env) Settings {
	routes := map[Level]Route{
		LevelCritical: RouteDigest,
		LevelError:    RouteDigest,
		LevelWarning:  RouteIgnored,
		LevelInfo:     RouteIgnored,
	}
	if env == target.EnvProd {
		routes[LevelCritical] = RouteImmediate
	}
	return Settings{
		Interval:         5 * time.Minute,
		RetentionDays:    90,
		ResolveAfter:     7 * 24 * time.Hour,
		ReadCap:          5 << 20,
		ReadTimeout:      30 * time.Second,
		MaxAlertsPerHour: 10,
		Routes:           routes,
	}
}

// SignatureID is the identity of an error: the SHA-256 of its source, level,
// type, location and channel. The text is not part of it.
func SignatureID(sourceID string, level Level, typ, location, channel string) string {
	h := sha256.New()
	for _, p := range []string{sourceID, string(level), typ, location, channel} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Spike thresholds: an error spikes when an hour holds at least spikeMin
// occurrences and spikeFactor times the hour before.
// FrequentMin is how many times an error must be read in the period of a digest
// to be told as frequent when it is neither new nor back.
const FrequentMin = 100

const (
	spikeMin    = 100
	spikeFactor = 10
)
