package serverlog

import (
	"math"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FileState is what the filter says about one file it looked at. Offset is the
// new position, Skipped the bytes left unread because of the cap, Rotated tells
// that the file was replaced or truncated, First that it was only located.
type FileState struct {
	// File is a server path, which can hold a user name: it never goes into an
	// API answer.
	File            string `json:"-"`
	FileID          string `json:"-"`
	Offset, Skipped int64
	Rotated, First  bool
}

// Output is what is left of a filter's output once revalidated. Rejected counts
// the lines thrown away; nothing of their content is kept anywhere.
type Output struct {
	Files        []FileState
	Records      []Record
	Rejected     int
	Unseen       []string
	TooManyFiles bool
	// None says that the filter found nothing to read and could tell: the file,
	// or its folder, is really absent (an unsearchable folder does not count).
	None bool
}

// The schema of what may come back from a server. The output of the filter is
// hostile: visitors write part of the log lines it reads.
var (
	typeRe     = regexp.MustCompile(`^[A-Za-z_\\][A-Za-z0-9_\\]{0,127}$`)
	sqlstateRe = regexp.MustCompile(`^(00|01|02|03|08|09|0A|0B|0F|0L|0P|0Z|20|21|22|23|24|25|26|27|28|2B|2D|2F|34|38|39|3B|3D|3F|40|42|44|53|54|55|57|58|72|F0|HV|P0|XX)[0-9A-Z]{3}$`)
	locationRe = regexp.MustCompile(`^[A-Za-z0-9_.-][A-Za-z0-9_./-]{0,199}\.(php|phtml|inc|module|twig|tpl):[0-9]{1,6}$`)
	channelRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	countRe    = regexp.MustCompile(`^[1-9][0-9]{0,17}$`)
	numberRe   = regexp.MustCompile(`^[0-9]{1,18}$`)
	fileIDRe   = regexp.MustCompile(`^[0-9]{1,40}$`)
	cleanRe    = regexp.MustCompile("^[ !#-&(-/:-?A-_a-~]{0,200}$")
)

// Shapes that are values, not names, even when each character is allowed: a
// national number, an address or a phone number in 3 or more digit groups, a
// host in a folder, with or without a suffix. The price: a dated or versioned
// folder (2026-11-02, v1.2.3) leaves the location. The filter has the same rules
// (safe_word, safe_path), and an identifier like jean_dupont stays out of reach.
var (
	longDigitsRe   = regexp.MustCompile(`[0-9]{7}`)
	digitGroupsRe  = regexp.MustCompile(`[0-9]+[-_.][0-9]+[-_.][0-9]+`)
	dottedNumberRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)+$`)
	folderHostRe   = regexp.MustCompile(`\.[A-Za-z]`)
	fileExtRe      = regexp.MustCompile(`\.[A-Za-z]+$`)
	doubleExtRe    = regexp.MustCompile(`^[^.]+\.(blade|html|class|inc|tpl|config|module|interface|trait)$`)
	fullIPv6Re     = regexp.MustCompile(`[0-9A-Fa-f]+(:[0-9A-Fa-f]+){3}`)
)

// safeWord refuses a word holding a long digit run or 3 or more digit groups.
func safeWord(w string) bool {
	return !longDigitsRe.MatchString(w) && !digitGroupsRe.MatchString(w)
}

// safeLocation checks each segment of a "path:line" location.
func safeLocation(loc string) bool {
	segments := strings.Split(loc[:strings.LastIndex(loc, ":")], "/")
	last := len(segments) - 1
	for _, s := range segments[:last] {
		s = strings.TrimPrefix(s, ".")
		if !safeWord(s) || dottedNumberRe.MatchString(s) || folderHostRe.MatchString(s) {
			return false
		}
	}
	stem := strings.TrimPrefix(fileExtRe.ReplaceAllString(segments[last], ""), ".")
	return safeWord(stem) && (!strings.Contains(stem, ".") || doubleExtRe.MatchString(stem))
}

// maxOutputLine is longer than any line the filter can write.
const maxOutputLine = 4096

// maxFuture is how far ahead the hour of a line may be: a server's local hour,
// read as UTC, is never a full day away.
const maxFuture = 24 * time.Hour

// ParseOutput revalidates the output of a filter line by line. A line out of
// the schema is dropped and counted in Rejected. There is no error and no
// journal on purpose: nothing of a rejected line can travel further.
func ParseOutput(out []byte, src Source, o FilterOptions, now time.Time) Output {
	var res Output
	seenFile := map[string]bool{}
	seenUnseen := map[string]bool{}
	index := map[recordKey]int{}
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		ok := false
		if len(line) <= maxOutputLine {
			fields := strings.Split(line, "\t")
			switch fields[0] {
			case "R":
				var r Record
				if r, ok = parseRecord(fields, src, o, now); ok {
					ok = addRecord(&res, index, r)
				}
			case "F":
				var f FileState
				if f, ok = parseFile(fields, src); ok && !seenFile[f.File] {
					seenFile[f.File] = true
					res.Files = append(res.Files, f)
				} else {
					ok = false
				}
			case "U":
				if ok = len(fields) == 2 && inSource(fields[1], src); ok && !seenUnseen[fields[1]] {
					seenUnseen[fields[1]] = true
					res.Unseen = append(res.Unseen, fields[1])
				}
			case "N":
				if ok = len(fields) == 1; ok {
					res.None = true
				}
			case "M":
				if ok = len(fields) == 1; ok {
					res.TooManyFiles = true
				}
			}
		}
		if !ok {
			res.Rejected++
		}
	}
	return res
}

// recordKey is what makes two records one group.
type recordKey struct {
	level                  Level
	typ, location, channel string
	hour                   int64
}

// addRecord adds r to its group, and refuses a count that cannot be summed.
func addRecord(res *Output, index map[recordKey]int, r Record) bool {
	k := recordKey{r.Level, r.Type, r.Location, r.Channel, r.Hour.Unix()}
	i, found := index[k]
	if !found {
		index[k] = len(res.Records)
		res.Records = append(res.Records, r)
		return true
	}
	cur := &res.Records[i]
	if cur.Count > math.MaxInt64-r.Count {
		return false
	}
	cur.Count += r.Count
	if cur.Text == "" {
		cur.Text = r.Text
	}
	return true
}

// parseRecord checks one "R level type location channel hour count [text]" line.
func parseRecord(f []string, src Source, o FilterOptions, now time.Time) (Record, bool) {
	wantText := textAllowed(src, o)
	if len(f) != 7 && !(wantText && len(f) == 8) {
		return Record{}, false
	}
	r := Record{Level: Level(f[1]), Type: f[2], Location: f[3], Channel: f[4]}
	switch r.Level {
	case LevelCritical, LevelError, LevelWarning, LevelInfo:
	default:
		return Record{}, false
	}
	if !validForFormat(r, src.Format) || !countRe.MatchString(f[6]) {
		return Record{}, false
	}
	var err error
	if r.Count, err = strconv.ParseInt(f[6], 10, 64); err != nil {
		return Record{}, false
	}
	var ok bool
	if r.Hour, ok = parseHour(f[5], now); !ok {
		return Record{}, false
	}
	if len(f) == 8 {
		if !validText(f[7]) {
			return Record{}, false
		}
		r.Text = f[7]
	}
	// Laravel doubles the backslashes of a class: one class, one signature.
	r.Type = strings.ReplaceAll(r.Type, `\\`, `\`)
	return r, true
}

// validForFormat checks each field against what the format may hold at all.
func validForFormat(r Record, format Format) bool {
	validType := r.Type == "" || (typeRe.MatchString(r.Type) && safeWord(r.Type))
	validLocation := r.Location == "" || (locationRe.MatchString(r.Location) && !strings.Contains(r.Location, "..") && safeLocation(r.Location))
	validChannel := r.Channel == "" || (channelRe.MatchString(r.Channel) && safeWord(r.Channel))
	switch format {
	case FormatPHP:
		return validType && validLocation && r.Channel == ""
	case FormatMonolog:
		return validType && validLocation && validChannel
	case FormatPostgres:
		return (r.Type == "" || (sqlstateRe.MatchString(r.Type) && strings.ContainsAny(r.Type, "0123456789"))) && r.Location == "" && r.Channel == ""
	case FormatJSON:
		return r.Type == "" && r.Location == "" && validChannel
	case FormatText:
		return r.Type == "" && r.Location == "" && r.Channel == ""
	}
	return false
}

// validText is the second barrier on the cleaned text: cleanRe holds printable
// ASCII without digit, at sign or quote, which the filter has all replaced. An
// IPv6 address can be made of letters alone: those forms are refused too.
func validText(s string) bool {
	return cleanRe.MatchString(s) && !strings.Contains(s, "://") && !strings.Contains(s, "::") && !fullIPv6Re.MatchString(s)
}

// parseHour reads the hour of a line, or takes the hour of the read if the line
// gave none. A line without a timezone is read as UTC.
func parseHour(s string, now time.Time) (time.Time, bool) {
	if s == "" {
		return now.UTC().Truncate(time.Hour), true
	}
	t, err := time.Parse("2006-01-02T15", s)
	if err != nil {
		if t, err = time.Parse("2006-01-02T15Z07:00", s); err != nil {
			return time.Time{}, false
		}
	}
	if t.After(now.Add(maxFuture)) {
		return time.Time{}, false
	}
	return t.UTC().Truncate(time.Hour), true
}

// parseFile checks one "F file id offset skipped rotated first" line.
func parseFile(f []string, src Source) (FileState, bool) {
	if len(f) != 7 || !plainPathRe.MatchString(f[1]) || !inSource(f[1], src) || !fileIDRe.MatchString(f[2]) ||
		!numberRe.MatchString(f[3]) || !numberRe.MatchString(f[4]) ||
		!isFlag(f[5]) || !isFlag(f[6]) {
		return FileState{}, false
	}
	offset, err1 := strconv.ParseInt(f[3], 10, 64)
	skipped, err2 := strconv.ParseInt(f[4], 10, 64)
	if err1 != nil || err2 != nil {
		return FileState{}, false
	}
	return FileState{File: f[1], FileID: f[2], Offset: offset, Skipped: skipped, Rotated: f[5] == "1", First: f[6] == "1"}, true
}

func isFlag(s string) bool { return s == "0" || s == "1" }

// inSource tells whether file is what the source declares: the path itself, or
// a match of its wildcard, which stays within the last segment.
func inSource(file string, src Source) bool {
	if file == src.Path {
		return true
	}
	if !plainPathRe.MatchString(file) || strings.Contains(file, "..") {
		return false
	}
	ok, err := path.Match(src.Path, file)
	return err == nil && ok
}
