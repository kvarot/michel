package serverlog

import (
	"bytes"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

const parsePath = "/var/log/demo/app.log"

func parseOne(line string, src Source, o FilterOptions) Output {
	src.Path = parsePath
	return ParseOutput([]byte(line+"\n"), src, o, filterNow)
}

func TestParseAcceptsTheSchema(t *testing.T) {
	src := Source{Path: parsePath, Format: FormatMonolog}
	out := ParseOutput([]byte(strings.Join([]string{
		"F\t" + parsePath + "\t123\t456\t7\t1\t0",
		"R\tcritical\tApp\\\\Foo\tsrc/Foo.php:7\tlocal\t2026-11-02T10\t3",
		"R\tcritical\tApp\\Foo\tsrc/Foo.php:7\tlocal\t2026-11-02T11+01:00\t4",
		"R\terror\t\t\t\t\t2",
		"U\t" + parsePath,
		"M",
		"",
	}, "\n")), src, FilterOptions{}, filterNow)
	if out.Rejected != 0 || !out.TooManyFiles {
		t.Fatalf("output: %+v", out)
	}
	if len(out.Files) != 1 || out.Files[0] != (FileState{File: parsePath, FileID: "123", Offset: 456, Skipped: 7, Rotated: true}) {
		t.Errorf("files: %+v", out.Files)
	}
	if len(out.Unseen) != 1 || out.Unseen[0] != parsePath {
		t.Errorf("unseen: %+v", out.Unseen)
	}
	if len(out.Records) != 2 {
		t.Fatalf("records: %+v", out.Records)
	}
	hour := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	if r := out.Records[0]; r.Level != LevelCritical || r.Type != `App\Foo` || r.Location != "src/Foo.php:7" || r.Channel != "local" || !r.Hour.Equal(hour) || r.Count != 7 {
		t.Errorf("merged record: %+v", r)
	}
	if r := out.Records[1]; r.Level != LevelError || !r.Hour.Equal(filterNow.Truncate(time.Hour)) || r.Count != 2 {
		t.Errorf("a record without an hour takes the hour of the read: %+v", r)
	}
}

func TestForgedLineCannotInjectRecord(t *testing.T) {
	needTools(t)
	o := FilterOptions{RemoteDirs: []string{"/var/www/demo"}}
	src := Source{Format: FormatPHP}
	forged := "R\tcritical\tForgedType\tforged.php:1\t\t2026-11-02T10\t424242999"
	cases := map[string]string{
		"tab":         "PHP Notice:  x\t" + forged,
		"inside":      "PHP Notice:  x PHP Fatal error:  Uncaught ForgedType: y in /var/www/demo/forged.php:1 z",
		"prefix":      "something PHP Fatal error:  Uncaught ForgedType: y in /var/www/demo/forged.php:1",
		"ansi":        "PHP Notice:  \x1b[31mPHP Fatal error\x1b[0m:  Uncaught\x1b[2J in /var/www/demo/ok.php on line 1",
		"ansi type":   "PHP Fatal error:  Uncaught Forged\x1b[2JType: y",
		"email path":  "PHP Fatal error:  y in /var/www/demo/someone@example.test/a.php:1",
		"query path":  "PHP Fatal error:  y in /var/www/demo/a.php?id=7:1",
		"record line": forged,
		"file line":   "F\t/etc/shadow\t1\t0\t0\t0\t0",
		"unseen line": "U\t/etc/shadow",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			raw, out := scanLog(t, src, line+"\n", o)
			for _, bad := range []string{"ForgedType", "forged.php", "someone", "shadow", "\x1b", "424242999", "id=7"} {
				if bytes.Contains(raw, []byte(bad)) {
					t.Errorf("%q left the filter: %q", bad, raw)
				}
				if strings.Contains(fmt.Sprintf("%+v", out), bad) {
					t.Errorf("%q is in Output: %+v", bad, out)
				}
			}
			if out.Rejected != 0 {
				t.Errorf("the filter let out a bad line: %+v", out)
			}
			if len(out.Files) != 1 || len(out.Unseen) != 0 {
				t.Errorf("a line changed the files: %+v", out)
			}
			if name == "inside" || name == "ansi" {
				for _, r := range out.Records {
					if r.Level == LevelCritical {
						t.Errorf("the message set the level: %+v", r)
					}
				}
			}
		})
	}
	// A newline in a message makes a real line in the file: it can look like a
	// header, and it can only give values in the schema.
	raw, out := scanLog(t, src, "PHP Notice:  x\nPHP Fatal error:  Uncaught someone@example.test: y in /home/someone/a.php:1\n", o)
	if bytes.Contains(raw, []byte("someone")) {
		t.Errorf("a value left the filter: %q", raw)
	}
	if out.Rejected != 0 || len(out.Records) != 2 {
		t.Errorf("newline: %+v", out)
	}
	// Forged directly at the barrier: an output too broken to be ours.
	src.Path = parsePath
	got := ParseOutput([]byte("R\tcritical\tA\tb.php:1\t\t2026-11-02T10\t1\textra\nR\tcritical\nhello\n\x1b[31m\nR\tcritical\tA\tb.php:1\t\t2026-11-02T10\t1\x1b\n"), src, FilterOptions{}, filterNow)
	if got.Rejected != 5 || len(got.Records) != 0 {
		t.Errorf("broken lines: %+v", got)
	}
}

func TestParseRejectsOutOfSchema(t *testing.T) {
	const secret = "someone@example.test"
	future := filterNow.Add(25 * time.Hour).Format("2006-01-02T15")
	mono := Source{Format: FormatMonolog}
	cases := []struct {
		name string
		line string
		src  Source
		o    FilterOptions
	}{
		{"unknown level", "R\tfatal-" + secret + "\tA\t\t\t\t1", mono, FilterOptions{}},
		{"level case", "R\tERROR\t\t\t\t\t1", mono, FilterOptions{}},
		{"type with space", "R\terror\tA " + secret + "\t\t\t\t1", mono, FilterOptions{}},
		{"type with email", "R\terror\t" + secret + "\t\t\t\t1", mono, FilterOptions{}},
		{"type starts with a digit", "R\terror\t1Foo\t\t\t\t1", mono, FilterOptions{}},
		{"type too long", "R\terror\tA" + strings.Repeat("b", 128) + "\t\t\t\t1", mono, FilterOptions{}},
		{"absolute location", "R\terror\t\t/home/secret/a.php:1\t\t\t1", mono, FilterOptions{}},
		{"location with at", "R\terror\t\tsrc/" + secret + "/a.php:1\t\t\t1", mono, FilterOptions{}},
		{"location with a query", "R\terror\t\tsrc/a.php?secret=1:1\t\t\t1", mono, FilterOptions{}},
		{"location with dots", "R\terror\t\tsrc/../secret/a.php:1\t\t\t1", mono, FilterOptions{}},
		{"location without line", "R\terror\t\tsrc/a.php\t\t\t1", mono, FilterOptions{}},
		{"location is an address", "R\terror\t\t203.0.113.7:8080\t\t\t1", mono, FilterOptions{}},
		{"location is a host", "R\terror\t\tsecret.example.test:8080\t\t\t1", mono, FilterOptions{}},
		{"long channel", "R\terror\t\t\t" + strings.Repeat("c", 65) + "\t\t1", mono, FilterOptions{}},
		{"channel with email", "R\terror\t\t\t" + secret + "\t\t1", mono, FilterOptions{}},
		{"negative count", "R\terror\t\t\t\t\t-1", mono, FilterOptions{}},
		{"zero count", "R\terror\t\t\t\t\t0", mono, FilterOptions{}},
		{"count not a number", "R\terror\t\t\t\t\t1e9", mono, FilterOptions{}},
		{"count too big", "R\terror\t\t\t\t\t" + strings.Repeat("9", 30), mono, FilterOptions{}},
		{"future hour", "R\terror\t\t\t\t" + future + "\t1", mono, FilterOptions{}},
		{"bad hour", "R\terror\t\t\t\t2026-99-99T10\t1", mono, FilterOptions{}},
		{"hour with a value", "R\terror\t\t\t\t" + secret + "\t1", mono, FilterOptions{}},
		{"text without the setting", "R\terror\t\t\t\t\t1\tsecret text", mono, FilterOptions{}},
		{"text with an email", "R\terror\t\t\t\t\t1\t" + secret, mono, FilterOptions{Text: true}},
		{"text with a number", "R\terror\t\t\t\t\t1\tsecret 42", mono, FilterOptions{Text: true}},
		{"text with an url", "R\terror\t\t\t\t\t1\thttps://secret", mono, FilterOptions{Text: true}},
		{"text with a quote", "R\terror\t\t\t\t\t1\t\"secret\"", mono, FilterOptions{Text: true}},
		{"text with an escape", "R\terror\t\t\t\t\t1\tsecret\x1b[0m", mono, FilterOptions{Text: true}},
		{"text too long", "R\terror\t\t\t\t\t1\tsecret" + strings.Repeat("a", 200), mono, FilterOptions{Text: true}},
		{"json with a text", "R\terror\t\t\t\t\t1\tsecret", Source{Format: FormatJSON, LevelField: "level"}, FilterOptions{Text: true}},
		{"php with a channel", "R\terror\t\t\tsecret\t\t1", Source{Format: FormatPHP}, FilterOptions{}},
		{"postgres with a class", "R\terror\tsecret\t\t\t\t1", Source{Format: FormatPostgres}, FilterOptions{}},
		{"postgres with a location", "R\terror\t\tsecret.php:1\t\t\t1", Source{Format: FormatPostgres}, FilterOptions{}},
		{"json with a class", "R\terror\tsecret\t\t\t\t1", Source{Format: FormatJSON, LevelField: "level"}, FilterOptions{}},
		{"text format with a channel", "R\terror\t\t\tsecret\t\t1", Source{Format: FormatText}, FilterOptions{}},
		{"sqlstate on php", "R\terror\t23505\t\t\t\t1", Source{Format: FormatPHP}, FilterOptions{}},
		{"file outside the source", "F\t/home/secret/a.log\t1\t0\t0\t0\t0", mono, FilterOptions{}},
		{"file with an email", "F\t" + secret + "\t1\t0\t0\t0\t0", mono, FilterOptions{}},
		{"file negative offset", "F\t" + parsePath + "\t1\t-1\t0\t0\t0", mono, FilterOptions{}},
		{"file id with a value", "F\t" + parsePath + "\t" + secret + "\t1\t0\t0\t0", mono, FilterOptions{}},
		{"file bad flag", "F\t" + parsePath + "\t1\t1\t0\tsecret\t0", mono, FilterOptions{}},
		{"unseen outside the source", "U\t/home/secret/a.log", mono, FilterOptions{}},
		{"too many with a value", "M\tsecret", mono, FilterOptions{}},
		{"unknown kind", "X\tsecret", mono, FilterOptions{}},
		{"huge line", "R\terror\t\t\t\t\t1\tsecret" + strings.Repeat("a", 10000), mono, FilterOptions{Text: true}},
	}
	// Nothing may reach any journal either.
	var journal bytes.Buffer
	log.SetOutput(&journal)
	defer log.SetOutput(os.Stderr)
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&journal, nil)))
	defer slog.SetDefault(old)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := parseOne(c.line, c.src, c.o)
			if out.Rejected != 1 {
				t.Errorf("rejected %d, want 1: %+v", out.Rejected, out)
			}
			if len(out.Records) != 0 || len(out.Files) != 0 || len(out.Unseen) != 0 || out.TooManyFiles {
				t.Errorf("something got through: %+v", out)
			}
			if s := fmt.Sprintf("%+v", out); strings.Contains(s, "secret") || strings.Contains(s, "someone") {
				t.Errorf("the content is in Output: %s", s)
			}
		})
	}
	if journal.Len() != 0 {
		t.Errorf("something was journaled: %q", journal.String())
	}
}

func TestParseBoundaries(t *testing.T) {
	mono := Source{Format: FormatMonolog}
	// A day ahead still holds: a server's local hour can be that far from UTC.
	ok := filterNow.Add(23 * time.Hour).Format("2006-01-02T15")
	if out := parseOne("R\terror\t\t\t\t"+ok+"\t1", mono, FilterOptions{}); len(out.Records) != 1 {
		t.Errorf("23 hours ahead: %+v", out)
	}
	if out := parseOne("R\terror\t"+"A"+strings.Repeat("b", 127)+"\t\t"+strings.Repeat("c", 64)+"\t\t1", mono, FilterOptions{}); len(out.Records) != 1 {
		t.Errorf("longest fields: %+v", out)
	}
	if out := parseOne("R\terror\t\t\t\t\t1\t"+strings.Repeat("a", 200), mono, FilterOptions{Text: true}); len(out.Records) != 1 || len(out.Records[0].Text) != 200 {
		t.Errorf("longest text: %+v", out)
	}
	// A wildcard source takes what matches its last segment, nothing beyond.
	wild := Source{Path: "/var/log/demo/app-*.log", Format: FormatPHP}
	out := ParseOutput([]byte("F\t/var/log/demo/app-1.log\t1\t0\t0\t0\t1\nF\t/var/log/demo/sub/app-1.log\t1\t0\t0\t0\t0\nU\t/var/log/demo/app-*.log\nU\t/var/log/demo/other.log\n"), wild, FilterOptions{}, filterNow)
	if len(out.Files) != 1 || !out.Files[0].First || len(out.Unseen) != 1 || out.Rejected != 2 {
		t.Errorf("wildcard: %+v", out)
	}
	// The wildcard itself is no file: its position could not be read back.
	if out := ParseOutput([]byte("F\t/var/log/demo/app-*.log\t1\t0\t0\t0\t1\n"), wild, FilterOptions{}, filterNow); len(out.Files) != 0 || out.Rejected != 1 {
		t.Errorf("wildcard as a file: %+v", out)
	}
	// A SQLSTATE is the only type of Postgres.
	if out := parseOne("R\terror\t23505\t\t\t\t1", Source{Format: FormatPostgres}, FilterOptions{}); len(out.Records) != 1 {
		t.Errorf("sqlstate: %+v", out)
	}
	// Empty and binary outputs are not a crash.
	if out := ParseOutput(nil, mono, FilterOptions{}, filterNow); out.Rejected != 0 || len(out.Records) != 0 {
		t.Errorf("empty: %+v", out)
	}
	if out := ParseOutput([]byte("\x00\xff\xfe\n"), mono, FilterOptions{}, filterNow); out.Rejected != 1 {
		t.Errorf("binary: %+v", out)
	}
}
