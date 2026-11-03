package serverlog

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

var filterNow = time.Date(2026, 11, 2, 12, 30, 0, 0, time.UTC)

// shPath turns a local temp path into the form sh understands here.
func shPath(p string) string {
	p = filepath.ToSlash(p)
	if runtime.GOOS == "windows" && len(p) > 2 && p[1] == ':' {
		return "/" + strings.ToLower(p[:1]) + p[2:]
	}
	return p
}

// needTools skips when the real sh or awk is not there.
func needTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"sh", "awk", "tail", "head", "tr", "ls", "wc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
}

// run feeds a script to `sh -s`, the way Task 3 sends it over SSH.
func run(t *testing.T, script string) []byte {
	t.Helper()
	return runWith(t, script, []string{"sh"}, "")
}

// runWith runs the script with the given shell, with pathPrefix ahead on PATH.
// Only stdout counts: the parser reads nothing else.
func runWith(t *testing.T, script string, shell []string, pathPrefix string) []byte {
	t.Helper()
	cmd := exec.Command(shell[0], append(shell[1:], "-s")...)
	cmd.Stdin = strings.NewReader(script)
	if pathPrefix != "" {
		cmd.Env = append(os.Environ(), "PATH="+pathPrefix+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, errOut.String())
	}
	return out.Bytes()
}

// writeLog writes content to a temp file and returns its sh path.
func writeLog(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return shPath(p)
}

// earlier is a cursor on another file, so that the file under test counts as
// one that appeared after the activation: it is read from its start.
var earlier = []Cursor{{File: "/var/log/demo/previous.log", FileID: "1", Offset: 0}}

// scanLog runs the filter over content from its start.
func scanLog(t *testing.T, src Source, content string, o FilterOptions) ([]byte, Output) {
	t.Helper()
	src.Path = writeLog(t, content)
	script, err := Script(src, earlier, o)
	if err != nil {
		t.Fatalf("Script: %v", err)
	}
	raw := run(t, script)
	return raw, ParseOutput(raw, src, o, filterNow)
}

func oneRecord(t *testing.T, out Output) Record {
	t.Helper()
	if len(out.Records) != 1 || out.Rejected != 0 {
		t.Fatalf("want one record, nothing rejected, got %+v", out)
	}
	return out.Records[0]
}

func TestPHPExtractsLevelTypeLocation(t *testing.T) {
	needTools(t)
	line := "PHP Fatal error:  Uncaught PDOException: secret in /var/www/demo/app/Invoice.php:42\n"
	raw, out := scanLog(t, Source{Format: FormatPHP}, line, FilterOptions{RemoteDirs: []string{"/var/www/demo"}})
	r := oneRecord(t, out)
	if r.Level != LevelCritical || r.Type != "PDOException" || r.Location != "app/Invoice.php:42" || r.Count != 1 {
		t.Errorf("bad record: %+v", r)
	}
	if bytes.Contains(raw, []byte("secret")) {
		t.Errorf("the message left the filter: %q", raw)
	}
	_, out = scanLog(t, Source{Format: FormatPHP}, line, FilterOptions{RemoteDirs: []string{"/var/www/other", "/var/www/dem"}})
	if r := oneRecord(t, out); r.Location != "Invoice.php:42" {
		t.Errorf("outside a linked folder, want the file name alone: %+v", r)
	}
}

func TestPHPLevelsAndOtherForms(t *testing.T) {
	needTools(t)
	cases := []struct {
		line  string
		level Level
		typ   string
		loc   string
		hour  string
	}{
		{"[02-Nov-2026 10:15:00 UTC] PHP Warning:  Undefined variable $x in /var/www/demo/a.php on line 3", LevelWarning, "", "a.php:3", "2026-11-02T10"},
		{"[02-Nov-2026 09:15:00 Europe/Paris] PHP Parse error:  syntax error in /var/www/demo/a.php on line 4", LevelCritical, "", "a.php:4", "2026-11-02T09"},
		{"PHP Deprecated:  old in /var/www/demo/a.php on line 5", LevelInfo, "", "a.php:5", "2026-11-02T12"},
		{"[Mon Nov 02 10:00:00 2026] [php:error] [pid 1] [client 192.0.2.1:9] PHP Notice:  x in /home/someone/b.php on line 6", LevelInfo, "", "b.php:6", "2026-11-02T12"},
		{"PHP Fatal error:  Uncaught App\\Foo: x in /var/www/demo/a.php:7\r", LevelCritical, "App\\Foo", "a.php:7", "2026-11-02T12"},
		{"PHP Fatal error:  no location given", LevelCritical, "", "", "2026-11-02T12"},
		{"PHP Fatal error:  bad in /var/www/demo/../../etc/a.php:8", LevelCritical, "", "", "2026-11-02T12"},
		{"PHP Fatal error:  not code in /var/www/demo/notes.txt:8", LevelCritical, "", "", "2026-11-02T12"},
	}
	for _, c := range cases {
		_, out := scanLog(t, Source{Format: FormatPHP}, c.line+"\n", FilterOptions{RemoteDirs: []string{"/var/www/demo/"}})
		r := oneRecord(t, out)
		if r.Level != c.level || r.Type != c.typ || r.Location != c.loc || r.Hour.Format("2006-01-02T15") != c.hour {
			t.Errorf("%q gave %+v", c.line, r)
		}
	}
	for _, ignored := range []string{"Stack trace:", "#0 /var/www/demo/a.php(3): f()", "  thrown in /var/www/demo/a.php on line 3", "PHP  1. {main}() /var/www/demo/a.php:0", "[02-Nov-2026 10:15:00 UTC] plain message"} {
		if _, out := scanLog(t, Source{Format: FormatPHP}, ignored+"\n", FilterOptions{}); len(out.Records) != 0 {
			t.Errorf("%q made a record: %+v", ignored, out.Records)
		}
	}
}

func TestPostgresKeepsSeverityAndSqlstateOnly(t *testing.T) {
	needTools(t)
	src := Source{Format: FormatPostgres}
	_, out := scanLog(t, src, "2026-11-02 10:00:00.123 UTC [12345] demo@demo 23505 ERROR:  duplicate key \"x\"\n", FilterOptions{})
	if r := oneRecord(t, out); r.Level != LevelError || r.Type != "23505" || r.Location != "" || r.Channel != "" || r.Hour.Format(time.RFC3339) != "2026-11-02T10:00:00Z" {
		t.Errorf("with %%e: %+v", r)
	}
	_, out = scanLog(t, src, "2026-11-02 10:00:00.123 UTC [12345] demo@demo ERROR:  duplicate key\n", FilterOptions{})
	if r := oneRecord(t, out); r.Level != LevelError || r.Type != "" {
		t.Errorf("without %%e: %+v", r)
	}
	for sev, want := range map[string]Level{"FATAL": LevelCritical, "PANIC": LevelCritical, "WARNING": LevelWarning, "LOG": LevelInfo, "NOTICE": LevelInfo} {
		_, out = scanLog(t, src, "2026-11-02 10:00:00 UTC [1] "+sev+":  x\n", FilterOptions{})
		if r := oneRecord(t, out); r.Level != want {
			t.Errorf("%s: %+v", sev, r)
		}
	}
	for _, sev := range []string{"DETAIL", "STATEMENT", "HINT", "CONTEXT"} {
		if _, out := scanLog(t, src, "2026-11-02 10:00:00 UTC [1] 23505 "+sev+":  x\n", FilterOptions{}); len(out.Records) != 0 {
			t.Errorf("%s made a record: %+v", sev, out.Records)
		}
	}
	// A value in a message, or the continuation of a statement, is not a severity.
	_, out = scanLog(t, src, "2026-11-02 10:00:00 UTC [1] LOG:  statement: SELECT 'x ERROR:  y'\n", FilterOptions{})
	if r := oneRecord(t, out); r.Level != LevelInfo {
		t.Errorf("a severity in a value: %+v", r)
	}
	if _, out := scanLog(t, src, "\tSELECT 1 FATAL:  y\n", FilterOptions{}); len(out.Records) != 0 {
		t.Errorf("a continuation line made a record: %+v", out.Records)
	}
	// The known classes are all taken, with letters or not.
	for _, code := range []string{"57P01", "42P01", "XX000", "HV00P", "P0001", "F0000", "0A000"} {
		_, out = scanLog(t, src, "2026-11-02 10:00:00 UTC [1] "+code+" ERROR:  x\n", FilterOptions{})
		if r := oneRecord(t, out); r.Type != code {
			t.Errorf("%s: %+v", code, r)
		}
	}
	// A pid and a user name are not a SQLSTATE.
	for _, l := range []string{
		"2026-11-02 10:00:00 UTC [12345] ERROR:  x",
		"2026-11-02 10:00:00 UTC ALICE ERROR:  x",
		"2026-11-02 10:00:00 UTC 12345 ERROR:  x",
		"2026-11-02 10:00:00 UTC DR123 ERROR:  x",
		"2026-11-02 10:00:00 UTC HVABC ERROR:  x",
	} {
		_, out = scanLog(t, src, l+"\n", FilterOptions{})
		if r := oneRecord(t, out); r.Type != "" {
			t.Errorf("%q: %+v", l, r)
		}
	}
}

func TestMonologReadsAnchoredContextOnly(t *testing.T) {
	needTools(t)
	src := Source{Format: FormatMonolog}
	o := FilterOptions{RemoteDirs: []string{"/var/www/demo"}}
	line := `[2026-11-02 10:00:00] local.ERROR: un message {"exception":"[object] (App\Foo(code: 0): valeur at /var/www/demo/src/Foo.php:7)` + "\n"
	raw, out := scanLog(t, src, line, o)
	r := oneRecord(t, out)
	if r.Level != LevelError || r.Channel != "local" || r.Type != `App\Foo` || r.Location != "src/Foo.php:7" || r.Hour.Format("2006-01-02T15") != "2026-11-02T10" {
		t.Errorf("bad record: %+v", r)
	}
	if bytes.Contains(raw, []byte("valeur")) || bytes.Contains(raw, []byte("message")) {
		t.Errorf("a value left the filter: %q", raw)
	}
	// Laravel doubles its backslashes, and the same class must stay one signature.
	_, out = scanLog(t, src, `[2026-11-02 10:00:00] local.ERROR: m {"exception":"[object] (App\\Foo(code: 23000): v at /var/www/demo/src/Foo.php:7)"} []`+"\n", o)
	if r := oneRecord(t, out); r.Type != `App\Foo` || r.Location != "src/Foo.php:7" {
		t.Errorf("doubled backslashes: %+v", r)
	}
	// The real context comes last, whatever the message says before it.
	_, out = scanLog(t, src, `[2026-11-02 10:00:00] app.CRITICAL: [object] (Forged(code: 0): x at /f/forged.php:1) {"exception":"[object] (App\Real(code: 0): y at /f/fake.php:2) at /var/www/demo/src/Real.php:3)"}`+"\n", o)
	if r := oneRecord(t, out); r.Level != LevelCritical || r.Type != `App\Real` || r.Location != "src/Real.php:3" {
		t.Errorf("forged context: %+v", r)
	}
	// A timezone offset is honoured; no context means level and channel only.
	_, out = scanLog(t, src, "[2026-11-02T10:00:00.123456+01:00] app.WARNING: x\n", o)
	if r := oneRecord(t, out); r.Level != LevelWarning || r.Type != "" || r.Location != "" || r.Hour.Format(time.RFC3339) != "2026-11-02T09:00:00Z" {
		t.Errorf("offset: %+v", r)
	}
	for _, ignored := range []string{"[stacktrace]", "#0 /var/www/demo/a.php(3): f()", "free text ERROR: x", "x [2026-11-02 10:00:00] app.ERROR: y"} {
		if _, out := scanLog(t, src, ignored+"\n", o); len(out.Records) != 0 {
			t.Errorf("%q made a record: %+v", ignored, out.Records)
		}
	}
}

func TestJSONUsesDeclaredFieldsOnly(t *testing.T) {
	needTools(t)
	src := Source{Format: FormatJSON, LevelField: "severity", ChannelField: "topic"}
	raw, out := scanLog(t, src, `{"severity":"ERROR","topic":"billing","level":"debug","channel":"other","message":"secret"}`+"\n", FilterOptions{})
	r := oneRecord(t, out)
	if r.Level != LevelError || r.Channel != "billing" || r.Type != "" || r.Location != "" {
		t.Errorf("bad record: %+v", r)
	}
	if bytes.Contains(raw, []byte("secret")) {
		t.Errorf("a value left the filter: %q", raw)
	}
	// Undeclared fields, nested fields and a field written inside a value do not count.
	for _, l := range []string{
		`{"level":"error"}`,
		`{"context":{"severity":"critical"}}`,
		`{"message":"x \"severity\":\"critical\" y"}`,
		`{"severity":"someone@example.test"}`,
		`{"severity":400}`,
		`not json "severity":"error"`,
	} {
		if _, out := scanLog(t, src, l+"\n", FilterOptions{}); len(out.Records) != 0 {
			t.Errorf("%q made a record: %+v", l, out.Records)
		}
	}
	// A channel out of its closed form is left out, the level still counts.
	_, out = scanLog(t, src, `{"severity":"warn","topic":"someone@example.test"}`+"\n", FilterOptions{})
	if r := oneRecord(t, out); r.Level != LevelWarning || r.Channel != "" {
		t.Errorf("hostile channel: %+v", r)
	}
	// A level field is required, and field names must be plain.
	if _, err := Script(Source{Path: "/var/log/demo/a.log", Format: FormatJSON}, nil, FilterOptions{}); err == nil {
		t.Error("a JSON source without a level field was accepted")
	}
	for _, f := range []string{`a"b`, "a'b", `a\b`, "a b", strings.Repeat("a", 65)} {
		if _, err := Script(Source{Path: "/var/log/demo/a.log", Format: FormatJSON, LevelField: f}, nil, FilterOptions{}); err == nil {
			t.Errorf("hostile level field %q accepted", f)
		}
		if _, err := Script(Source{Path: "/var/log/demo/a.log", Format: FormatJSON, LevelField: "level", ChannelField: f}, nil, FilterOptions{}); err == nil {
			t.Errorf("hostile channel field %q accepted", f)
		}
	}
}

func TestTextCountsByLevelOnly(t *testing.T) {
	needTools(t)
	src := Source{Format: FormatText}
	content := "ERROR one\nan ERROR two\nFATAL three\nWARNING four\n2026/11/02 [error] 1#1: five\nnothing here\nthe ERRORS word\n"
	raw, out := scanLog(t, src, content, FilterOptions{})
	got := map[Level]int64{}
	for _, r := range out.Records {
		if r.Type != "" || r.Location != "" || r.Channel != "" || r.Text != "" {
			t.Errorf("more than a level: %+v", r)
		}
		got[r.Level] += r.Count
	}
	if got[LevelError] != 3 || got[LevelCritical] != 1 || got[LevelWarning] != 1 || got[LevelInfo] != 0 {
		t.Errorf("counts: %v", got)
	}
	for _, m := range []string{"one", "two", "three", "four", "five"} {
		if bytes.Contains(raw, []byte(m)) {
			t.Errorf("%q left the filter: %q", m, raw)
		}
	}
	// A pattern replaces the keywords.
	src.Pattern = "boom|bang[0-9]+"
	_, out = scanLog(t, src, "ERROR one\nboom two\nbang42 three\nbang four\n", FilterOptions{})
	if r := oneRecord(t, out); r.Level != LevelError || r.Count != 2 {
		t.Errorf("pattern: %+v", r)
	}
	for _, p := range []string{`a"b`, "a'b", `a\b`, "a/b", "a\nb", "a>b", "(", strings.Repeat("a", 129)} {
		if _, err := Script(Source{Path: "/var/log/demo/a.log", Format: FormatText, Pattern: p}, nil, FilterOptions{}); err == nil {
			t.Errorf("hostile pattern %q accepted", p)
		}
	}
}

func allSources() []Source {
	return []Source{
		{Path: "/var/log/demo/app.log", Format: FormatPHP},
		{Path: "/var/log/demo/app.log", Format: FormatPostgres},
		{Path: "/var/log/demo/app-*.log", Format: FormatMonolog},
		{Path: "/var/log/demo/app.log", Format: FormatJSON, LevelField: "level", ChannelField: "channel"},
		{Path: "/var/log/demo/app.log", Format: FormatText},
		{Path: "/var/log/demo/app.log", Format: FormatText, Pattern: "boom"},
	}
}

func TestDefaultScriptCannotEmitText(t *testing.T) {
	for _, src := range allSources() {
		script, err := Script(src, earlier, FilterOptions{RemoteDirs: []string{"/var/www/demo"}})
		if err != nil {
			t.Fatal(err)
		}
		// $0 only ever goes to the held line, which only goes to the parser.
		if n := strings.Count(script, "$0"); n != 1 || !strings.Contains(script, "prev = $0") {
			t.Errorf("%s: $0 is used %d times", src.Format, n)
		}
		for _, l := range strings.Split(script, "\n") {
			if !strings.Contains(l, "print") {
				continue
			}
			for _, bad := range []string{"$0", "prev", "(l)", " l,", " msg", "tx["} {
				if strings.Contains(l, bad) {
					t.Errorf("%s: print with %q: %s", src.Format, bad, l)
				}
			}
		}
		for _, bad := range []string{"clean", "msg", "tx[", "[str]", "[email]", "[url]"} {
			if strings.Contains(script, bad) {
				t.Errorf("%s: the default script holds %q", src.Format, bad)
			}
		}
		withText, err := Script(src, earlier, FilterOptions{Text: true, RemoteDirs: []string{"/var/www/demo"}})
		if err != nil {
			t.Fatal(err)
		}
		if script == withText && src.Format != FormatJSON {
			t.Errorf("%s: asking for the text changes nothing", src.Format)
		}
		if script != withText && src.Format == FormatJSON {
			t.Errorf("json has no text to clean, and its script changed")
		}
	}
}

// writerWord names commands that write or move a file, whole words only.
var writerWord = regexp.MustCompile(`\b(tee|dd|mv|cp)\b`)

func TestScriptGrammar(t *testing.T) {
	banned := []string{"system", "getline", ">", "rm", "mktemp", "sudo", "ssh", "curl", "wget", "cat ", "ENVIRON", "/dev/"}
	for _, src := range allSources() {
		for _, text := range []bool{false, true} {
			for _, cursors := range [][]Cursor{nil, earlier} {
				script, err := Script(src, cursors, FilterOptions{Text: text, RemoteDirs: []string{"/var/www/demo"}})
				if err != nil {
					t.Fatal(err)
				}
				for _, b := range banned {
					if strings.Contains(script, b) {
						t.Errorf("%s text=%v: the script holds %q", src.Format, text, b)
					}
				}
				if w := writerWord.FindString(script); w != "" {
					t.Errorf("%s text=%v: the script holds the command %q", src.Format, text, w)
				}
				evals := 0
				for _, l := range strings.Split(script, "\n") {
					if strings.Contains(l, "eval") {
						evals++
						// The one form: a position number, nothing a file name can reach.
						if strings.TrimSpace(l) != `eval "f=\${$i}"` {
							t.Errorf("%s text=%v: another eval: %s", src.Format, text, l)
						}
					}
				}
				if evals != 2 {
					t.Errorf("%s text=%v: %d eval, want the 2 of the loops", src.Format, text, evals)
				}
				for _, l := range strings.Split(script, "\n") {
					if strings.Contains(l, "print") && strings.Contains(l, "|") {
						t.Errorf("%s text=%v: print into a pipe: %s", src.Format, text, l)
					}
				}
				if !strings.HasPrefix(script, "LC_ALL=C\nexport LC_ALL\n") {
					t.Errorf("%s: LC_ALL=C is not set first", src.Format)
				}
			}
		}
	}
}

func TestScriptQuotesHostilePaths(t *testing.T) {
	bad := []string{
		"", "relative.log", "/var/log/it's.log", "/var/log/$(touch x).log", "/var/log/`id`.log",
		"/var/log/a\nb.log", "/var/log/../shadow", "/var/log/a;b.log", "/var/log/a|b.log", "/var/log/a&b.log",
		"/var/log/a\"b.log", `/var/log/a\b.log`, "/var/log/a>b.log", "/var/log/a\tb.log", "/var/*/a.log", "/var/log/a[1].log",
		"/var/log/\x1b[31m.log", "/var/log/someone@example.test.log", "/var/log/..", "/var/log/a..*",
	}
	for _, p := range bad {
		if _, err := Script(Source{Path: p, Format: FormatPHP}, nil, FilterOptions{}); err == nil {
			t.Errorf("path %q accepted", p)
		} else if strings.Contains(err.Error(), "touch") || strings.Contains(err.Error(), "shadow") {
			t.Errorf("the error repeats the path: %v", err)
		}
		if p != "" && p != "/var/*/a.log" {
			if _, err := Script(Source{Path: "/var/log/a.log", Format: FormatPHP}, nil, FilterOptions{RemoteDirs: []string{p}}); err == nil {
				t.Errorf("remote dir %q accepted", p)
			}
			if _, err := Script(Source{Path: "/var/log/a.log", Format: FormatPHP}, []Cursor{{File: p, FileID: "1"}}, FilterOptions{}); err == nil {
				t.Errorf("cursor file %q accepted", p)
			}
		}
	}
	for _, id := range []string{"1'2", "$(id)", "1 2", "1\n2"} {
		if _, err := Script(Source{Path: "/var/log/a.log", Format: FormatPHP}, []Cursor{{File: "/var/log/a.log", FileID: id}}, FilterOptions{}); err == nil {
			t.Errorf("file id %q accepted", id)
		}
	}
	if _, err := Script(Source{Path: "/var/log/a.log", Format: FormatPHP}, []Cursor{{File: "/var/log/a.log", FileID: "1", Offset: -1}}, FilterOptions{}); err == nil {
		t.Error("a negative offset was accepted")
	}
	if _, err := Script(Source{Path: "/var/log/a.log", Format: Format("other")}, nil, FilterOptions{}); err == nil {
		t.Error("an unknown format was accepted")
	}
	if _, err := Script(Source{Path: "/var/log/a.log", Format: FormatPHP}, nil, FilterOptions{RemoteDirs: []string{"/"}}); err == nil {
		t.Error("a remote dir at the root was accepted: nothing would be left of the path")
	}
	// A plain space stays possible, and works.
	needTools(t)
	dir := filepath.Join(t.TempDir(), "with space")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "a b.log")
	if err := os.WriteFile(p, []byte("PHP Warning:  x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := Source{Path: shPath(p), Format: FormatPHP}
	script, err := Script(src, earlier, FilterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out := ParseOutput(run(t, script), src, FilterOptions{}, filterNow)
	if len(out.Records) != 1 || len(out.Files) != 1 || out.Files[0].File != src.Path {
		t.Errorf("a path with a space: %+v", out)
	}
}

// trapMarkers are the personal values placed in testdata/trap.log.
var trapMarkers = []string{
	"trappe", "example.test", "203.0.113", "198.51.100", "1 99 13", "199139", "diagnostic", "patients",
	"token", "fakebearer", "tok_fake", "urlfakeparam", "insert", "select", "reset", "bearer",
	"example.fr", "203-0-113", "203_0_113", "06-12-34",
}

func assertNoMarker(t *testing.T, where, s string, markers []string) {
	t.Helper()
	low := strings.ToLower(s)
	for _, m := range markers {
		if strings.Contains(low, m) {
			t.Errorf("%s holds the marker %q:\n%s", where, m, s)
		}
	}
}

func readTrap(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "trap.log"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTrapCorpusLeavesNoTrace(t *testing.T) {
	needTools(t)
	corpus := readTrap(t)
	// The test means nothing if the markers are not in the corpus.
	for _, m := range trapMarkers {
		if !strings.Contains(strings.ToLower(corpus), m) {
			t.Fatalf("marker %q is not in the corpus", m)
		}
	}
	minRead := map[Format]int64{FormatPHP: 5, FormatPostgres: 2, FormatMonolog: 3, FormatJSON: 2, FormatText: 3}
	for _, src := range []Source{
		{Format: FormatPHP},
		{Format: FormatPostgres},
		{Format: FormatMonolog},
		{Format: FormatJSON, LevelField: "level", ChannelField: "channel"},
		{Format: FormatText},
	} {
		t.Run(string(src.Format), func(t *testing.T) {
			raw, out := scanLog(t, src, corpus, FilterOptions{RemoteDirs: []string{"/var/www/demo"}})
			assertNoMarker(t, "the raw output", string(raw), trapMarkers)
			assertNoMarker(t, "Output", fmt.Sprintf("%+v", out), trapMarkers)
			var n int64
			for _, r := range out.Records {
				n += r.Count
				if r.Text != "" {
					t.Errorf("text with the default settings: %+v", r)
				}
			}
			if n < minRead[src.Format] {
				t.Errorf("only %d occurrences read: the filter may simply be blind. %+v", n, out)
			}
			if out.Rejected != 0 {
				t.Errorf("%d lines rejected", out.Rejected)
			}
		})
	}
}

func TestCleanedTextRemovesValues(t *testing.T) {
	needTools(t)
	line := `PHP Warning:  User "Zoe Trappe" (id 12345) from 203.0.113.77 or 2001:db8:0:0:0:0:0:1 mail jean.trappe@example.test at https://example.test/reset?token=urlfakeparam host db.example.test path /home/jtrappe/a.txt key=abc-secret ` + "`Trappe2`" + ` tok_fake_9f8e7d6c5b4a NIR 1 99 13 99 999 123 45 eyJhbGciOiJIUzI1NiJ9abcdef in /var/www/demo/a.php on line 3` + "\n"
	raw, out := scanLog(t, Source{Format: FormatPHP}, line, FilterOptions{Text: true, RemoteDirs: []string{"/var/www/demo"}})
	r := oneRecord(t, out)
	if !strings.Contains(r.Text, "User") || !strings.Contains(r.Text, "from") || !strings.Contains(r.Text, "host") {
		t.Fatalf("not much cleaned text left: %+v", r)
	}
	cleaned := []string{"trappe", "203.0.113", "2001:", "db8", "example.test", "urlfakeparam", "abc-secret", "12345", "tok_fake", "1 99 13", "eyj"}
	for _, where := range []string{string(raw), r.Text} {
		assertNoMarker(t, "the cleaned text", where, cleaned)
	}
	if len(r.Text) > 200 {
		t.Errorf("%d characters", len(r.Text))
	}
	// An apostrophe cannot shift the quotes and let a quoted value out.
	_, out = scanLog(t, Source{Format: FormatPHP}, "PHP Warning:  it's 'Trappe' done\n", FilterOptions{Text: true})
	assertNoMarker(t, "the cleaned text", oneRecord(t, out).Text, []string{"trappe"})
	// Each format gives a cleaned text, except JSON, which only has declared fields.
	for _, c := range []struct {
		src  Source
		line string
		want string
	}{
		{Source{Format: FormatPostgres}, `2026-11-02 10:00:00 UTC [1] demo@demo ERROR:  duplicate key "x" 42`, "duplicate key [str] [n]"},
		{Source{Format: FormatMonolog}, `[2026-11-02 10:00:00] app.ERROR: refused 42 {"exception":"[object] (App\Foo(code: 0): valeur at /a/b.php:1)`, "refused [n]"},
		{Source{Format: FormatText}, `ERROR refused 42`, "ERROR refused [n]"},
		{Source{Format: FormatJSON, LevelField: "level"}, `{"level":"error","message":"valeur"}`, ""},
	} {
		_, out := scanLog(t, c.src, c.line+"\n", FilterOptions{Text: true})
		if r := oneRecord(t, out); r.Text != c.want {
			t.Errorf("%s: got %q, want %q", c.src.Format, r.Text, c.want)
		}
	}
	// No address survives in its compressed form, nor any word holding "::".
	_, out = scanLog(t, Source{Format: FormatPHP}, "PHP Warning:  from abcd::ef to fe80::abcd or ::1 or ::ffff:203.0.113.7 or ab:cd:ef:ab end\n", FilterOptions{Text: true})
	if r := oneRecord(t, out); r.Text != "from [addr] to [addr] or [addr] or [addr] or [ip] end" {
		t.Errorf("compressed addresses: %q", r.Text)
	}
	// A long line is capped, control characters and an open quote go away.
	long := "PHP Warning:  " + strings.Repeat("word ", 2000) + "\n"
	_, out = scanLog(t, Source{Format: FormatPHP}, long, FilterOptions{Text: true})
	if r := oneRecord(t, out); len(r.Text) == 0 || len(r.Text) > 200 {
		t.Errorf("long line: %d characters", len(r.Text))
	}
	_, out = scanLog(t, Source{Format: FormatPHP}, "PHP Warning:  a\tb\x1b[31mc\x00d é 'open Trappe\n", FilterOptions{Text: true})
	r = oneRecord(t, out)
	if strings.ContainsAny(r.Text, "\t\x1b\x00é") || strings.Contains(r.Text, "Trappe") {
		t.Errorf("not cleaned: %q", r.Text)
	}
	// The trap corpus, all formats: an unquoted word can stay (the spec says so
	// in the warning), the values cannot.
	values := []string{"example.test", "203.0.113", "198.51.100", "1 99 13", "199139", "urlfakeparam", "fakebearertokenabc123", "tok_fake"}
	for _, src := range []Source{{Format: FormatPHP}, {Format: FormatPostgres}, {Format: FormatMonolog}, {Format: FormatText}} {
		raw, out := scanLog(t, src, readTrap(t), FilterOptions{Text: true})
		assertNoMarker(t, string(src.Format)+" raw", string(raw), values)
		if out.Rejected != 0 {
			t.Errorf("%s: %d rejected", src.Format, out.Rejected)
		}
	}
	// The text has no part in the grouping.
	a := "PHP Warning:  first 1 in /var/www/demo/a.php on line 3\nPHP Warning:  other in /var/www/demo/a.php on line 3\n"
	_, out = scanLog(t, Source{Format: FormatPHP}, a, FilterOptions{Text: true})
	r = oneRecord(t, out)
	if r.Count != 2 || r.Location != "a.php:3" {
		t.Errorf("the text split a group: %+v", out)
	}
}

// fileState returns the only file of an output.
func fileState(t *testing.T, out Output) FileState {
	t.Helper()
	if len(out.Files) != 1 {
		t.Fatalf("want one file, got %+v", out)
	}
	return out.Files[0]
}

// pass runs one read of path with the cursors.
func pass(t *testing.T, path string, cursors []Cursor, o FilterOptions) Output {
	t.Helper()
	src := Source{Path: path, Format: FormatPHP}
	script, err := Script(src, cursors, o)
	if err != nil {
		t.Fatal(err)
	}
	return ParseOutput(run(t, script), src, o, filterNow)
}

const warnLine = "PHP Warning:  x in /var/www/demo/a.php on line 3\n"

func TestFirstReadStartsAtEndWithoutRecord(t *testing.T) {
	needTools(t)
	p := writeLog(t, warnLine)
	out := pass(t, p, nil, FilterOptions{})
	f := fileState(t, out)
	if !f.First || f.Offset != int64(len(warnLine)) || len(out.Records) != 0 || f.FileID == "" {
		t.Errorf("first read: %+v", out)
	}
}

func TestOnlyWholeLinesAreConsumed(t *testing.T) {
	needTools(t)
	p := writeLog(t, warnLine+"PHP Warning:  half")
	out := pass(t, p, earlier, FilterOptions{})
	f := fileState(t, out)
	if f.Offset != int64(len(warnLine)) || f.Rotated || f.First || f.Skipped != 0 {
		t.Errorf("state: %+v", f)
	}
	if r := oneRecord(t, out); r.Count != 1 {
		t.Errorf("record: %+v", r)
	}
	// From the saved position, nothing is counted twice.
	cur := []Cursor{{File: p, FileID: f.FileID, Offset: f.Offset}}
	out = pass(t, p, cur, FilterOptions{})
	if f2 := fileState(t, out); f2.Offset != f.Offset || len(out.Records) != 0 {
		t.Errorf("second read: %+v", out)
	}
}

func TestCursorMovesAndRotationRestarts(t *testing.T) {
	needTools(t)
	p := writeLog(t, warnLine+warnLine)
	id := fileState(t, pass(t, p, nil, FilterOptions{})).FileID
	// The next line only.
	out := pass(t, p, []Cursor{{File: p, FileID: id, Offset: int64(len(warnLine))}}, FilterOptions{})
	if r := oneRecord(t, out); r.Count != 1 {
		t.Errorf("after the position: %+v", r)
	}
	// Up to date: nothing read.
	out = pass(t, p, []Cursor{{File: p, FileID: id, Offset: int64(2 * len(warnLine))}}, FilterOptions{})
	if f := fileState(t, out); f.Rotated || len(out.Records) != 0 || f.Offset != int64(2*len(warnLine)) {
		t.Errorf("up to date: %+v", out)
	}
	// Another inode: from the start, and it is said.
	out = pass(t, p, []Cursor{{File: p, FileID: "1", Offset: int64(len(warnLine))}}, FilterOptions{})
	if f := fileState(t, out); !f.Rotated || f.Offset != int64(2*len(warnLine)) || oneRecord(t, out).Count != 2 {
		t.Errorf("other inode: %+v", out)
	}
	// A shorter file: from the start, and it is said.
	out = pass(t, p, []Cursor{{File: p, FileID: id, Offset: 100000}}, FilterOptions{})
	if f := fileState(t, out); !f.Rotated || oneRecord(t, out).Count != 2 {
		t.Errorf("shorter: %+v", out)
	}
}

func TestReadCapSkipsToTheEndAndSaysSo(t *testing.T) {
	needTools(t)
	content := strings.Repeat(warnLine, 1000)
	p := writeLog(t, content)
	out := pass(t, p, earlier, FilterOptions{ReadCap: 1000})
	f := fileState(t, out)
	if f.Offset != int64(len(content)) || f.Skipped != int64(len(content))-1000 {
		t.Errorf("state: %+v", f)
	}
	var n int64
	for _, r := range out.Records {
		n += r.Count
	}
	if max := int64(1000 / len(warnLine)); n == 0 || n > max {
		t.Errorf("%d lines read, at most %d fit", n, max)
	}
}

func TestEndlessLineAndBinaryKeepPositionsRight(t *testing.T) {
	needTools(t)
	// Longer than the cap, no newline: the position moves on, and it is said.
	p := writeLog(t, strings.Repeat("x", 5000))
	out := pass(t, p, earlier, FilterOptions{ReadCap: 1000})
	if f := fileState(t, out); f.Offset != 5000 || f.Skipped != 5000 || len(out.Records) != 0 {
		t.Errorf("endless line: %+v", out)
	}
	// NUL and high bytes must not shift the position.
	bin := "PHP Warning:  a\x00b\xff\xfe in /var/www/demo/a.php on line 3\n"
	p = writeLog(t, bin+"\x00\x00\x00\n"+warnLine)
	out = pass(t, p, earlier, FilterOptions{})
	if f := fileState(t, out); f.Offset != int64(len(bin)+4+len(warnLine)) {
		t.Errorf("binary: %+v", out)
	}
	if r := oneRecord(t, out); r.Count != 2 {
		t.Errorf("binary record: %+v", r)
	}
	// A very long line is read without trouble, and keeps its location.
	big := "PHP Warning:  " + strings.Repeat("y ", 100000) + "in /var/www/demo/a.php on line 3\n"
	p = writeLog(t, big)
	out = pass(t, p, earlier, FilterOptions{})
	if f := fileState(t, out); f.Offset != int64(len(big)) {
		t.Errorf("big line: %+v", f)
	}
	if r := oneRecord(t, out); r.Location != "a.php:3" {
		t.Errorf("big line: %+v", r)
	}
}

func TestMissingAndNotRegularAreUnseen(t *testing.T) {
	needTools(t)
	dir := t.TempDir()
	missing := shPath(filepath.Join(dir, "missing.log"))
	out := pass(t, missing, earlier, FilterOptions{})
	if len(out.Unseen) != 1 || out.Unseen[0] != missing || len(out.Files) != 0 {
		t.Errorf("missing: %+v", out)
	}
	sub := filepath.Join(dir, "sub.log")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	out = pass(t, shPath(sub), earlier, FilterOptions{})
	if len(out.Unseen) != 1 || len(out.Files) != 0 {
		t.Errorf("a folder: %+v", out)
	}
	real := filepath.Join(dir, "real.log")
	if err := os.WriteFile(real, []byte(warnLine), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(real, link); err != nil {
		t.Logf("no symbolic link on this machine: %v", err)
		return
	}
	out = pass(t, shPath(link), earlier, FilterOptions{})
	if len(out.Unseen) != 1 || len(out.Records) != 0 {
		t.Errorf("a link: %+v", out)
	}
}

// MaxFiles bounds the files of a pass (the cap on bytes is another test, see
// TestPassBudgetIsSharedAndNewestFirst).
func TestWildcardKeepsTheNewestFilesPastMaxFiles(t *testing.T) {
	needTools(t)
	dir := t.TempDir()
	for _, day := range []string{"2026-10-30", "2026-10-31", "2026-11-01", "2026-11-02"} {
		if err := os.WriteFile(filepath.Join(dir, "app-"+day+".log"), []byte(warnLine), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := func(out Output) string {
		var days []string
		for _, f := range out.Files {
			days = append(days, strings.TrimSuffix(strings.TrimPrefix(f.File, shPath(dir)+"/app-"), ".log"))
		}
		sort.Strings(days)
		return strings.Join(days, " ")
	}
	if err := os.WriteFile(filepath.Join(dir, "other.log"), []byte(warnLine), 0o644); err != nil {
		t.Fatal(err)
	}
	pat := shPath(dir) + "/app-*.log"
	out := pass(t, pat, earlier, FilterOptions{MaxFiles: 10})
	if read(out) != "2026-10-30 2026-10-31 2026-11-01 2026-11-02" || out.TooManyFiles || oneRecord(t, out).Count != 4 {
		t.Errorf("wildcard: %+v", out)
	}
	out = pass(t, pat, earlier, FilterOptions{MaxFiles: 3})
	// Past the cap, the newest files are read: today's errors come first.
	if read(out) != "2026-10-31 2026-11-01 2026-11-02" || !out.TooManyFiles || oneRecord(t, out).Count != 3 {
		t.Errorf("capped: %+v", out)
	}
	// Each file has its own position.
	cur := []Cursor{{File: out.Files[0].File, FileID: out.Files[0].FileID, Offset: out.Files[0].Offset}}
	out = pass(t, pat, cur, FilterOptions{MaxFiles: 10})
	if len(out.Files) != 4 || oneRecord(t, out).Count != 3 {
		t.Errorf("per file: %+v", out)
	}
	// No match: said, not silent.
	none := shPath(dir) + "/none-*.log"
	out = pass(t, none, earlier, FilterOptions{})
	if len(out.Unseen) != 1 || out.Unseen[0] != none || len(out.Files) != 0 {
		t.Errorf("no match: %+v", out)
	}
}

func TestHostileFileNameIsNeverEmitted(t *testing.T) {
	needTools(t)
	dir := t.TempDir()
	made := 0
	// Windows refuses some of these names: the others still go through the shell.
	for _, name := range []string{"app-\tR\tcritical\tX\t\t\t\t9.log", "app-a\nb.log", "app-someone@example.test.log", "app-'x.log", "app-..log", "app-$(x).log"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(warnLine), 0o644); err == nil {
			made++
		}
	}
	if made == 0 {
		t.Skip("no hostile name can be made here")
	}
	pat := shPath(dir) + "/app-*.log"
	src := Source{Path: pat, Format: FormatPHP}
	script, err := Script(src, earlier, FilterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw := run(t, script)
	for _, bad := range []string{"critical", "'x", "someone", "app-..", "$(x)"} {
		if bytes.Contains(raw, []byte(bad)) {
			t.Errorf("%q left the filter: %q", bad, raw)
		}
	}
	out := ParseOutput(raw, src, FilterOptions{}, filterNow)
	if out.Rejected != 0 || len(out.Records) != 0 || len(out.Files) != 0 || len(out.Unseen) != 1 || out.Unseen[0] != pat {
		t.Errorf("hostile names: %+v", out)
	}
}

// A folder, a field or a pattern may hold the letters of an internal word.
func TestValuesSurviveTheMessageRemoval(t *testing.T) {
	needTools(t)
	_, out := scanLog(t, Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/msgapp/a/b.php on line 3\n", FilterOptions{RemoteDirs: []string{"/var/www/msgapp"}})
	if r := oneRecord(t, out); r.Location != "a/b.php:3" {
		t.Errorf("folder: %+v", r)
	}
	_, out = scanLog(t, Source{Format: FormatJSON, LevelField: "msg_level", ChannelField: "msg"}, `{"msg_level":"error","msg":"billing"}`+"\n", FilterOptions{})
	if r := oneRecord(t, out); r.Level != LevelError || r.Channel != "billing" {
		t.Errorf("fields: %+v", r)
	}
	_, out = scanLog(t, Source{Format: FormatText, Pattern: "msgboom"}, "msgboom\nother\n", FilterOptions{})
	if r := oneRecord(t, out); r.Count != 1 {
		t.Errorf("pattern: %+v", r)
	}
}

// Without the tools, the source is unseen: nothing falls back on a copy.
func TestMissingToolsMakeTheSourceUnseen(t *testing.T) {
	needTools(t)
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is not installed")
	}
	p := writeLog(t, warnLine)
	src := Source{Path: p, Format: FormatPHP}
	script, err := Script(src, earlier, FilterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sh, "-s")
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(os.Environ(), "PATH="+t.TempDir())
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("script failed: %v", err)
	}
	out := ParseOutput(raw, src, FilterOptions{}, filterNow)
	if len(out.Unseen) != 1 || out.Unseen[0] != p || len(out.Files) != 0 || out.Rejected != 0 {
		t.Errorf("no tools: %+v", out)
	}
}

// A tool that fails in the pipe must not read as "no error" at the old position.
func TestShortReadIsUnseen(t *testing.T) {
	needTools(t)
	p := writeLog(t, warnLine)
	src := Source{Path: p, Format: FormatPHP}
	script, err := Script(src, earlier, FilterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	shim := t.TempDir()
	if err := os.WriteFile(filepath.Join(shim, "head"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := ParseOutput(runWith(t, script, []string{"sh"}, shim), src, FilterOptions{}, filterNow)
	if len(out.Unseen) != 1 || out.Unseen[0] != p || len(out.Files) != 0 || len(out.Records) != 0 {
		t.Errorf("failing head: %+v", out)
	}
}

// Forged lines cannot fill the output: past the cap of groups, they count by level.
func TestGroupsAreCapped(t *testing.T) {
	needTools(t)
	var b strings.Builder
	n := maxGroups + 200
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "PHP Warning:  x in /var/www/demo/f%d.php on line 1\n", i)
	}
	_, out := scanLog(t, Source{Format: FormatPHP}, b.String(), FilterOptions{})
	if len(out.Records) != maxGroups+1 || out.Rejected != 0 {
		t.Errorf("%d groups, %d rejected", len(out.Records), out.Rejected)
	}
	var total int64
	for _, r := range out.Records {
		total += r.Count
	}
	if total != int64(n) {
		t.Errorf("%d occurrences counted, want %d", total, n)
	}
}

// Addresses, national numbers and hosts have a shape the fields cannot hold,
// in any format, even when every character is allowed.
func TestValueShapesNeverLeaveTheFilter(t *testing.T) {
	needTools(t)
	o := FilterOptions{RemoteDirs: []string{"/var/www/demo"}}
	json := Source{Format: FormatJSON, LevelField: "level", ChannelField: "channel"}
	for _, c := range []struct {
		src      Source
		line     string
		channel  string
		location string
		typ      string
	}{
		{Source{Format: FormatMonolog}, "[2026-11-02 10:00:00] 203.0.113.7.ERROR: x", "", "", ""},
		{Source{Format: FormatMonolog}, "[2026-11-02 10:00:00] 199139999912345.ERROR: x", "", "", ""},
		{Source{Format: FormatMonolog}, "[2026-11-02 10:00:00] a.example.test.ERROR: x", "", "", ""},
		{Source{Format: FormatMonolog}, "[2026-11-02 10:00:00] app-1_x.ERROR: x", "app-1_x", "", ""},
		{json, `{"level":"error","channel":"203.0.113.7"}`, "", "", ""},
		{json, `{"level":"error","channel":"199139999912345"}`, "", "", ""},
		{json, `{"level":"error","channel":"a.example.test"}`, "", "", ""},
		{json, `{"level":"error","channel":"billing"}`, "billing", "", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/203.0.113.77/a.php on line 1", "", "a.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/ip-203.0.113.77/a.php on line 1", "", "a.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /srv/203.0.113.77.php on line 1", "", "", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/199139999912345/a.php on line 1", "", "a.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /srv/199139999912345.php on line 1", "", "", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/jean.example.test/a.php on line 1", "", "a.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /srv/jean.example.test.php on line 1", "", "", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/a.php:199139999", "", "", ""},
		{Source{Format: FormatPHP}, "PHP Fatal error:  Uncaught Zoe199139999912345: x in /var/www/demo/a.php:1", "", "a.php:1", ""},
		{Source{Format: FormatMonolog}, `[2026-11-02 10:00:00] app.ERROR: m [object] (Zoe199139999912345(code: 0): x at /var/www/demo/a.php:1)`, "app", "a.php:1", ""},
		// A host with a suffix, and digits in separated groups.
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/jean.trappe.example.test.1/a.php on line 1", "", "a.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/jean.trappe.example.test-x/a.php on line 1", "", "a.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/example.fr_old/a.php on line 1", "", "a.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/ip-203-0-113-7/a.php on line 1", "", "a.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/06-12-34-56-78/a.php on line 1", "", "a.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/ip-203.0.113/a.php on line 1", "", "a.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/ip_203_0_113_7/a.php on line 1", "", "a.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/2026-11-02/a.php on line 1", "", "a.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/v1.2.3/a.php on line 1", "", "a.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /srv/ip-203-0-113-7.php on line 1", "", "", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /srv/06-12-34-56-78.php on line 1", "", "", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /srv/ip_203_0_113_7.php on line 1", "", "", ""},
		{Source{Format: FormatPHP}, "PHP Fatal error:  Uncaught Ip_203_0_113_7: x in /var/www/demo/a.php:1", "", "a.php:1", ""},
		{Source{Format: FormatMonolog}, `[2026-11-02 10:00:00] app.ERROR: m [object] (Ip_203_0_113_7(code: 0): x at /var/www/demo/a.php:1)`, "app", "a.php:1", ""},
		{Source{Format: FormatMonolog}, "[2026-11-02 10:00:00] ip-203-0-113-7.ERROR: x", "", "", ""},
		{Source{Format: FormatMonolog}, "[2026-11-02 10:00:00] 06-12-34-56-78.ERROR: x", "", "", ""},
		{Source{Format: FormatMonolog}, "[2026-11-02 10:00:00] ip_203_0_113_7.ERROR: x", "", "", ""},
		{json, `{"level":"error","channel":"ip-203-0-113-7"}`, "", "", ""},
		{json, `{"level":"error","channel":"06-12-34-56-78"}`, "", "", ""},
		{json, `{"level":"error","channel":"ip_203_0_113_7"}`, "", "", ""},
		// Real code keeps its place.
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/php8.1/a.php on line 1", "", "php8.1/a.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/.hidden/a.php on line 1", "", ".hidden/a.php:1", ""},
		{Source{Format: FormatMonolog}, "[2026-11-02 10:00:00] app-2_x.ERROR: x", "app-2_x", "", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/resources/views/home.blade.php on line 1", "", "resources/views/home.blade.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/templates/home.html.twig on line 1", "", "templates/home.html.twig:1", ""},
		{Source{Format: FormatPHP}, "PHP Warning:  x in /var/www/demo/php8.1/2026/a.php on line 1", "", "php8.1/2026/a.php:1", ""},
		{Source{Format: FormatPHP}, "PHP Fatal error:  Uncaught App\\Foo2: x in /var/www/demo/.hidden/a.php:123456", "", ".hidden/a.php:123456", `App\Foo2`},
	} {
		raw, out := scanLog(t, c.src, c.line+"\n", o)
		r := oneRecord(t, out)
		if r.Channel != c.channel || r.Location != c.location || r.Type != c.typ {
			t.Errorf("%q gave %+v", c.line, r)
		}
		for _, bad := range []string{"203.0.113", "199139", "example.test", "example.fr", "203-0-113", "203_0_113", "06-12-34", "2026-11-02/", "v1.2.3"} {
			if bytes.Contains(raw, []byte(bad)) {
				t.Errorf("%q: %q left the filter: %q", c.line, bad, raw)
			}
		}
	}
}

// TestFilterVariants runs one corpus under each shell and awk that exists on
// this machine, and wants the same result from all.
func TestFilterVariants(t *testing.T) {
	needTools(t)
	shells := []struct {
		name string
		argv []string
	}{
		{"sh", []string{"sh"}},
		{"dash", []string{"dash"}},
		{"busybox-sh", []string{"busybox", "sh"}},
	}
	awks := []struct {
		name string
		argv []string
	}{
		{"awk", []string{"awk"}},
		{"gawk", []string{"gawk"}},
		{"gawk-posix", []string{"gawk", "--posix"}},
		{"mawk", []string{"mawk"}},
		{"busybox-awk", []string{"busybox", "awk"}},
	}
	corpus := readTrap(t) + warnLine + "\x00\xff binary line\n"
	sources := []Source{
		{Format: FormatPHP}, {Format: FormatPostgres}, {Format: FormatMonolog},
		{Format: FormatJSON, LevelField: "level", ChannelField: "channel"}, {Format: FormatText},
	}
	path := writeLog(t, corpus)
	scriptFor := func(src Source, text bool) (Source, FilterOptions, string) {
		src.Path = path
		o := FilterOptions{Text: text, RemoteDirs: []string{"/var/www/demo"}}
		script, err := Script(src, earlier, o)
		if err != nil {
			t.Fatal(err)
		}
		return src, o, script
	}
	// The reference is the plain sh with the plain awk.
	baseline := map[string]string{}
	key := func(src Source, text bool) string { return fmt.Sprintf("%s/%v", src.Format, text) }
	for _, src := range sources {
		for _, text := range []bool{false, true} {
			_, _, script := scriptFor(src, text)
			baseline[key(src, text)] = sortedLines(run(t, script))
		}
	}
	for _, sh := range shells {
		for _, aw := range awks {
			t.Run(sh.name+"/"+aw.name, func(t *testing.T) {
				if sh.name == "sh" && aw.name == "awk" {
					return // the reference itself
				}
				if _, err := exec.LookPath(sh.argv[0]); err != nil {
					t.Skipf("%s is not installed", sh.argv[0])
				}
				if _, err := exec.LookPath(aw.argv[0]); err != nil {
					t.Skipf("%s is not installed", aw.argv[0])
				}
				// The script calls `awk`: a shim ahead on PATH picks which one.
				shim := t.TempDir()
				body := "#!/bin/sh\nexec " + strings.Join(aw.argv, " ") + " \"$@\"\n"
				if aw.name != "awk" {
					if err := os.WriteFile(filepath.Join(shim, "awk"), []byte(body), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				for _, base := range sources {
					for _, text := range []bool{false, true} {
						src, o, script := scriptFor(base, text)
						raw := runWith(t, script, sh.argv, shim)
						if got := sortedLines(raw); got != baseline[key(base, text)] {
							t.Errorf("%s text=%v differs from the reference:\n%s\n--- reference\n%s", src.Format, text, got, baseline[key(base, text)])
						}
						if !text {
							assertNoMarker(t, string(src.Format), string(raw), trapMarkers)
						}
						out := ParseOutput(raw, src, o, filterNow)
						if out.Rejected != 0 || len(out.Files) != 1 || len(out.Records) == 0 {
							t.Errorf("%s text=%v: %+v", src.Format, text, out)
						}
					}
				}
			})
		}
	}
}

// sortedLines makes two outputs comparable: awk walks its groups in any order.
func sortedLines(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// An awk that writes records and then dies must not leave records without their
// position: they would be counted again by the next pass.
func TestRecordsOfACrashedAwkAreNotKept(t *testing.T) {
	needTools(t)
	p := writeLog(t, warnLine)
	src := Source{Path: p, Format: FormatPHP}
	script, err := Script(src, earlier, FilterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	shim := t.TempDir()
	fake := "#!/bin/sh\ncat >/dev/null\nprintf 'R\twarning\t\ta.php:3\t\t2026-11-02T12\t1\n'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(shim, "awk"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	out := ParseOutput(runWith(t, script, []string{"sh"}, shim), src, FilterOptions{}, filterNow)
	if len(out.Records) != 0 || len(out.Files) != 0 || len(out.Unseen) != 1 || out.Rejected != 0 {
		t.Errorf("crashed awk: %+v", out)
	}
}
