package serverlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/target"
)

// logHost is a simulated server whose `sh -s` is the real sh of this machine,
// with a client connected to it through the egress gateway.
type logHost struct {
	srv    *sshtest.Server
	client *sshx.Client

	mu      sync.Mutex
	scripts []string
}

func (h *logHost) sent() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.scripts...)
}

// realShell runs the script on the real sh. env nil means the test's own.
func (h *logHost) realShell(env []string) sshtest.ShellFunc {
	return func(_ *sshtest.Server, script string, stdout, stderr io.Writer) int {
		h.mu.Lock()
		h.scripts = append(h.scripts, script)
		h.mu.Unlock()
		sh, err := exec.LookPath("sh")
		if err != nil {
			io.WriteString(stderr, "sh: not found\n")
			return 127
		}
		cmd := exec.Command(sh, "-s")
		cmd.Stdin = strings.NewReader(script)
		cmd.Env = env
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return ee.ExitCode()
			}
			return 126
		}
		return 0
	}
}

func startLogHost(t *testing.T, shell func(h *logHost) sshtest.ShellFunc) *logHost {
	t.Helper()
	needTools(t)
	h := &logHost{}
	h.srv = sshtest.New(t, sshtest.Options{Shell: shell(h)})
	ag := h.srv.NewAgent(t)
	p := policy.Defaults()
	p.Sovereignty.Network.Allow = []policy.AllowRule{{Host: "127.0.0.1", Purpose: policy.PurposeTargetSSH}}
	gw := egress.New(p, nil)
	host, port, err := net.SplitHostPort(h.srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	pn, _ := strconv.Atoi(port)
	tg := target.Target{ID: "01TARGETDEMO", Name: "srv-demo", Host: host, Port: pn, User: "deploy",
		HostKey: h.srv.HostKeyFingerprint(), Kind: target.KindVPS, Env: target.EnvProd, Classification: policy.ClassInternal}
	c, err := sshx.Dial(context.Background(), sshx.Deps{
		Gateway:    gw,
		KnownHosts: filepath.Join(t.TempDir(), "known_hosts"),
		Agent:      func() (agent.ExtendedAgent, io.Closer, error) { return ag, nil, nil },
		Now:        time.Now,
	}, tg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	h.client = c
	return h
}

func plainHost(t *testing.T) *logHost {
	return startLogHost(t, func(h *logHost) sshtest.ShellFunc { return h.realShell(os.Environ()) })
}

func appendTo(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

var readNow = time.Date(2026, 11, 2, 12, 30, 0, 0, time.UTC)

const readLine = "PHP Warning:  x in /var/www/demo/a.php on line 3\n"

// readSrc reads src once, with the cursors saved so far, and merges the new
// ones in the way the caller does (an upsert by file).
func readSrc(t *testing.T, h *logHost, src Source, saved map[string]Cursor, o FilterOptions) (Output, []Cursor) {
	t.Helper()
	var cs []Cursor
	for _, c := range saved {
		cs = append(cs, c)
	}
	out, next, err := Read(context.Background(), h.client, src, cs, o, 30*time.Second, readNow)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	for _, c := range next {
		saved[c.File] = c
	}
	return out, next
}

func total(out Output) int64 {
	var n int64
	for _, r := range out.Records {
		n += r.Count
	}
	return n
}

func TestFirstReadStartsAtEnd(t *testing.T) {
	h := plainHost(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	appendTo(t, p, readLine+readLine)
	src := Source{ID: "S1", Path: shPath(p), Format: FormatPHP}
	saved := map[string]Cursor{}

	// Activation: the history is not read.
	out, next := readSrc(t, h, src, saved, FilterOptions{})
	if len(out.Records) != 0 || len(next) != 1 || next[0].Offset != int64(2*len(readLine)) || next[0].SourceID != "S1" || next[0].File != src.Path || next[0].FileID == "" {
		t.Fatalf("first read: out=%+v cursors=%+v", out, next)
	}
	// A line added after is read, once.
	appendTo(t, p, readLine)
	out, _ = readSrc(t, h, src, saved, FilterOptions{})
	if total(out) != 1 {
		t.Fatalf("after the activation: %+v", out)
	}
	out, _ = readSrc(t, h, src, saved, FilterOptions{})
	if total(out) != 0 {
		t.Fatalf("read twice: %+v", out)
	}
}

func TestFileAppearedAfterActivationIsReadFromItsStart(t *testing.T) {
	h := plainHost(t)
	dir := t.TempDir()
	appendTo(t, filepath.Join(dir, "app-1.log"), readLine+readLine)
	src := Source{ID: "S1", Path: shPath(dir) + "/app-*.log", Format: FormatPHP}
	saved := map[string]Cursor{}
	if out, _ := readSrc(t, h, src, saved, FilterOptions{}); len(out.Records) != 0 {
		t.Fatalf("activation: %+v", out)
	}
	appendTo(t, filepath.Join(dir, "app-2.log"), readLine+readLine+readLine)
	out, _ := readSrc(t, h, src, saved, FilterOptions{})
	if total(out) != 3 || len(saved) != 2 {
		t.Fatalf("new file: %+v, cursors %d", out, len(saved))
	}
}

// Decision: an activation that finds no file still counts as an activation. A
// file that shows up later is read from its start, like any file appeared
// after the activation. The read leaves a placeholder cursor for that.
func TestActivationWithoutFileReadsTheFileWhenItAppears(t *testing.T) {
	h := plainHost(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "late.log")
	src := Source{ID: "S1", Path: shPath(p), Format: FormatPHP}
	saved := map[string]Cursor{}
	out, next := readSrc(t, h, src, saved, FilterOptions{})
	if len(out.Unseen) != 1 || len(next) != 1 {
		t.Fatalf("no file: out=%+v cursors=%+v", out, next)
	}
	if next[0].File == src.Path || !strings.HasPrefix(next[0].File, src.Path) {
		t.Errorf("the placeholder must not be a file path: %q", next[0].File)
	}
	appendTo(t, p, readLine+readLine)
	out, _ = readSrc(t, h, src, saved, FilterOptions{})
	if total(out) != 2 || len(out.Unseen) != 0 {
		t.Fatalf("file appeared: %+v", out)
	}
	if f := saved[src.Path]; f.Offset != int64(2*len(readLine)) {
		t.Errorf("cursor: %+v", f)
	}
}

func TestPartialLineWaitsForNextRead(t *testing.T) {
	h := plainHost(t)
	p := filepath.Join(t.TempDir(), "app.log")
	appendTo(t, p, "")
	src := Source{ID: "S1", Path: shPath(p), Format: FormatPHP}
	saved := map[string]Cursor{}
	readSrc(t, h, src, saved, FilterOptions{})

	half := "PHP Warning:  x in /var/www/demo/a.php on"
	appendTo(t, p, readLine+half)
	out, _ := readSrc(t, h, src, saved, FilterOptions{})
	if total(out) != 1 || saved[src.Path].Offset != int64(len(readLine)) {
		t.Fatalf("partial line: %+v, %+v", out, saved[src.Path])
	}
	appendTo(t, p, " line 9\n")
	out, _ = readSrc(t, h, src, saved, FilterOptions{})
	if r := oneRecord(t, out); r.Count != 1 || r.Location != "a.php:9" {
		t.Fatalf("completed line: %+v", out)
	}
}

func TestHugeLineAndBinaryRespectCap(t *testing.T) {
	h := plainHost(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	appendTo(t, p, "")
	src := Source{ID: "S1", Path: shPath(p), Format: FormatPHP}
	saved := map[string]Cursor{}
	readSrc(t, h, src, saved, FilterOptions{})

	// 20 MiB without a newline.
	const size = 20 << 20
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	chunk := []byte(strings.Repeat("x", 1<<20))
	for i := 0; i < 20; i++ {
		if _, err := f.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	out, _ := readSrc(t, h, src, saved, FilterOptions{})
	fs := fileState(t, out)
	if fs.Skipped <= 0 || fs.Offset != size || len(out.Records) != 0 || fs.Skipped > size {
		t.Fatalf("huge line: %+v", out)
	}
	// Nothing is skipped again once the position is at the end.
	out, _ = readSrc(t, h, src, saved, FilterOptions{})
	if fs := fileState(t, out); fs.Skipped != 0 || fs.Offset != size {
		t.Fatalf("second read: %+v", out)
	}

	// NUL bytes: the position follows the bytes, the good line is read.
	bin := filepath.Join(dir, "bin.log")
	body := strings.Repeat("\x00", 100000) + "\n" + readLine
	appendTo(t, bin, "")
	bsrc := Source{ID: "S2", Path: shPath(bin), Format: FormatPHP}
	bsaved := map[string]Cursor{}
	readSrc(t, h, bsrc, bsaved, FilterOptions{})
	appendTo(t, bin, body)
	out, _ = readSrc(t, h, bsrc, bsaved, FilterOptions{ReadCap: 50000})
	fs = fileState(t, out)
	if fs.Skipped <= 0 || fs.Offset != int64(len(body)) || total(out) != 1 {
		t.Fatalf("binary: %+v", out)
	}
}

func TestFileSwappedOrTruncatedBetweenReads(t *testing.T) {
	h := plainHost(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	appendTo(t, p, readLine)
	src := Source{ID: "S1", Path: shPath(p), Format: FormatPHP}
	saved := map[string]Cursor{}
	readSrc(t, h, src, saved, FilterOptions{})
	id := saved[src.Path].FileID

	// Another file (another inode): from the start, and it is said.
	other := map[string]Cursor{src.Path: {SourceID: "S1", File: src.Path, FileID: id + "9", Offset: int64(len(readLine))}}
	out, next := readSrc(t, h, src, other, FilterOptions{})
	if fs := fileState(t, out); !fs.Rotated || total(out) != 1 || next[0].Offset != int64(len(readLine)) || next[0].FileID != id {
		t.Fatalf("swapped: %+v %+v", out, next)
	}
	// A shorter file: from the start, and it is said.
	short := map[string]Cursor{src.Path: {SourceID: "S1", File: src.Path, FileID: id, Offset: 1 << 20}}
	out, _ = readSrc(t, h, src, short, FilterOptions{})
	if fs := fileState(t, out); !fs.Rotated || total(out) != 1 {
		t.Fatalf("truncated: %+v", out)
	}

	// A file deleted, then a folder put in its place: unseen, nothing read.
	gone := filepath.Join(dir, "gone.log")
	appendTo(t, gone, readLine)
	gsrc := Source{ID: "S3", Path: shPath(gone), Format: FormatPHP}
	gsaved := map[string]Cursor{}
	readSrc(t, h, gsrc, gsaved, FilterOptions{})
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	out, next = readSrc(t, h, gsrc, gsaved, FilterOptions{})
	if len(out.Unseen) != 1 || len(out.Files) != 0 || len(out.Records) != 0 || len(next) != 0 {
		t.Fatalf("deleted: %+v %+v", out, next)
	}
	if err := os.Mkdir(gone, 0o755); err != nil {
		t.Fatal(err)
	}
	out, next = readSrc(t, h, gsrc, gsaved, FilterOptions{})
	if len(out.Unseen) != 1 || len(out.Files) != 0 || len(out.Records) != 0 || len(next) != 0 {
		t.Fatalf("folder: %+v %+v", out, next)
	}
}

// A symbolic link put where the file was is unseen: the target is not read
// (spec § 4). Skipped where the machine cannot make a link (Windows without the
// privilege); the check was made on Linux with the generated script.
func TestSymlinkInPlaceOfTheFileIsUnseen(t *testing.T) {
	h := plainHost(t)
	dir := t.TempDir()
	secret := filepath.Join(dir, "elsewhere.log")
	appendTo(t, secret, readLine+readLine)
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("no symbolic link on this machine: %v", err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Skip("the link is not a real link here")
	}
	src := Source{ID: "S3", Path: shPath(link), Format: FormatPHP}
	for _, cs := range [][]Cursor{nil, {{SourceID: "S3", File: src.Path, FileID: "1", Offset: 0}}} {
		out, _, err := Read(context.Background(), h.client, src, cs, FilterOptions{}, 30*time.Second, readNow)
		if err != nil || len(out.Unseen) != 1 || len(out.Records) != 0 || len(out.Files) != 0 {
			t.Fatalf("link: %+v %v", out, err)
		}
	}
}

func TestWildcardReadsAllWithOneCursorEach(t *testing.T) {
	h := plainHost(t)
	dir := t.TempDir()
	for i := 1; i <= 3; i++ {
		appendTo(t, filepath.Join(dir, fmt.Sprintf("app-%d.log", i)), readLine)
	}
	appendTo(t, filepath.Join(dir, "other.log"), readLine)
	src := Source{ID: "S1", Path: shPath(dir) + "/app-*.log", Format: FormatPHP}
	saved := map[string]Cursor{}
	_, next := readSrc(t, h, src, saved, FilterOptions{})
	if len(next) != 3 {
		t.Fatalf("one cursor per file, got %+v", next)
	}
	for i := 1; i <= 3; i++ {
		appendTo(t, filepath.Join(dir, fmt.Sprintf("app-%d.log", i)), strings.Repeat(readLine, i))
	}
	out, next := readSrc(t, h, src, saved, FilterOptions{})
	if len(next) != 3 || total(out) != 6 || len(out.Files) != 3 {
		t.Fatalf("each file from its own position: %+v", out)
	}
	for _, c := range next {
		if strings.Contains(c.File, "other") {
			t.Errorf("a file out of the wildcard: %+v", c)
		}
	}
}

func TestWildcardCapIsReported(t *testing.T) {
	h := plainHost(t)
	dir := t.TempDir()
	for i := 0; i < 51; i++ {
		appendTo(t, filepath.Join(dir, fmt.Sprintf("app-%02d.log", i)), readLine)
	}
	src := Source{ID: "S1", Path: shPath(dir) + "/app-*.log", Format: FormatPHP}
	saved := map[string]Cursor{}
	readSrc(t, h, src, saved, FilterOptions{})
	for i := 0; i < 51; i++ {
		appendTo(t, filepath.Join(dir, fmt.Sprintf("app-%02d.log", i)), readLine)
	}
	out, _ := readSrc(t, h, src, saved, FilterOptions{})
	if len(out.Files) != 50 || !out.TooManyFiles || total(out) != 50 {
		t.Fatalf("51 files: %d read, too many=%v, count=%d", len(out.Files), out.TooManyFiles, total(out))
	}
	// The first name in glob order is the one left out: the dated files that
	// matter are the newest.
	for _, f := range out.Files {
		if strings.HasSuffix(f.File, "app-00.log") {
			t.Errorf("the oldest name was read: %s", f.File)
		}
	}
}

// denyRead makes path unreadable for this user, or skips the test.
func denyRead(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		user := os.Getenv("USERNAME")
		if user == "" {
			t.Skip("no user name to deny")
		}
		if err := exec.Command("icacls", path, "/deny", user+":(R)").Run(); err != nil {
			t.Skipf("icacls cannot deny the file: %v", err)
		}
		t.Cleanup(func() { exec.Command("icacls", path, "/remove:d", user).Run() })
	} else if err := os.Chmod(path, 0); err != nil {
		t.Skipf("chmod: %v", err)
	}
	if f, err := os.Open(path); err == nil {
		f.Close()
		t.Skip("this user can read the file anyway (root?)")
	}
}

func TestDeniedFileIsUnseenWithoutSudo(t *testing.T) {
	h := plainHost(t)
	p := filepath.Join(t.TempDir(), "secret.log")
	appendTo(t, p, readLine)
	denyRead(t, p)
	src := Source{ID: "S1", Path: shPath(p), Format: FormatPHP}
	for _, cs := range [][]Cursor{nil, {{SourceID: "S1", File: src.Path + "/"}}} {
		out, _, err := Read(context.Background(), h.client, src, cs, FilterOptions{}, 30*time.Second, readNow)
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Unseen) != 1 || len(out.Files) != 0 || len(out.Records) != 0 {
			t.Fatalf("denied: %+v", out)
		}
	}
	all := append(h.srv.Log(), h.sent()...)
	for _, l := range all {
		if strings.Contains(l, "sudo") {
			t.Errorf("sudo was used or sent: %q", l)
		}
	}
	if len(h.srv.Log()) != 2 {
		t.Errorf("one command per read, got %q", h.srv.Log())
	}
}

func TestAwkMissingIsUnseen(t *testing.T) {
	h := startLogHost(t, func(h *logHost) sshtest.ShellFunc {
		return h.realShell(append(os.Environ(), "PATH="+t.TempDir()))
	})
	p := filepath.Join(t.TempDir(), "app.log")
	appendTo(t, p, readLine)
	src := Source{ID: "S1", Path: shPath(p), Format: FormatPHP}
	out, _, err := Read(context.Background(), h.client, src, earlier, FilterOptions{}, 30*time.Second, readNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Unseen) != 1 || len(out.Records) != 0 || len(out.Files) != 0 {
		t.Fatalf("no awk: %+v", out)
	}
	// No fallback: one command, and no copy of the file asked for.
	if got := h.srv.Log(); len(got) != 1 || got[0] != "'sh' '-s'" {
		t.Errorf("commands: %q", got)
	}
	for _, s := range h.sent() {
		if strings.Contains(s, "cat ") {
			t.Errorf("the script falls back to cat")
		}
	}
}

func TestTryStoresNothing(t *testing.T) {
	h := plainHost(t)
	e := setup(t, target.EnvProd)
	p := filepath.Join(t.TempDir(), "app.log")
	appendTo(t, p, readLine+readLine)
	src, err := e.r.AddSource(context.Background(), Source{TargetID: e.tgt.ID, Path: shPath(p), Format: FormatPHP, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	// Try shows what the history holds, from its start.
	out, err := Try(context.Background(), h.client, src, FilterOptions{}, 30*time.Second, readNow)
	if err != nil {
		t.Fatal(err)
	}
	if total(out) != 2 {
		t.Fatalf("Try: %+v", out)
	}
	ctx := context.Background()
	if cs, err := e.r.Cursors(ctx, src.ID); err != nil || len(cs) != 0 {
		t.Errorf("a position was stored: %+v %v", cs, err)
	}
	if sigs, err := e.r.Signatures(ctx, e.tgt.ID); err != nil || len(sigs) != 0 {
		t.Errorf("a signature was stored: %+v %v", sigs, err)
	}
	for _, q := range []string{`SELECT COUNT(*) FROM log_bucket`, `SELECT COUNT(*) FROM log_cursor`, `SELECT COUNT(*) FROM log_signature`} {
		if n := count(t, e, q); n != 0 {
			t.Errorf("%s = %d", q, n)
		}
	}
	// The first real read still starts at the end: Try moved nothing.
	saved := map[string]Cursor{}
	if out, _ := readSrc(t, h, src, saved, FilterOptions{}); len(out.Records) != 0 || !fileState(t, out).First {
		t.Errorf("Try moved the start: %+v", out)
	}
}

func TestReadRefusesAnOutputThatWasCut(t *testing.T) {
	h := startLogHost(t, func(*logHost) sshtest.ShellFunc {
		return func(_ *sshtest.Server, _ string, stdout, _ io.Writer) int {
			// A valid record, then more than MaxOutput of noise: the F line would come last.
			io.WriteString(stdout, "R\twarning\t\ta.php:3\t\t2026-11-02T12\t1\n")
			io.WriteString(stdout, strings.Repeat("R\n", sshx.MaxOutput))
			io.WriteString(stdout, "F\t/var/log/a.log\t1\t10\t0\t0\t0\n")
			return 0
		}
	})
	src := Source{ID: "S1", Path: "/var/log/a.log", Format: FormatPHP}
	out, cs, err := Read(context.Background(), h.client, src, earlier, FilterOptions{}, 30*time.Second, readNow)
	if !errors.Is(err, ErrOutputCut) || len(cs) != 0 || len(out.Records) != 0 {
		t.Fatalf("cut output: out=%+v cursors=%+v err=%v", out, cs, err)
	}
	if _, err := Try(context.Background(), h.client, src, FilterOptions{}, 30*time.Second, readNow); !errors.Is(err, ErrOutputCut) {
		t.Errorf("Try on a cut output: %v", err)
	}
}

func TestReadFailuresMoveNothing(t *testing.T) {
	cases := map[string]sshtest.ShellFunc{
		"exit status": func(_ *sshtest.Server, _ string, stdout, stderr io.Writer) int {
			io.WriteString(stdout, "F\t/var/log/a.log\t1\t10\t0\t0\t0\n")
			io.WriteString(stderr, "boom /home/someone\n")
			return 2
		},
		"no answer": func(*sshtest.Server, string, io.Writer, io.Writer) int { return 0 },
	}
	for name, shell := range cases {
		t.Run(name, func(t *testing.T) {
			h := startLogHost(t, func(*logHost) sshtest.ShellFunc { return shell })
			src := Source{ID: "S1", Path: "/var/log/a.log", Format: FormatPHP}
			out, cs, err := Read(context.Background(), h.client, src, earlier, FilterOptions{}, 30*time.Second, readNow)
			if err == nil || len(cs) != 0 || len(out.Files) != 0 {
				t.Fatalf("out=%+v cursors=%+v err=%v", out, cs, err)
			}
			if strings.Contains(err.Error(), "someone") {
				t.Errorf("the error carries what the server wrote: %v", err)
			}
		})
	}
}

func TestReadTimesOut(t *testing.T) {
	h := startLogHost(t, func(*logHost) sshtest.ShellFunc {
		return func(*sshtest.Server, string, io.Writer, io.Writer) int {
			time.Sleep(1500 * time.Millisecond)
			return 0
		}
	})
	src := Source{ID: "S1", Path: "/var/log/a.log", Format: FormatPHP}
	_, cs, err := Read(context.Background(), h.client, src, earlier, FilterOptions{}, 300*time.Millisecond, readNow)
	if !errors.Is(err, sshx.ErrCommandTimeout) || len(cs) != 0 {
		t.Fatalf("timeout: %v %+v", err, cs)
	}
}

func TestReadRefusesABadSourceBeforeAnyCommand(t *testing.T) {
	h := plainHost(t)
	_, _, err := Read(context.Background(), h.client, Source{Path: "/var/log/../etc/x", Format: FormatPHP}, nil, FilterOptions{}, time.Second, readNow)
	if err == nil || len(h.srv.Log()) != 0 {
		t.Fatalf("bad path: %v, commands %q", err, h.srv.Log())
	}
}

// The server path of a file stays out of the API: a FileState marshals without it.
func TestFileStateKeepsThePathOutOfJSON(t *testing.T) {
	b, err := json.Marshal(FileState{File: "/home/someone/app.log", FileID: "42", Offset: 7})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "someone") || strings.Contains(string(b), "app.log") {
		t.Errorf("the path is in the JSON: %s", b)
	}
}

// The placeholder of a wildcard source must still be a path Script accepts, and
// must survive a round trip through the database: the next read builds a script
// from what Repo gives back.
func TestPlaceholderCursorSurvivesTheRepoForAWildcard(t *testing.T) {
	h := plainHost(t)
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	for _, glob := range []string{"/app-*.log", "/app-????.log", "/one.log"} {
		t.Run(glob, func(t *testing.T) {
			dir := t.TempDir()
			src, err := e.r.AddSource(ctx, Source{TargetID: e.tgt.ID, Path: shPath(dir) + glob, Format: FormatPHP, Active: true})
			if err != nil {
				t.Fatal(err)
			}
			// Activation with no file: only a placeholder is left.
			out, next, err := Read(ctx, h.client, src, nil, FilterOptions{}, 30*time.Second, readNow)
			if err != nil || len(out.Unseen) != 1 || len(next) != 1 {
				t.Fatalf("activation: out=%+v next=%+v err=%v", out, next, err)
			}
			if err := e.r.SaveCursors(ctx, next); err != nil {
				t.Fatal(err)
			}
			stored, err := e.r.Cursors(ctx, src.ID)
			if err != nil || len(stored) != 1 {
				t.Fatalf("stored: %+v %v", stored, err)
			}
			// Still no file: the script is built from the stored placeholder.
			if _, _, err := Read(ctx, h.client, src, stored, FilterOptions{}, 30*time.Second, readNow); err != nil {
				t.Fatalf("read with the stored placeholder: %v", err)
			}
			// The file shows up: read from its start, never the placeholder's.
			name := strings.NewReplacer("*", "2026", "?", "7").Replace(glob[1:])
			appendTo(t, filepath.Join(dir, name), readLine+readLine)
			out, next, err = Read(ctx, h.client, src, stored, FilterOptions{}, 30*time.Second, readNow)
			if err != nil || total(out) != 2 || len(next) != 1 {
				t.Fatalf("file appeared: out=%+v next=%+v err=%v", out, next, err)
			}
			for _, c := range next {
				if strings.HasSuffix(c.File, "/") {
					t.Errorf("the placeholder came back as a position: %+v", c)
				}
			}
			// Try uses the same placeholder.
			if _, err := Try(ctx, h.client, src, FilterOptions{}, 30*time.Second, readNow); err != nil {
				t.Fatalf("Try: %v", err)
			}
		})
	}
}

// Decision: a first read that finds only files it cannot read leaves a
// placeholder like an empty one. The file is read from its start once it is
// readable (the cap bounds how much history that is).
func TestFirstReadOfOnlyUnreadableFilesLeavesAPlaceholder(t *testing.T) {
	h := plainHost(t)
	p := filepath.Join(t.TempDir(), "secret.log")
	appendTo(t, p, readLine)
	denyRead(t, p)
	src := Source{ID: "S1", Path: shPath(p), Format: FormatPHP}
	out, next, err := Read(context.Background(), h.client, src, nil, FilterOptions{}, 30*time.Second, readNow)
	if err != nil || len(out.Unseen) != 1 || len(next) != 1 || !strings.HasSuffix(next[0].File, "/") {
		t.Fatalf("out=%+v next=%+v err=%v", out, next, err)
	}
}
