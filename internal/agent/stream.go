package agent

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kvarot/michel/internal/scan"
)

// Event kinds.
const (
	KindText  = "text"  // the agent wrote text to the user
	KindTool  = "tool"  // the agent used a tool (Tool, and a short Text)
	KindDone  = "done"  // the agent finished its turn, or Claude Code ended cleanly
	KindError = "error" // the turn or the session failed (Text is a cause)
)

// Causes of an error event besides Claude Code's own result subtypes
// (error_max_turns, error_during_execution...).
const (
	CauseTimeout   = "timeout"   // Spec.Timeout reached: the process tree was killed
	CauseCancelled = "cancelled" // the context of Start was cancelled
	CauseExit      = "exit"      // Claude Code exited with an error
)

// Event is one thing Claude Code did, read from its stream-json output.
// Text is untrusted, sanitized (scan.SanitizeText) and capped.
type Event struct {
	Kind string
	Text string
	Tool string
}

// Caps of what Michel reads from Claude Code.
const (
	maxLine = 4 << 20  // a longer stdout line is skipped (counted)
	maxText = 64 << 10 // text of one event
	maxTool = 64       // tool name
	maxCmd  = 300      // tool summary
)

// newTree puts a started Claude Code under Michel's control (a variable
// for the tests).
var newTree = newProcessTree

// closeGrace is how long Close waits for Claude Code to end after its
// input is closed, before killing its process tree.
var closeGrace = 3 * time.Second

// Session is a running Claude Code. Its events end (the channel closes)
// when the process has ended.
type Session struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	events  chan Event
	done    chan struct{} // closed when the process has ended and events closed
	quit    chan struct{} // closed by kill: events are dropped, not sent
	tree    processTree
	cleanup func()
	dir     string // the copy: tool paths are shown relative to it

	wmu      sync.Mutex  // one stdin write at a time
	inClosed atomic.Bool // stdin closed; closing never waits for a write

	mu        sync.Mutex // the state below, never held during I/O
	id        string
	skipped   int
	cause     string // why Michel killed the process
	sinceSend bool   // a result arrived since the last Send

	killOnce  sync.Once
	closeOnce sync.Once
	timer     *time.Timer
}

// launch starts cmd with pipes and the readers of its output.
func launch(cmd *exec.Cmd, dir string, timeout time.Duration, cleanup func()) (*Session, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = io.Discard // may hold paths or prompt text: never kept
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	tree, err := newTree(cmd)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, ErrNoJob
	}
	s := &Session{cmd: cmd, dir: dir, stdin: stdin, events: make(chan Event, 256), done: make(chan struct{}), quit: make(chan struct{}), cleanup: cleanup, tree: tree}
	s.timer = time.AfterFunc(timeout, func() { s.kill(CauseTimeout) })
	go s.run(stdout)
	return s, nil
}

// Events is the stream of the session's events.
func (s *Session) Events() <-chan Event { return s.events }

// ID is Claude Code's session id (for Spec.ResumeID), "" until Claude Code
// has written it.
func (s *Session) ID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id
}

// Skipped is the number of output lines Michel could not read (not JSON,
// or longer than its cap) and ignored.
func (s *Session) Skipped() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.skipped
}

// Send writes text to Claude Code as a stream-json user message.
func (s *Session) Send(text string) error {
	b, err := json.Marshal(map[string]any{
		"type":               "user",
		"message":            map[string]any{"role": "user", "content": text},
		"parent_tool_use_id": nil,
		"session_id":         "",
	})
	if err != nil {
		return err
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.inClosed.Load() {
		return errors.New("the agent's session is closed")
	}
	s.mu.Lock()
	s.sinceSend = false
	s.mu.Unlock()
	if _, err := s.stdin.Write(append(b, '\n')); err != nil {
		return errors.New("the agent's session has ended")
	}
	return nil
}

// CloseInput closes Claude Code's stdin: it ends after its current turn.
// A Send blocked on a full pipe then fails instead of holding it.
func (s *Session) CloseInput() {
	if s.inClosed.CompareAndSwap(false, true) {
		_ = s.stdin.Close()
	}
}

// Close ends the session: closes the input, gives Claude Code closeGrace
// to end, then kills its process tree, and removes the generated files.
// It can be called more than once.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.CloseInput()
		select {
		case <-s.done:
		case <-time.After(closeGrace):
			s.kill("")
			<-s.done
		}
	})
	return nil
}

// kill kills the process tree; cause, when not "", is the error event the
// session ends with.
func (s *Session) kill(cause string) {
	s.killOnce.Do(func() {
		s.mu.Lock()
		s.cause = cause
		s.mu.Unlock()
		close(s.quit)
		s.CloseInput()
		s.tree.kill()
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
	})
}

// send delivers e unless the session is being killed.
func (s *Session) send(e Event) {
	select {
	case s.events <- e:
	case <-s.quit:
	}
}

// last delivers the final event: waiting for the reader, unless the
// session is being killed, then only if the channel has room (nobody may
// be reading any more).
func (s *Session) last(e Event) {
	select {
	case s.events <- e:
	case <-s.quit:
		select {
		case s.events <- e:
		default:
		}
	}
}

// run reads stdout to its end, then waits for the process and sends the
// last event.
func (s *Session) run(stdout io.Reader) {
	r := bufio.NewReaderSize(stdout, 64<<10)
	for {
		line, ok, err := readLine(r)
		if !ok {
			s.mu.Lock()
			s.skipped++
			s.mu.Unlock()
		} else if len(line) > 0 {
			s.parse(line)
		}
		if err != nil {
			break
		}
	}
	err := s.cmd.Wait()
	s.timer.Stop()
	s.tree.close()
	s.mu.Lock()
	cause, sinceSend := s.cause, s.sinceSend
	s.mu.Unlock()
	switch {
	case cause != "":
		s.last(Event{Kind: KindError, Text: cause})
	case err != nil:
		s.last(Event{Kind: KindError, Text: CauseExit})
	case !sinceSend:
		s.last(Event{Kind: KindDone})
	}
	close(s.events)
	s.cleanup()
	close(s.done)
}

// readLine reads one line of at most maxLine bytes. ok is false for a
// longer line, which is consumed and dropped. err is set at the end of the
// stream (the line read with it, if any, is still returned).
func readLine(r *bufio.Reader) (line []byte, ok bool, err error) {
	var buf []byte
	tooLong := false
	for {
		chunk, err := r.ReadSlice('\n')
		if !tooLong {
			if len(buf)+len(chunk) > maxLine+1 {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if tooLong {
			return nil, false, err
		}
		return []byte(strings.TrimRight(string(buf), "\r\n")), true, err
	}
}

// streamLine is what Michel reads of a stream-json line.
type streamLine struct {
	Type      string `json:"type"`
	Subtype   string `json:"subtype"`
	SessionID string `json:"session_id"`
	IsError   bool   `json:"is_error"`
	Message   struct {
		Content json.RawMessage `json:"content"`
	} `json:"message"`
}

type contentBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// subtypeShape is a result subtype Michel passes on as a cause.
var subtypeShape = regexp.MustCompile(`^[a-z_]{1,40}$`)

// parse turns one stream-json line into events.
func (s *Session) parse(line []byte) {
	var l streamLine
	if json.Unmarshal(line, &l) != nil || l.Type == "" {
		s.mu.Lock()
		s.skipped++
		s.mu.Unlock()
		return
	}
	if l.SessionID != "" && sessionID.MatchString(l.SessionID) {
		s.mu.Lock()
		s.id = l.SessionID
		s.mu.Unlock()
	}
	switch l.Type {
	case "assistant":
		var blocks []contentBlock
		if json.Unmarshal(l.Message.Content, &blocks) != nil {
			return
		}
		for _, b := range blocks {
			switch b.Type {
			case "text":
				if t := clean(b.Text, maxText); t != "" {
					s.send(Event{Kind: KindText, Text: t})
				}
			case "tool_use":
				s.send(Event{Kind: KindTool, Tool: clean(b.Name, maxTool), Text: toolSummary(b.Input, s.dir)})
			}
		}
	case "result":
		s.mu.Lock()
		s.sinceSend = true
		s.mu.Unlock()
		if l.IsError || (l.Subtype != "" && l.Subtype != "success") {
			cause := CauseExit
			if l.Subtype != "success" && subtypeShape.MatchString(l.Subtype) {
				cause = l.Subtype
			}
			s.send(Event{Kind: KindError, Text: cause})
			return
		}
		s.send(Event{Kind: KindDone})
	}
}

// toolSummary is a one-line summary of a tool's input: its command, or
// the file, folder or pattern it works on, with paths relative to the copy
// (dir) and any other absolute path shown as <path>.
func toolSummary(input json.RawMessage, dir string) string {
	var in struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
		Path     string `json:"path"`
		Pattern  string `json:"pattern"`
	}
	if json.Unmarshal(input, &in) != nil {
		return ""
	}
	if in.Command != "" {
		v, _, _ := strings.Cut(in.Command, "\n")
		return clean(relCommand(v, dir), maxCmd)
	}
	for _, v := range []string{in.FilePath, in.Path, in.Pattern} {
		if v != "" {
			v, _, _ = strings.Cut(v, "\n")
			return clean(relPath(v, dir), maxCmd)
		}
	}
	return ""
}

// absolute reports whether p is an absolute path on any OS Michel runs on.
func absolute(p string) bool {
	return filepath.IsAbs(p) || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) ||
		len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}

// relPath is p relative to dir (slashes), "<path>" for an absolute path
// outside dir, p itself when it is relative.
func relPath(p, dir string) string {
	if !absolute(p) {
		return p
	}
	rel, err := filepath.Rel(dir, filepath.Clean(p))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "<path>"
	}
	return filepath.ToSlash(rel)
}

// absInText matches an absolute path starting a word of a command.
var absInText = regexp.MustCompile(`(^|[\s'"=(])((?:[A-Za-z]:[\\/]|/|\\\\)[^\s'"]*)`)

// relCommand shows the copy's paths in a command relative to it and any
// other absolute path as <path>.
func relCommand(c, dir string) string {
	for _, prefix := range []string{dir + string(filepath.Separator), filepath.ToSlash(dir) + "/"} {
		c = strings.ReplaceAll(c, prefix, "")
	}
	return absInText.ReplaceAllString(c, "${1}<path>")
}

// clean sanitizes untrusted text and caps it at max bytes, on a rune
// boundary.
func clean(s string, max int) string {
	s = scan.SanitizeText(strings.ToValidUTF8(s, "�"))
	if len(s) > max {
		cut := max
		for cut > 0 && !utf8Start(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return s
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
