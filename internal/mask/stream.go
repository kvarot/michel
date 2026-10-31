package mask

import "strings"

// StreamUnmasker unmasks a text that arrives in chunks. It never emits part
// of a token: text from the last "[" is held back while it could still grow
// into a token of its Masker (within the length of the longest known token),
// and released as soon as it cannot. It is not safe for concurrent use.
type StreamUnmasker struct {
	m   *Masker
	buf string
}

// NewStreamUnmasker returns a StreamUnmasker over m.
func NewStreamUnmasker(m *Masker) *StreamUnmasker { return &StreamUnmasker{m: m} }

// couldBeToken reports whether tail (starting with "[") may be the start of
// a token that begins with prefix.
func couldBeToken(tail, prefix string, maxLen int) bool {
	if len(tail) >= maxLen { // a full-length token would already be closed
		return false
	}
	if len(tail) <= len(prefix) {
		return strings.HasPrefix(prefix, tail)
	}
	if !strings.HasPrefix(tail, prefix) {
		return false
	}
	for _, c := range tail[len(prefix):] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Write adds chunk and returns the text that is safe to show.
func (s *StreamUnmasker) Write(chunk string) string {
	s.buf += chunk
	cut := len(s.buf)
	if i := strings.LastIndexByte(s.buf, '['); i >= 0 && couldBeToken(s.buf[i:], s.m.prefix, s.m.maxTokenLen()) {
		cut = i
	}
	out := s.m.Unmask(s.buf[:cut])
	s.buf = s.buf[cut:]
	return out
}

// Flush returns what is still held (unmasked) and empties the buffer.
func (s *StreamUnmasker) Flush() string {
	out := s.m.Unmask(s.buf)
	s.buf = ""
	return out
}
