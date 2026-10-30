// Package mask replaces secrets in text meant for an agent by tokens
// "[secret-N]" and puts them back in what the agent returns. The table of
// tokens lives in the secret store, never in the data base or the audit.
package mask

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/kvarot/michel/internal/secret"
)

// Table maps a token to the value it stands for.
type Table map[string]string

// pathPlaceholder replaces an absolute path; it is not reversible.
const pathPlaceholder = "<path>"

// Masker masks and unmasks text. It is safe for concurrent use.
type Masker struct {
	mu      sync.Mutex
	table   Table
	byValue map[string]string
	next    int
	counts  map[string]int
}

// New returns an empty Masker; tokens are numbered from 1.
func New() *Masker {
	return &Masker{table: Table{}, byValue: map[string]string{}, next: 1, counts: map[string]int{}}
}

func tokenName(n int) string { return tokenPrefix + strconv.Itoa(n) + "]" }

// Mask replaces every secret of s by its token (the same value always gets
// the same token) and every absolute path by "<path>".
func (m *Masker) Mask(s string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	found := find(s)
	if len(found) == 0 {
		return s
	}
	var b strings.Builder
	pos := 0
	for _, f := range found {
		b.WriteString(s[pos:f.start])
		pos = f.end
		m.counts[string(f.kind)]++
		if f.kind == KindAbsPath {
			b.WriteString(pathPlaceholder)
			continue
		}
		value := s[f.start:f.end]
		tok, ok := m.byValue[value]
		if !ok {
			tok = tokenName(m.next)
			m.next++
			m.byValue[value] = tok
			m.table[tok] = value
		}
		b.WriteString(tok)
	}
	b.WriteString(s[pos:])
	return b.String()
}

// Unmask puts the real values back in place of the known tokens of s.
// Unknown tokens and "<path>" are left as they are.
func (m *Masker) Unmask(s string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.unmaskLocked(s)
}

func (m *Masker) unmaskLocked(s string) string {
	if !strings.Contains(s, tokenPrefix) {
		return s
	}
	return tokenRe.ReplaceAllStringFunc(s, func(tok string) string {
		if v, ok := m.table[tok]; ok {
			return v
		}
		return tok
	})
}

// Counts returns how many items each detector masked so far (never values).
func (m *Masker) Counts() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]int, len(m.counts))
	for k, v := range m.counts {
		out[k] = v
	}
	return out
}

// Table returns a copy of the token table.
func (m *Masker) Table() Table {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(Table, len(m.table))
	for k, v := range m.table {
		out[k] = v
	}
	return out
}

// maxTokenLen is the length of the longest known token.
func (m *Masker) maxTokenLen() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(tokenName(m.next - 1))
}

func storeName(attemptID string) string { return "mask-" + strings.ToLower(attemptID) }

// Save writes the token table to the secret store as "mask-<attempt id>"
// (encrypted by the store).
func (m *Masker) Save(st secret.Store, attemptID string) error {
	data, err := json.Marshal(m.Table())
	if err != nil {
		return err
	}
	if err := st.Set(storeName(attemptID), data); err != nil {
		return fmt.Errorf("cannot save the mask table: %w", err)
	}
	return nil
}

// Load reads the table saved by Save; numbering goes on after it.
func Load(st secret.Store, attemptID string) (*Masker, error) {
	data, err := st.Get(storeName(attemptID))
	if err != nil {
		return nil, fmt.Errorf("cannot load the mask table: %w", err)
	}
	var t Table
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("mask table is corrupt: %w", err)
	}
	m := New()
	for tok, v := range t {
		sub := tokenRe.FindStringSubmatch(tok)
		if sub == nil || sub[0] != tok {
			return nil, fmt.Errorf("mask table is corrupt: bad token")
		}
		n, _ := strconv.Atoi(sub[1])
		if n >= m.next {
			m.next = n + 1
		}
		m.table[tok] = v
		m.byValue[v] = tok
	}
	return m, nil
}
