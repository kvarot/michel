// Package mask replaces secrets in text meant for an agent by tokens
// "[secret-<nonce>-N]" and puts them back in what the agent returns, for the
// page only. Michel never unmasks into a commit: applying a proposal is
// refused as soon as HasToken finds a token in it.
//
// Every Masker has its own random nonce, so a token that was already in the
// input (any "[secret-..]" text, whatever its nonce) is never resolved:
// Unmask and StreamUnmasker only replace tokens made by that Masker. The
// table of tokens lives in the secret store, never in the data base or the
// audit. Counts are per session and are not saved.
package mask

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/kvarot/michel/internal/secret"
)

// Table maps a token to the value it stands for.
type Table map[string]string

// pathPlaceholder replaces an absolute path; it is not reversible.
const pathPlaceholder = "<path>"

var nonceRe = regexp.MustCompile(`^[0-9a-f]{8}$`)

// Masker masks and unmasks text. It is safe for concurrent use.
type Masker struct {
	nonce  string
	prefix string // "[secret-<nonce>-"
	re     *regexp.Regexp

	mu      sync.Mutex
	table   Table
	byValue map[string]string
	next    int
	counts  map[string]int
}

func newWithNonce(nonce string) *Masker {
	return &Masker{
		nonce:   nonce,
		prefix:  "[secret-" + nonce + "-",
		re:      regexp.MustCompile(`^\[secret-` + nonce + `-([0-9]+)\]$`),
		table:   Table{},
		byValue: map[string]string{},
		next:    1,
		counts:  map[string]int{},
	}
}

// New returns an empty Masker with a fresh random nonce; tokens are numbered
// from 1.
func New() *Masker {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("mask: no randomness: " + err.Error())
	}
	return newWithNonce(hex.EncodeToString(b[:]))
}

// token returns the n-th token of this Masker.
func (m *Masker) token(n int) string { return m.prefix + strconv.Itoa(n) + "]" }

// Mask replaces every secret of s by its token (the same value always gets
// the same token) and every absolute path by "<path>".
func (m *Masker) Mask(s string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	found := find(s, m.prefix)
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
			tok = m.token(m.next)
			m.next++
			m.byValue[value] = tok
			m.table[tok] = value
		}
		b.WriteString(tok)
	}
	b.WriteString(s[pos:])
	return b.String()
}

// Unmask puts the real values back in place of the tokens of this Masker.
// Any other token-shaped text (other nonce, old shape, "<path>") is left as
// it is.
func (m *Masker) Unmask(s string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !strings.Contains(s, m.prefix) {
		return s
	}
	return tokenShape.ReplaceAllStringFunc(s, func(tok string) string {
		if v, ok := m.table[tok]; ok {
			return v
		}
		return tok
	})
}

// Counts returns how many items each detector masked in this session (never
// values). They are not saved.
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
	return len(m.token(m.next - 1))
}

func storeName(attemptID string) string { return "mask-" + strings.ToLower(attemptID) }

type saved struct {
	Nonce string `json:"nonce"`
	Table Table  `json:"table"`
}

// Save writes the nonce and the token table to the secret store as
// "mask-<attempt id>" (encrypted by the store).
func (m *Masker) Save(st secret.Store, attemptID string) error {
	data, err := json.Marshal(saved{Nonce: m.nonce, Table: m.Table()})
	if err != nil {
		return err
	}
	if err := st.Set(storeName(attemptID), data); err != nil {
		return fmt.Errorf("cannot save the mask table: %w", err)
	}
	return nil
}

// Delete removes the saved table of an attempt; an absent table is not an
// error.
func Delete(st secret.Store, attemptID string) error {
	if err := st.Delete(storeName(attemptID)); err != nil && !errors.Is(err, secret.ErrNotFound) {
		return fmt.Errorf("cannot delete the mask table: %w", err)
	}
	return nil
}

var errCorrupt = errors.New("mask table is corrupt")

// Load reads what Save wrote: same nonce, same tokens; numbering goes on
// after the table. A malformed table is an error.
func Load(st secret.Store, attemptID string) (*Masker, error) {
	data, err := st.Get(storeName(attemptID))
	if err != nil {
		return nil, fmt.Errorf("cannot load the mask table: %w", err)
	}
	var s saved
	if err := json.Unmarshal(data, &s); err != nil || !nonceRe.MatchString(s.Nonce) {
		return nil, errCorrupt
	}
	m := newWithNonce(s.Nonce)
	for tok, v := range s.Table {
		sub := m.re.FindStringSubmatch(tok)
		if sub == nil {
			return nil, errCorrupt
		}
		n, err := strconv.Atoi(sub[1])
		if err != nil || n < 1 {
			return nil, errCorrupt
		}
		if n >= m.next {
			m.next = n + 1
		}
		m.table[tok] = v
		m.byValue[v] = tok
	}
	return m, nil
}
