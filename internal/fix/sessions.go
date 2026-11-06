package fix

import (
	"sync"
	"time"

	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/secret"
)

// Sessions is the registry of the agents running in this process.
type Sessions struct {
	mu        sync.Mutex
	m         map[string]*running
	lock      map[string]*sync.Mutex
	proposing map[string]*sync.Mutex
	// gitLocks are the locks of a click on a remote, per project.
	gitLocks map[string]*sync.Mutex
	// gitRuleMu is the lock of the network rules of Git services (lockGitRules).
	gitRuleMu sync.Mutex
	// The level 3 runner's memory (ApplyAutoServer) and the agents' package
	// simulations, per attempt.
	autoErr     map[string]string
	autoTried   map[string]time.Time
	autoAlerted map[string]bool
	sims        map[string]int
	// testing are the attempts whose tests run now on a click (RunTests).
	testing map[string]bool
}

// running is one attempt's session: the agent, its proxy, its masker and
// the signal of its end.
type running struct {
	sess       Session
	masker     *mask.Masker
	closeProxy func()
	done       chan struct{}
	// mu serializes mask (a Mask and the Save of the table it grew); saved
	// is the size of the table last saved.
	mu    sync.Mutex
	saved int
}

// mask masks text with the session's masker and, when that made a new
// token, saves the table at once: the page's display masker (another
// masker loaded from the store) then numbers its own tokens after it, so
// that one token never stands for two values (final review I8). The
// process that runs the session is the only one that saves its table;
// michel mcp masks with a fresh masker of its own (controller ruling 18).
func (r *running) mask(st secret.Store, attemptID, text string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.masker.Mask(text)
	if n := r.masker.Len(); n != r.saved && st != nil {
		if r.masker.Save(st, attemptID) == nil {
			r.saved = n
		}
	}
	return out
}

// NewSessions returns an empty registry.
func NewSessions() *Sessions {
	return &Sessions{m: map[string]*running{}, lock: map[string]*sync.Mutex{}, proposing: map[string]*sync.Mutex{},
		autoErr: map[string]string{}, autoTried: map[string]time.Time{}, autoAlerted: map[string]bool{}, sims: map[string]int{}}
}

// proposeLock is the mutex held for a whole Propose of one attempt: two
// proposals of the same attempt never run at the same time (one scratch
// worktree, one commit at a time); the second waits for the first.
func (s *Sessions) proposeLock(id string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.proposing[id]
	if !ok {
		m = &sync.Mutex{}
		s.proposing[id] = m
	}
	return m
}

func (s *Sessions) add(id string, r *running) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = r
}

func (s *Sessions) get(id string) (*running, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[id]
	return r, ok
}

func (s *Sessions) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

// attemptLock is the mutex of one attempt: Apply and the end of its session
// never run at the same time.
func (s *Sessions) attemptLock(id string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.lock[id]
	if !ok {
		m = &sync.Mutex{}
		s.lock[id] = m
	}
	return m
}

// Wait waits until the session of the attempt has ended (at once when there
// is none) and reports whether it did within timeout.
func (s *Sessions) Wait(id string, timeout time.Duration) bool {
	r, ok := s.get(id)
	if !ok {
		return true
	}
	select {
	case <-r.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// Close ends the session of the attempt, if this process runs it, and
// waits for its loop to finish.
func (s *Sessions) Close(id string) {
	r, ok := s.get(id)
	if !ok {
		return
	}
	_ = r.sess.Close()
	<-r.done
}

// CloseAll ends every session of the registry (serve stops).
func (s *Sessions) CloseAll() {
	s.mu.Lock()
	ids := make([]string, 0, len(s.m))
	for id := range s.m {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.Close(id)
	}
}
