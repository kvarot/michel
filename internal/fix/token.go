package fix

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/kvarot/michel/internal/secret"
)

// The environment variables through which Michel binds a "michel mcp"
// session to one attempt.
const (
	EnvAttempt = "MICHEL_FIX_ATTEMPT"
	EnvToken   = "MICHEL_FIX_TOKEN"
)

// tokenName is the secret store name of the token of an attempt.
func tokenName(attemptID string) string { return "fix-token-" + strings.ToLower(attemptID) }

func tokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return []byte(hex.EncodeToString(sum[:]))
}

// SetAttemptToken stores the SHA-256 of token for the attempt (the token
// itself is never stored).
func SetAttemptToken(st secret.Store, attemptID, token string) error {
	if token == "" {
		return errors.New("empty fix attempt token")
	}
	name := tokenName(attemptID)
	if !secret.ValidName(name) {
		return secret.ErrInvalidName
	}
	return st.Set(name, tokenHash(token))
}

// CheckAttemptToken reports whether token is the one stored for the attempt.
// The hashes are compared in constant time; any problem gives false.
func CheckAttemptToken(st secret.Store, attemptID, token string) bool {
	name := tokenName(attemptID)
	if st == nil || token == "" || !secret.ValidName(name) {
		return false
	}
	stored, err := st.Get(name)
	if err != nil || len(stored) != sha256.Size*2 {
		return false
	}
	return subtle.ConstantTimeCompare(stored, tokenHash(token)) == 1
}

// DeleteAttemptToken removes the token of the attempt; an absent token is
// not an error.
func DeleteAttemptToken(st secret.Store, attemptID string) error {
	name := tokenName(attemptID)
	if !secret.ValidName(name) {
		return secret.ErrInvalidName
	}
	if err := st.Delete(name); err != nil && !errors.Is(err, secret.ErrNotFound) {
		return err
	}
	return nil
}
