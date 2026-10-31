package fix

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/kvarot/michel/internal/secret"
)

// The server backups kept on the workstation are sealed with AES-256-GCM
// under one key that lives in Michel's secret store, like the mask tables
// of the fix agent (DPAPI on Windows; a file only its owner may read
// elsewhere). The database never holds a backup in clear, on any system.
// Without a secret store Michel keeps no copy at all.

// backupKeyName is the secret holding the backup key.
const backupKeyName = "server-backup-key"

// errNoKeyStore: no secret store, so no backup is kept.
var errNoKeyStore = errors.New("no secret store: the backup is not kept on this computer")

// errBackupTampered: a stored backup does not open or does not match its
// hash.
var errBackupTampered = errors.New("a stored backup does not match its hash")

// backupKey returns the key, made on first use. When two processes make
// it at once the one stored last wins: the key is read back after it is
// written, so both use the stored one.
func (d Deps) backupKey() ([]byte, error) {
	if d.Secrets == nil {
		return nil, errNoKeyStore
	}
	k, err := d.Secrets.Get(backupKeyName)
	if err == nil && len(k) == 32 {
		return k, nil
	}
	if err != nil && !errors.Is(err, secret.ErrNotFound) {
		return nil, fmt.Errorf("cannot read the backup key: %w", err)
	}
	k = make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := d.Secrets.Set(backupKeyName, k); err != nil {
		return nil, fmt.Errorf("cannot save the backup key: %w", err)
	}
	if k, err = d.Secrets.Get(backupKeyName); err != nil || len(k) != 32 {
		return nil, fmt.Errorf("cannot read the backup key back: %v", err)
	}
	return k, nil
}

func backupAEAD(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// addBackup seals b.Content and stores it with its SHA-256 (set here). The
// attempt, the path and the hash are bound to the ciphertext, so a blob
// moved to another row does not open.
func (d Deps) addBackup(ctx context.Context, b ServerBackup) error {
	sum := sha256.Sum256(b.Content)
	b.SHA256 = hex.EncodeToString(sum[:])
	key, err := d.backupKey()
	if err != nil {
		return err
	}
	aead, err := backupAEAD(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	blob := aead.Seal(nonce, nonce, b.Content, []byte(b.AttemptID+"\n"+b.RemotePath+"\n"+b.SHA256))
	_, err = d.repo().AddBackup(ctx, b, blob)
	return err
}

// backups returns the backups of an attempt, opened and checked against
// their hash.
func (d Deps) backups(ctx context.Context, attemptID string) ([]ServerBackup, error) {
	sealed, err := d.repo().Backups(ctx, attemptID)
	if err != nil || len(sealed) == 0 {
		return nil, err
	}
	key, err := d.backupKey()
	if err != nil {
		return nil, err
	}
	aead, err := backupAEAD(key)
	if err != nil {
		return nil, err
	}
	out := make([]ServerBackup, 0, len(sealed))
	for _, s := range sealed {
		n := aead.NonceSize()
		if len(s.Blob) < n {
			return nil, fmt.Errorf("%w (%s)", errBackupTampered, s.ID)
		}
		plain, err := aead.Open(nil, s.Blob[:n], s.Blob[n:], []byte(s.AttemptID+"\n"+s.RemotePath+"\n"+s.SHA256))
		if err != nil {
			return nil, fmt.Errorf("%w (%s)", errBackupTampered, s.ID)
		}
		sum := sha256.Sum256(plain)
		if hex.EncodeToString(sum[:]) != s.SHA256 {
			return nil, fmt.Errorf("%w (%s)", errBackupTampered, s.ID)
		}
		b := s.ServerBackup
		b.Content = plain
		out = append(out, b)
	}
	return out, nil
}

// ServerBackups returns the backups of a server fix kept on this computer,
// opened and checked (for the page: the files to put back by hand).
func ServerBackups(ctx context.Context, d Deps, attemptID string) ([]ServerBackup, error) {
	return d.backups(ctx, attemptID)
}
