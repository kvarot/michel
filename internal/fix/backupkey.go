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
	"time"
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

// backupKey returns the key that seals the backups. The secret store
// holds the key; the database holds its fingerprint, in one row that only
// one process can write first (a conditional insert), so two processes
// never seal with two keys: the loser waits for the winner's key to show
// in the store. A key lost from the store (store wiped) is replaced the
// same way (conditional update); the backups sealed with the lost key no
// longer open, which is fail closed (they are still on the server).
func (d Deps) backupKey(ctx context.Context) ([]byte, error) {
	if d.Secrets == nil {
		return nil, errNoKeyStore
	}
	repo := d.repo()
	for try := 0; try < 3; try++ {
		fp, err := repo.BackupKeyFingerprint(ctx)
		if err != nil {
			return nil, err
		}
		if fp != "" {
			// Wait a little for the key of the process that made it.
			for wait := 0; wait < 50; wait++ {
				if k, err := d.Secrets.Get(backupKeyName); err == nil && keyFingerprint(k) == fp {
					return k, nil
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		won, err := repo.SetBackupKeyFingerprint(ctx, fp, keyFingerprint(k))
		if err != nil {
			return nil, err
		}
		if !won {
			continue
		}
		if err := d.Secrets.Set(backupKeyName, k); err != nil {
			return nil, fmt.Errorf("cannot save the backup key: %w", err)
		}
		if got, err := d.Secrets.Get(backupKeyName); err != nil || keyFingerprint(got) != keyFingerprint(k) {
			return nil, fmt.Errorf("cannot read the backup key back: %v", err)
		}
		return k, nil
	}
	return nil, errors.New("cannot agree on the backup key")
}

// keyFingerprint names a key without revealing it.
func keyFingerprint(k []byte) string {
	if len(k) != 32 {
		return "-"
	}
	h := sha256.Sum256(append([]byte("michel server backup key\n"), k...))
	return hex.EncodeToString(h[:])
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
	key, err := d.backupKey(ctx)
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
	blob := aead.Seal(nonce, nonce, b.Content, backupAAD(b))
	_, err = d.repo().AddBackup(ctx, b, blob)
	return err
}

// backups returns the backups of an attempt, opened and checked against
// their hash. A row that does not open is left out and reported in the
// error (errBackupTampered), the good ones are still returned.
func (d Deps) backups(ctx context.Context, attemptID string) ([]ServerBackup, error) {
	sealed, err := d.repo().Backups(ctx, attemptID)
	if err != nil || len(sealed) == 0 {
		return nil, err
	}
	key, err := d.backupKey(ctx)
	if err != nil {
		return nil, err
	}
	aead, err := backupAEAD(key)
	if err != nil {
		return nil, err
	}
	out := make([]ServerBackup, 0, len(sealed))
	var bad []error
	for _, s := range sealed {
		n := aead.NonceSize()
		var plain []byte
		var oerr error
		if len(s.Blob) < n {
			oerr = errBackupTampered
		} else if plain, oerr = aead.Open(nil, s.Blob[:n], s.Blob[n:], backupAAD(s.ServerBackup)); oerr == nil {
			sum := sha256.Sum256(plain)
			if hex.EncodeToString(sum[:]) != s.SHA256 {
				oerr = errBackupTampered
			}
		}
		if oerr != nil {
			// One bad row never hides the others: it is skipped and reported.
			bad = append(bad, fmt.Errorf("%w (%s)", errBackupTampered, s.ID))
			continue
		}
		b := s.ServerBackup
		b.Content = plain
		out = append(out, b)
	}
	return out, errors.Join(bad...)
}

// backupAAD binds a sealed backup to its attempt, server, path and hash:
// a blob moved to another row, or a row moved to another server, does not
// open.
func backupAAD(b ServerBackup) []byte {
	return []byte(b.AttemptID + "\n" + b.TargetID + "\n" + b.RemotePath + "\n" + b.SHA256)
}

// ServerBackups returns the backups of a server fix kept on this computer,
// opened and checked (for the page: the files to put back by hand).
func ServerBackups(ctx context.Context, d Deps, attemptID string) ([]ServerBackup, error) {
	return d.backups(ctx, attemptID)
}
