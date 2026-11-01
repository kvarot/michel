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

// backupKey returns the key that seals the backups. The secret store
// holds the key; the database holds its fingerprint, in one row that only
// one process writes first (INSERT ... ON CONFLICT DO NOTHING), so two
// processes never seal with two keys.
//
// A process that finds the row waits (up to BackupKeyWait, as long as ctx
// allows) for the key with that fingerprint to show in the store. The key
// is replaced only when the store keeps saying it has no such secret
// (secret.ErrNotFound) past that wait: the store was wiped, the backups
// sealed with the lost key no longer open (they are still on the server).
// Any other read error, or a key with another fingerprint, fails closed for
// the caller (that one backup is not kept) and leaves the key alone. A
// secret that exists is never written over.
func (d Deps) backupKey(ctx context.Context) ([]byte, error) {
	if d.Secrets == nil {
		return nil, errNoKeyStore
	}
	repo := d.repo()
	fp, err := repo.BackupKeyFingerprint(ctx)
	if err != nil {
		return nil, err
	}
	if fp == "" {
		cur, gerr := d.Secrets.Get(backupKeyName)
		switch {
		case gerr == nil && len(cur) == 32:
			// A key without its record: record it, never replace it.
			if _, err := repo.SetBackupKeyFingerprint(ctx, "", keyFingerprint(cur)); err != nil {
				return nil, err
			}
		case gerr == nil:
			return nil, errKeyUnusable
		case !errors.Is(gerr, secret.ErrNotFound):
			return nil, fmt.Errorf("cannot read the backup key: %w", gerr)
		default:
			k, err := newKey()
			if err != nil {
				return nil, err
			}
			won, err := repo.SetBackupKeyFingerprint(ctx, "", keyFingerprint(k))
			if err != nil {
				return nil, err
			}
			if won {
				return d.storeKey(k)
			}
		}
		if fp, err = repo.BackupKeyFingerprint(ctx); err != nil || fp == "" {
			return nil, errors.Join(errors.New("cannot agree on the backup key"), err)
		}
	}
	k, err := d.waitKey(ctx, fp)
	if err == nil || !errors.Is(err, secret.ErrNotFound) {
		return k, err
	}
	// The key stayed missing: replace it, once, by a compare and swap on
	// its fingerprint.
	k, err = newKey()
	if err != nil {
		return nil, err
	}
	won, err := repo.SetBackupKeyFingerprint(ctx, fp, keyFingerprint(k))
	if err != nil {
		return nil, err
	}
	if !won {
		// Another process replaced it first: wait for its key.
		nfp, err := repo.BackupKeyFingerprint(ctx)
		if err != nil {
			return nil, err
		}
		return d.waitKey(ctx, nfp)
	}
	k, err = d.storeKey(k)
	if err == nil {
		_ = keep("server_fix.backup_key", "", d.record(ctx, "server_fix.backup_key", "", "rotated", map[string]any{"reason": "key missing from the secret store"}))
	}
	return k, err
}

var errKeyUnusable = errors.New("the backup key in the secret store is not the recorded one: no backup is kept")

func newKey() ([]byte, error) {
	k := make([]byte, 32)
	_, err := rand.Read(k)
	return k, err
}

// storeKey writes the key this process won the record for, never over an
// existing secret, and reads it back.
func (d Deps) storeKey(k []byte) ([]byte, error) {
	if _, err := d.Secrets.Get(backupKeyName); !errors.Is(err, secret.ErrNotFound) {
		return nil, errors.Join(errKeyUnusable, err)
	}
	if err := d.Secrets.Set(backupKeyName, k); err != nil {
		return nil, fmt.Errorf("cannot save the backup key: %w", err)
	}
	got, err := d.Secrets.Get(backupKeyName)
	if err != nil || keyFingerprint(got) != keyFingerprint(k) {
		return nil, fmt.Errorf("cannot read the backup key back: %v", err)
	}
	return k, nil
}

// waitKey waits for the key with fingerprint fp in the store. It returns
// an error wrapping secret.ErrNotFound only when the store said so until
// the wait ended; any other error at once.
func (d Deps) waitKey(ctx context.Context, fp string) ([]byte, error) {
	wait := d.BackupKeyWait
	if wait <= 0 {
		wait = 10 * time.Second
	}
	end := time.Now().Add(wait)
	for {
		k, err := d.Secrets.Get(backupKeyName)
		switch {
		case err == nil && keyFingerprint(k) == fp:
			return k, nil
		case err == nil:
			return nil, errKeyUnusable
		case !errors.Is(err, secret.ErrNotFound):
			return nil, fmt.Errorf("cannot read the backup key: %w", err)
		}
		if time.Now().After(end) {
			return nil, fmt.Errorf("the backup key is missing from the secret store: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
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
	b.KeyFingerprint = keyFingerprint(key)
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
		if openBackup(aead, s) != nil {
			// One bad row never hides the others: it is skipped and reported.
			bad = append(bad, fmt.Errorf("%w (%s)", errBackupTampered, s.ID))
			continue
		}
		plain, _ := aead.Open(nil, s.Blob[:n], s.Blob[n:], backupAAD(s.ServerBackup))
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

// The states of a backup kept on this computer.
const (
	// BackupKept: the copy opens and matches its hash.
	BackupKept = "kept"
	// BackupKeyLost: the copy was sealed with a key the secret store no
	// longer holds (it was replaced): it cannot be opened, the copy on the
	// server is the one to use.
	BackupKeyLost = "key_lost"
	// BackupDamaged: the copy was sealed with the current key (or one Michel
	// did not record) and does not open or does not match its hash.
	BackupDamaged = "damaged"
)

// BackupState is a backup of a server fix as the page shows it: the server
// file it copies, when, and whether it can still be opened here.
type BackupState struct {
	RemotePath string
	CreatedAt  time.Time
	State      string
}

// BackupStates tells, for each backup of an attempt kept on this computer,
// whether it opens (kept), was sealed with a key that was replaced since
// (key_lost), or no longer matches (damaged). Nothing is opened for the
// caller: only the state is returned.
func BackupStates(ctx context.Context, d Deps, attemptID string) ([]BackupState, error) {
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
	current := keyFingerprint(key)
	out := make([]BackupState, 0, len(sealed))
	for _, s := range sealed {
		st := BackupState{RemotePath: s.RemotePath, CreatedAt: s.CreatedAt, State: BackupKept}
		if openBackup(aead, s) != nil {
			st.State = BackupDamaged
			if s.KeyFingerprint != "" && s.KeyFingerprint != current {
				st.State = BackupKeyLost
			}
		}
		out = append(out, st)
	}
	return out, nil
}

// openBackup opens a sealed backup and checks its hash.
func openBackup(aead cipher.AEAD, s SealedBackup) error {
	n := aead.NonceSize()
	if len(s.Blob) < n {
		return errBackupTampered
	}
	plain, err := aead.Open(nil, s.Blob[:n], s.Blob[n:], backupAAD(s.ServerBackup))
	if err != nil {
		return errBackupTampered
	}
	sum := sha256.Sum256(plain)
	if hex.EncodeToString(sum[:]) != s.SHA256 {
		return errBackupTampered
	}
	return nil
}

// ServerBackups returns the backups of a server fix kept on this computer,
// opened and checked (for the page: the files to put back by hand).
func ServerBackups(ctx context.Context, d Deps, attemptID string) ([]ServerBackup, error) {
	return d.backups(ctx, attemptID)
}
