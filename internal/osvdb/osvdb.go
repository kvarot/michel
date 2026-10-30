package osvdb

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// baseURL is replaced in tests.
var baseURL = "https://" + Host

// ErrDatabaseMissing means an offline database has not been downloaded.
var ErrDatabaseMissing = errors.New("offline database missing")

// ErrNotModified means the server answered 304 to the If-Modified-Since of
// the last download: the database on disk is current and was kept as it is.
var ErrNotModified = errors.New("the database has not changed since the last download")

// Status describes one ecosystem's database on disk.
type Status struct {
	Ecosystem string    `json:"ecosystem"`
	Path      string    `json:"path"`
	Present   bool      `json:"present"`
	FetchedAt time.Time `json:"fetched_at"`
	SizeBytes int64     `json:"size_bytes"`
}

func statusOf(root, eco string) Status {
	s := Status{Ecosystem: eco, Path: ZipPath(root, eco)}
	if fi, err := os.Stat(s.Path); err == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
		s.Present, s.SizeBytes = true, fi.Size()
	}
	if b, err := os.ReadFile(fetchedAtPath(root, eco)); err == nil {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b))); err == nil {
			s.FetchedAt = t
		}
	}
	return s
}

// Statuses reports the state of each of ecosystems under root.
func Statuses(root string, ecosystems []string) ([]Status, error) {
	out := make([]Status, 0, len(ecosystems))
	for _, eco := range ecosystems {
		out = append(out, statusOf(root, eco))
	}
	return out, nil
}

// Require returns ErrDatabaseMissing for the first ecosystem without a database.
func Require(root string, ecosystems []string) error {
	for _, eco := range ecosystems {
		if !statusOf(root, eco).Present {
			return fmt.Errorf("%w for %s: run \"michel db update\"", ErrDatabaseMissing, eco)
		}
	}
	return nil
}

// Update downloads the archive of each ecosystem through client and installs
// it atomically. An archive the server reports unchanged since the last
// download (304) is kept and counts as updated. It returns the statuses of
// the ecosystems updated so far.
func Update(ctx context.Context, root string, client *http.Client, ecosystems []string, now func() time.Time) ([]Status, error) {
	out := make([]Status, 0, len(ecosystems))
	for _, eco := range ecosystems {
		st, _, err := UpdateEcosystem(ctx, root, client, eco, now)
		if err != nil && !errors.Is(err, ErrNotModified) {
			return out, err
		}
		out = append(out, st)
	}
	return out, nil
}

// UpdateEcosystem downloads the archive of one ecosystem through client and
// installs it atomically. When a database is present, the request carries
// If-Modified-Since with its last download or check date; a 304 answer keeps
// the database, moves that date to now and returns ErrNotModified. advisories is the
// number of entries of the new archive (0 on ErrNotModified).
func UpdateEcosystem(ctx context.Context, root string, client *http.Client, eco string, now func() time.Time) (st Status, advisories int, err error) {
	advisories, err = updateOne(ctx, root, client, eco, now)
	return statusOf(root, eco), advisories, err
}

// Limits protecting the disk and memory from a hostile or broken server.
// They are variables so tests can lower them.
var (
	maxDownloadBytes   int64  = 2 << 30
	maxZipEntries             = 2_000_000
	maxZipUncompressed uint64 = 8 << 30
)

// perEcosystemTimeout bounds the whole download of one archive.
const perEcosystemTimeout = 15 * time.Minute

// SetLimitsForTest lowers the safety limits and returns a restore function.
// Tests only.
func SetLimitsForTest(download int64, entries int, uncompressed uint64) (restore func()) {
	d, e, u := maxDownloadBytes, maxZipEntries, maxZipUncompressed
	maxDownloadBytes, maxZipEntries, maxZipUncompressed = download, entries, uncompressed
	return func() { maxDownloadBytes, maxZipEntries, maxZipUncompressed = d, e, u }
}

func updateOne(parent context.Context, root string, client *http.Client, eco string, now func() time.Time) (int, error) {
	ctx, cancel := context.WithTimeout(parent, perEcosystemTimeout)
	defer cancel()
	dst := ZipPath(root, eco)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/"+eco+"/all.zip", nil)
	if err != nil {
		return 0, err
	}
	if cur := statusOf(root, eco); cur.Present && !cur.FetchedAt.IsZero() {
		req.Header.Set("If-Modified-Since", cur.FetchedAt.UTC().Format(http.TimeFormat))
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("cannot download the %s database: %w", eco, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		// The database on disk is current as of now: the date moves so the
		// freshness check and the next If-Modified-Since start from here.
		if err := os.WriteFile(fetchedAtPath(root, eco), []byte(now().UTC().Format(time.RFC3339)+"\n"), 0o640); err != nil {
			return 0, fmt.Errorf("cannot record the check date for %s: %w", eco, err)
		}
		return 0, ErrNotModified
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("cannot download the %s database: the server answered %s", eco, resp.Status)
	}
	if resp.ContentLength > maxDownloadBytes {
		return 0, fmt.Errorf("the %s database announces %d bytes, above the %d byte limit; refusing to download it", eco, resp.ContentLength, maxDownloadBytes)
	}
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return 0, fmt.Errorf("cannot create %s: %w", dir, err)
	}
	tmp := dst + ".tmp"
	if err := writeFile(tmp, io.LimitReader(resp.Body, maxDownloadBytes+1), maxDownloadBytes); err != nil {
		os.Remove(tmp)
		return 0, fmt.Errorf("cannot save the %s database: %w", eco, err)
	}
	entries, err := checkZip(tmp)
	if err != nil {
		os.Remove(tmp)
		return 0, fmt.Errorf("the %s download is not an acceptable zip archive (%v); the previous database, if any, was kept", eco, err)
	}
	if err := install(tmp, dst); err != nil {
		os.Remove(tmp)
		return 0, fmt.Errorf("cannot install the %s database at %s: %w", eco, dst, err)
	}
	stamp := now().UTC().Format(time.RFC3339)
	if err := os.WriteFile(fetchedAtPath(root, eco), []byte(stamp+"\n"), 0o640); err != nil {
		return 0, fmt.Errorf("cannot record the download date for %s: %w", eco, err)
	}
	return entries, nil
}

// install moves tmp over dst without ever deleting dst before tmp is in place.
func install(tmp, dst string) error {
	err := os.Rename(tmp, dst)
	if err == nil {
		return nil
	}
	if _, serr := os.Lstat(dst); serr != nil {
		return err
	}
	old := dst + ".old"
	os.Remove(old)
	if rerr := os.Rename(dst, old); rerr != nil {
		return err
	}
	if rerr := os.Rename(tmp, dst); rerr != nil {
		os.Rename(old, dst)
		return rerr
	}
	os.Remove(old)
	return nil
}

func writeFile(path string, r io.Reader, limit int64) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, r)
	if err != nil {
		f.Close()
		return err
	}
	if n > limit {
		f.Close()
		return fmt.Errorf("the download exceeds the %d byte limit", limit)
	}
	return f.Close()
}

// checkZip checks the archive at path against the limits and returns its
// number of entries.
func checkZip(path string) (int, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return 0, err
	}
	defer zr.Close()
	if len(zr.File) > maxZipEntries {
		return 0, fmt.Errorf("%d entries, above the %d limit", len(zr.File), maxZipEntries)
	}
	var total uint64
	for _, f := range zr.File {
		total += f.UncompressedSize64
		if total > maxZipUncompressed {
			return 0, fmt.Errorf("uncompressed size above the %d byte limit", maxZipUncompressed)
		}
	}
	return len(zr.File), nil
}
