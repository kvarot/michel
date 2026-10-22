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

// Statuses reports the state of every watched ecosystem under root.
func Statuses(root string) ([]Status, error) {
	out := make([]Status, 0, len(Ecosystems))
	for _, eco := range Ecosystems {
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
// it atomically. It returns the statuses of the ecosystems updated so far.
func Update(ctx context.Context, root string, client *http.Client, ecosystems []string, now func() time.Time) ([]Status, error) {
	out := make([]Status, 0, len(ecosystems))
	for _, eco := range ecosystems {
		if err := updateOne(ctx, root, client, eco, now); err != nil {
			return out, err
		}
		out = append(out, statusOf(root, eco))
	}
	return out, nil
}

func updateOne(ctx context.Context, root string, client *http.Client, eco string, now func() time.Time) error {
	dst := ZipPath(root, eco)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/"+eco+"/all.zip", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot download the %s database: %w", eco, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cannot download the %s database: the server answered %s", eco, resp.Status)
	}
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("cannot create %s: %w", dir, err)
	}
	tmp := dst + ".tmp"
	if err := writeFile(tmp, resp.Body); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("cannot save the %s database: %w", eco, err)
	}
	if err := checkZip(tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("the %s download is not a valid zip archive (%v); the previous database, if any, was kept", eco, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		// Windows can refuse to rename over an existing file.
		if rmErr := os.Remove(dst); rmErr != nil && !os.IsNotExist(rmErr) {
			os.Remove(tmp)
			return fmt.Errorf("cannot replace %s: %w", dst, err)
		}
		if err := os.Rename(tmp, dst); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("cannot install %s: %w", dst, err)
		}
	}
	stamp := now().UTC().Format(time.RFC3339)
	if err := os.WriteFile(fetchedAtPath(root, eco), []byte(stamp+"\n"), 0o640); err != nil {
		return fmt.Errorf("cannot record the download date for %s: %w", eco, err)
	}
	return nil
}

func writeFile(path string, r io.Reader) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func checkZip(path string) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	return zr.Close()
}
