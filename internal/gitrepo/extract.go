package gitrepo

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Extract writes the members of a gzip-compressed tar archive under dst,
// without the first path component (codeload's <repo>-<sha>/ folder). It
// refuses the whole archive (ErrTraversal) when a member's path is absolute,
// holds "..", a backslash, a drive letter or a reserved name; it refuses
// links (ErrSymlink, hard links too) and devices (ErrSpecialFile). Files are
// written 0o644 and folders 0o755, whatever the archive says. The caps are
// MaxArchiveBytes compressed, MaxExtractedBytes and MaxFiles written. On an
// error, what was already written stays: the caller extracts into a fresh
// folder and drops it (Fetch does).
func Extract(r io.Reader, dst string) ([]FileInfo, error) { return extract(r, dst, "") }

// capReader fails with ErrTooLarge once more than max bytes went through.
type capReader struct {
	r    io.Reader
	n    int64
	max  int64
	what string
}

func (c *capReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n, fmt.Errorf("%w: more than %d bytes %s", ErrTooLarge, c.max, c.what)
	}
	return n, err
}

// unsafeName reports whether a member's raw path could leave its folder on
// any system.
func unsafeName(name string) bool {
	if name == "" || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") {
		return true
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." || strings.Contains(seg, ":") {
			return true
		}
	}
	return false
}

// rootFile reports whether rel is a licence or readme at the repository's
// root, kept beside a skill's folder for the preview.
func rootFile(rel string) bool {
	if strings.Contains(rel, "/") {
		return false
	}
	u := strings.ToUpper(rel)
	for _, p := range []string{"LICENSE", "LICENCE", "COPYING", "README"} {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	return false
}

// extract is Extract limited to the folder sub of the repository (and the
// licence and readme files of its root) when sub is not "": the other
// members are read through and dropped, never written, so a link elsewhere
// in a large repository does not refuse a skill that has none.
func extract(r io.Reader, dst, sub string) ([]FileInfo, error) {
	gz, err := gzip.NewReader(&capReader{r: r, max: limits.archive, what: "compressed"})
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return nil, err
		}
		return nil, fmt.Errorf("the archive is not a gzip file: %w", err)
	}
	defer gz.Close()
	plain := &capReader{r: gz, max: maxScannedBytes, what: "in the whole archive"}
	tr := tar.NewReader(plain)
	var files []FileInfo
	var written int64
	members := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, ErrTooLarge) {
				return nil, err
			}
			return nil, fmt.Errorf("the archive cannot be read: %w", err)
		}
		if members++; members > maxScannedMembers {
			return nil, ErrTooManyFiles
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		if unsafeName(h.Name) {
			return nil, fmt.Errorf("%w: %q", ErrTraversal, clip(h.Name))
		}
		parts := strings.Split(strings.Trim(h.Name, "/"), "/")
		if len(parts) < 2 {
			continue // the root folder itself
		}
		rel := strings.Join(parts[1:], "/")
		if sub != "" && rel != sub && !strings.HasPrefix(rel, sub+"/") && !(rootFile(rel) && h.Typeflag == tar.TypeReg) {
			continue
		}
		local := filepath.FromSlash(rel)
		if !filepath.IsLocal(local) {
			return nil, fmt.Errorf("%w: %q", ErrTraversal, clip(h.Name))
		}
		target := filepath.Join(dst, local)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return nil, fmt.Errorf("cannot create a folder of the archive: %w", err)
			}
		case tar.TypeReg:
			if len(files) >= limits.files {
				return nil, fmt.Errorf("%w (cap %d)", ErrTooManyFiles, limits.files)
			}
			if h.Size < 0 || written+h.Size > limits.extracted {
				return nil, fmt.Errorf("%w: more than %d bytes once extracted", ErrTooLarge, limits.extracted)
			}
			n, err := writeFile(target, tr, limits.extracted-written)
			if err != nil {
				return nil, err
			}
			written += n
			files = append(files, FileInfo{Path: rel, Size: n})
		case tar.TypeSymlink, tar.TypeLink:
			return nil, fmt.Errorf("%w: %q", ErrSymlink, clip(rel))
		default:
			return nil, fmt.Errorf("%w: %q", ErrSpecialFile, clip(rel))
		}
	}
	// Read to the end of the gzip stream: its checksum is verified and the
	// compressed cap applies to the whole download.
	if _, err := io.Copy(io.Discard, plain); err != nil {
		if errors.Is(err, ErrTooLarge) {
			return nil, err
		}
		return nil, fmt.Errorf("the archive cannot be read: %w", err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

// writeFile copies at most max bytes of r to a new file at target, mode
// 0o644, its folders 0o755.
func writeFile(target string, r io.Reader, max int64) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return 0, fmt.Errorf("cannot create a folder of the archive: %w", err)
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, fmt.Errorf("cannot write a file of the archive: %w", err)
	}
	n, err := io.Copy(f, io.LimitReader(r, max+1))
	cerr := f.Close()
	switch {
	case err != nil:
		return n, fmt.Errorf("cannot write a file of the archive: %w", err)
	case n > max:
		return n, fmt.Errorf("%w: more than %d bytes once extracted", ErrTooLarge, limits.extracted)
	case cerr != nil:
		return n, fmt.Errorf("cannot write a file of the archive: %w", cerr)
	}
	return n, nil
}

// clip bounds a member name quoted in an error.
func clip(s string) string {
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return strings.ToValidUTF8(s, "?")
}
