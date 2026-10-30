package gitrepo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/source"
)

// SkillsDirEnv overrides the skills folder. It exists for the tests, which
// must never write in the real ~/.claude/skills; it is not a setting.
const SkillsDirEnv = "MICHEL_SKILLS_DIR"

// DefaultSkillsDir is the user's skills folder of Claude Code
// (~/.claude/skills), or SkillsDirEnv when set.
func DefaultSkillsDir() (string, error) {
	if d := os.Getenv(SkillsDirEnv); d != "" {
		return filepath.Abs(d)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot find your home folder: %w", err)
	}
	return filepath.Join(home, ".claude", "skills"), nil
}

// marker is the content of MarkerFile.
type marker struct {
	Key         string `json:"key"`
	SHA         string `json:"sha"`
	InstalledAt string `json:"installed_at"`
}

// readMarker reads the marker of dir; ok is false when there is none or it
// cannot be read.
func readMarker(dir string) (marker, bool) {
	b, err := os.ReadFile(filepath.Join(dir, MarkerFile))
	if err != nil || len(b) > 4096 {
		return marker{}, false
	}
	var m marker
	if err := json.Unmarshal(b, &m); err != nil {
		return marker{}, false
	}
	return m, true
}

// OwnerKey returns the key written in the marker of dir (a folder Michel
// owns); ok is false for a missing or unreadable marker.
func OwnerKey(dir string) (key string, ok bool) {
	m, ok := readMarker(dir)
	return m.Key, ok
}

// ownedBy reports whether dir carries the marker of key.
func ownedBy(dir, key string) bool {
	m, ok := readMarker(dir)
	return ok && m.Key == key
}

// insideAny reports whether p is one of roots or under one of them.
func insideAny(p string, roots []string) bool {
	for _, r := range roots {
		if r == "" {
			continue
		}
		ra, err := filepath.Abs(r)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(ra, p)
		if err == nil && (rel == "." || filepath.IsLocal(rel)) {
			return true
		}
	}
	return false
}

// Install installs e at the commit sha, after the caller has shown the
// preview of that same sha and got the user's consent. A skill's folder is
// copied to SkillsDir/<name>/ with MarkerFile; a folder of that name without
// the marker of e, or with another source's, is refused with ErrForeignDir
// and left untouched. An MCP server writes nothing outside the data folder:
// the user adds it to Claude Code with the line of the preview. The entry is
// pinned to sha and records installed_sha (and install_dir for a skill); a
// source.install event is written. When a new version of an installed skill
// has another name (Upgrade shows the move), it is installed in the new
// folder and, once the config is saved, the previous one is removed when it
// carries the marker of e at the installed sha; otherwise the installation
// is kept and the error is ErrOldFolderKept, with the folder returned.
func Install(ctx context.Context, d Deps, e source.Entry, sha string) (string, error) {
	t, err := targetOf(e, sha)
	if err != nil {
		return "", err
	}
	folder, _, err := t.fetch(ctx, d, e.Key)
	if err != nil {
		return "", err
	}
	user := map[string]any{}
	for k, v := range e.Config.User {
		user[k] = v
	}
	user["installed_sha"], user["pinned"] = sha, sha
	ev := map[string]any{"key": e.Key, "kind": string(e.Kind), "repo": t.owner + "/" + t.name, "sha": sha}
	installedTo := ""
	var leftover error
	if e.Kind == source.KindSkill {
		name, err := skillNameOf(folder, t)
		if err != nil {
			return "", err
		}
		if installedTo, err = copySkill(d, e.Key, sha, folder, name); err != nil {
			return "", err
		}
		user["install_dir"] = installedTo
		ev["folder"] = name
	}
	if err := d.Repo.SetUserConfig(ctx, e.Key, user); err != nil {
		return "", err
	}
	// The previous folder goes only once the config names the new one.
	if old := previousDir(e, installedTo); e.Kind == source.KindSkill && old != "" {
		ev["previous_folder"] = filepath.Base(old)
		leftover = removeOld(d, e.Key, e.Config.Str("installed_sha"), old, installedTo)
	}
	if d.Audit != nil {
		if _, err := d.Audit.Record(ctx, audit.Event{Actor: d.actor(), Action: "source.install", Target: e.Key, Result: "ok", Evidence: ev}); err != nil {
			return "", fmt.Errorf("cannot write the audit event of %s: %w", e.Key, err)
		}
	}
	return installedTo, leftover
}

// previousDir is the folder of the installed version of e when the new one
// went elsewhere (its skill name changed); "" otherwise.
func previousDir(e source.Entry, installedTo string) string {
	old := e.Config.Str("install_dir")
	if e.Config.Str("installed_sha") == "" || old == "" || SameDir(old, installedTo) {
		return ""
	}
	return old
}

// removeOld removes the folder of the previous version after a move: only
// when it is not the folder just installed (installedTo) under another
// spelling, lies in the skills folder, has a valid name and carries the
// marker of key with the previous sha (oldSHA; the new installation's
// marker has the new one). A case-only rename on a case-insensitive
// filesystem resolves old to the new folder: it is kept, without error.
// Otherwise, or when the removal fails, old is left there and the error
// (ErrOldFolderKept) says so; the new installation stays.
func removeOld(d Deps, key, oldSHA, old, installedTo string) error {
	if _, err := os.Lstat(old); err != nil {
		return nil // already gone
	}
	if a, err := os.Stat(old); err == nil {
		if b, err := os.Stat(installedTo); err == nil && os.SameFile(a, b) {
			return nil // the folder just installed
		}
	}
	skills, err := filepath.Abs(d.SkillsDir)
	m, marked := readMarker(old)
	if err != nil || d.SkillsDir == "" || !SameDir(filepath.Dir(old), skills) || !validSkillName(filepath.Base(old)) ||
		!marked || m.Key != key || oldSHA == "" || m.SHA != oldSHA {
		return fmt.Errorf("%w: %s does not carry Michel's marker for %s at %s", ErrOldFolderKept, old, key, oldSHA)
	}
	if err := os.RemoveAll(old); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrOldFolderKept, old, err)
	}
	return nil
}

// SameDir compares two folders after cleaning, without case on Windows.
func SameDir(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// copySkill copies folder to SkillsDir/name through a temporary folder in
// SkillsDir renamed into place, so a failed copy leaves the previous
// installation (or nothing) behind.
func copySkill(d Deps, key, sha, folder, name string) (string, error) {
	if d.SkillsDir == "" {
		return "", errors.New("no skills folder")
	}
	skills, err := filepath.Abs(d.SkillsDir)
	if err != nil {
		return "", fmt.Errorf("cannot resolve the skills folder: %w", err)
	}
	if insideAny(skills, d.Forbidden) {
		return "", ErrInsideProject
	}
	dst := filepath.Join(skills, name)
	if _, err := os.Lstat(dst); err == nil && !ownedBy(dst, key) {
		return "", fmt.Errorf("%w: %s", ErrForeignDir, dst)
	}
	if err := os.MkdirAll(skills, 0o755); err != nil {
		return "", fmt.Errorf("cannot create the skills folder: %w", err)
	}
	tmp, err := os.MkdirTemp(skills, ".michel-install-")
	if err != nil {
		return "", fmt.Errorf("cannot write in the skills folder: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(tmp)
		}
	}()
	if err := copyTree(folder, tmp); err != nil {
		return "", err
	}
	m, _ := json.Marshal(marker{Key: key, SHA: sha, InstalledAt: d.now().UTC().Format(time.RFC3339)})
	if err := os.WriteFile(filepath.Join(tmp, MarkerFile), m, 0o644); err != nil {
		return "", fmt.Errorf("cannot write the marker: %w", err)
	}
	if err := swapDir(skills, tmp, dst, name); err != nil {
		return "", err
	}
	ok = true
	return dst, nil
}

// copyTree copies the regular files and folders of src into dst (files
// 0o644, folders 0o755); the extracted archive holds nothing else.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil || !(rel == "." || filepath.IsLocal(rel)) {
			return fmt.Errorf("%w: %q", ErrTraversal, p)
		}
		to := filepath.Join(dst, rel)
		switch {
		case de.IsDir():
			return os.MkdirAll(to, 0o755)
		case de.Type().IsRegular():
			in, err := os.Open(p)
			if err != nil {
				return err
			}
			defer in.Close()
			out, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
			if err != nil {
				return err
			}
			_, err = io.Copy(out, in)
			if cerr := out.Close(); err == nil {
				err = cerr
			}
			return err
		}
		return fmt.Errorf("%w: %q", ErrSpecialFile, rel)
	})
}

// Uninstall removes what Install wrote for e: the skill's folder when it
// carries the marker of e (ErrForeignDir otherwise, nothing removed), and
// the kept archives. The entry forgets installed_sha and install_dir; a
// source.remove event is written.
func Uninstall(ctx context.Context, d Deps, e source.Entry) error {
	if e.Config.Str("installed_sha") == "" {
		return fmt.Errorf("%w: %s", ErrNotInstalled, e.Key)
	}
	ev := map[string]any{"key": e.Key, "kind": string(e.Kind), "mode": "uninstalled"}
	if dir := e.Config.Str("install_dir"); e.Kind == source.KindSkill && dir != "" {
		skills, err := filepath.Abs(d.SkillsDir)
		if d.SkillsDir == "" || err != nil || !SameDir(filepath.Dir(dir), skills) || !validSkillName(filepath.Base(dir)) {
			return fmt.Errorf("%w: %s is not a folder of the skills folder", ErrForeignDir, dir)
		}
		if _, err := os.Lstat(dir); err == nil {
			if !ownedBy(dir, e.Key) {
				return fmt.Errorf("%w: %s", ErrForeignDir, dir)
			}
			if err := os.RemoveAll(dir); err != nil {
				return fmt.Errorf("cannot remove the installed skill: %w", err)
			}
		}
		ev["folder"] = filepath.Base(dir)
	}
	if d.DataDir != "" {
		os.RemoveAll(reposDir(d.DataDir, e.Key))
	}
	user := map[string]any{}
	for k, v := range e.Config.User {
		if k != "installed_sha" && k != "install_dir" {
			user[k] = v
		}
	}
	if err := d.Repo.SetUserConfig(ctx, e.Key, user); err != nil {
		return err
	}
	if d.Audit != nil {
		if _, err := d.Audit.Record(ctx, audit.Event{Actor: d.actor(), Action: "source.remove", Target: e.Key, Result: "ok", Evidence: ev}); err != nil {
			return fmt.Errorf("cannot write the audit event of %s: %w", e.Key, err)
		}
	}
	return nil
}

// Upgrade downloads the archive of toSHA and compares it with the installed
// one (or the pinned one when nothing is installed): the files added,
// changed and removed in the entry's folder, and the changed lines of
// SKILL.md. It installs nothing: the caller shows the diff, asks, then
// calls Install with toSHA.
func Upgrade(ctx context.Context, d Deps, e source.Entry, toSHA string) (Diff, error) {
	from := e.Config.Str("installed_sha")
	if from == "" {
		from = e.Config.Str("pinned")
	}
	tf, err := targetOf(e, from)
	if err != nil {
		return Diff{}, err
	}
	tt, err := targetOf(e, toSHA)
	if err != nil {
		return Diff{}, err
	}
	oldDir, _, err := tf.fetch(ctx, d, e.Key)
	if err != nil {
		return Diff{}, err
	}
	newDir, _, err := tt.fetch(ctx, d, e.Key)
	if err != nil {
		return Diff{}, err
	}
	diff := Diff{From: from, To: toSHA, Added: []string{}, Changed: []string{}, Removed: []string{}}
	if e.Kind == source.KindSkill {
		// The folder the new version goes to is shown before consent: a
		// new front matter name moves the skill.
		name, err := skillNameOf(newDir, tt)
		if err != nil {
			return Diff{}, err
		}
		if d.SkillsDir == "" {
			return Diff{}, errors.New("no skills folder")
		}
		skills, err := filepath.Abs(d.SkillsDir)
		if err != nil {
			return Diff{}, fmt.Errorf("cannot resolve the skills folder: %w", err)
		}
		diff.NewDir = filepath.Join(skills, name)
		diff.OldDir = e.Config.Str("install_dir")
		if diff.OldDir == "" {
			diff.OldDir = diff.NewDir
		}
	}
	oldFiles, err := hashes(oldDir)
	if err != nil {
		return Diff{}, err
	}
	newFiles, err := hashes(newDir)
	if err != nil {
		return Diff{}, err
	}
	for _, f := range sortedKeys(newFiles) {
		switch h, ok := oldFiles[f]; {
		case !ok:
			diff.Added = append(diff.Added, f)
		case h != newFiles[f]:
			diff.Changed = append(diff.Changed, f)
		}
	}
	for _, f := range sortedKeys(oldFiles) {
		if _, ok := newFiles[f]; !ok {
			diff.Removed = append(diff.Removed, f)
		}
	}
	a, _ := os.ReadFile(filepath.Join(oldDir, "SKILL.md"))
	b, _ := os.ReadFile(filepath.Join(newDir, "SKILL.md"))
	if !bytes.Equal(a, b) {
		diff.SkillMDDiff = lineDiff(string(a), string(b))
	}
	return diff, nil
}

// hashes maps each file under dir (slash paths) to its SHA-256.
func hashes(dir string) (map[string][32]byte, error) {
	files, err := listFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot list the files of the archive: %w", err)
	}
	out := make(map[string][32]byte, len(files))
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil {
			return nil, err
		}
		out[f.Path] = sha256.Sum256(b)
	}
	return out, nil
}

func sortedKeys(m map[string][32]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// maxDiffLines bounds each side of the SKILL.md comparison.
const maxDiffLines = 2000

// lineDiff is a minimal unified diff of a and b: the removed lines with
// "-", the added ones with "+", in order, from a longest common
// subsequence; lines are cleaned for a terminal.
func lineDiff(a, b string) string {
	al, bl := splitLines(a), splitLines(b)
	if len(al) > maxDiffLines || len(bl) > maxDiffLines {
		return fmt.Sprintf("(SKILL.md too long to compare: %d and %d lines)\n", len(al), len(bl))
	}
	n, m := len(al), len(bl)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if al[i] == bl[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var sb strings.Builder
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && al[i] == bl[j]:
			i, j = i+1, j+1
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			sb.WriteString("-" + cleanLine(al[i]) + "\n")
			i++
		default:
			sb.WriteString("+" + cleanLine(bl[j]) + "\n")
			j++
		}
	}
	return sb.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(strings.ReplaceAll(s, "\r\n", "\n"), "\n"), "\n")
}

// swapDir puts the prepared folder tmp in place of dst (named name, in
// skills). An existing dst, checked to be ours by the caller, goes aside
// into a fresh folder of unpredictable name, removed only after success, and
// is put back when the rename fails.
func swapDir(skills, tmp, dst, name string) error {
	if _, err := os.Lstat(dst); err == nil {
		// Ours (checked above): the previous version goes aside into a
		// fresh folder of unpredictable name, removed only after success.
		aside, err := os.MkdirTemp(skills, ".michel-old-")
		if err != nil {
			return fmt.Errorf("cannot replace the installed skill: %w", err)
		}
		old := filepath.Join(aside, name)
		if err := os.Rename(dst, old); err != nil {
			os.Remove(aside)
			return fmt.Errorf("cannot replace the installed skill: %w", err)
		}
		if err := os.Rename(tmp, dst); err != nil {
			if rerr := os.Rename(old, dst); rerr != nil {
				return fmt.Errorf("cannot install the skill (%v), and the previous version could not be put back: it is in %s", err, old)
			}
			os.Remove(aside)
			return fmt.Errorf("cannot install the skill: %w", err)
		}
		os.RemoveAll(aside)
	} else if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("cannot install the skill: %w", err)
	}
	return nil
}
