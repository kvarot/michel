package gitrepo

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/source"
	"gopkg.in/yaml.v3"
)

// Bounds of the preview text.
const (
	headLines     = 40
	maxHeadRunes  = 300
	maxFrontBytes = 16 << 10
)

// target is what an entry points at: the repository, its folder and the
// commit, all checked.
type target struct {
	owner, name, sub, sha string
}

func targetOf(e source.Entry, sha string) (target, error) {
	if e.Kind != source.KindSkill && e.Kind != source.KindMCP {
		return target{}, fmt.Errorf("%w: %s is a %s", ErrWrongKind, e.Key, e.Kind)
	}
	owner, name, err := SplitRepo(e.Config.Str("repo"))
	if err != nil {
		return target{}, err
	}
	sub, err := cleanSub(e.Config.Str("path"))
	if err != nil {
		return target{}, err
	}
	if !ValidSHA(sha) {
		return target{}, fmt.Errorf("%w: %q", ErrBadSHA, clip(sha))
	}
	return target{owner: owner, name: name, sub: sub, sha: sha}, nil
}

// fetch downloads (or finds) the archive of t and returns the folder of the
// entry's files inside it, and the root of the archive.
func (t target) fetch(ctx context.Context, d Deps, key string) (folder, root string, err error) {
	root, err = fetchPath(ctx, d.Client, d.DataDir, key, t.owner, t.name, t.sha, t.sub)
	if err != nil {
		return "", "", err
	}
	folder = filepath.Join(root, filepath.FromSlash(t.sub))
	if fi, err := os.Stat(folder); err != nil || !fi.IsDir() {
		return "", "", fmt.Errorf("%w: %q", ErrNoFolder, t.sub)
	}
	return folder, root, nil
}

// listFiles lists the regular files under dir, paths relative to it in
// slash form, sorted.
func listFiles(dir string) ([]FileInfo, error) {
	var out []FileInfo
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		out = append(out, FileInfo{Path: filepath.ToSlash(rel), Size: fi.Size()})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, err
}

// cleanLine is a line of untrusted text fit for a terminal: no control
// characters, bounded.
func cleanLine(s string) string {
	s = strings.TrimRight(scan.SanitizeText(strings.TrimRight(s, "\r")), " \t")
	if utf8.RuneCountInString(s) > maxHeadRunes {
		s = string([]rune(s)[:maxHeadRunes-1]) + "…"
	}
	return s
}

// headOf returns the first lines of SKILL.md or README.md in folder, else
// of README.md at the root of the archive.
func headOf(folder, root string) []string {
	for _, p := range []string{filepath.Join(folder, "SKILL.md"), filepath.Join(folder, "README.md"), filepath.Join(root, "README.md")} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		var out []string
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for len(out) < headLines && sc.Scan() {
			out = append(out, cleanLine(sc.Text()))
		}
		f.Close()
		return out
	}
	return []string{}
}

// skillNameOf is the folder name of a skill: the name of SKILL.md's front
// matter, else the folder's own name, else the repository's. A name that is
// not a single plain segment is refused with ErrBadName.
func skillNameOf(folder string, t target) (string, error) {
	name := ""
	if b, err := os.ReadFile(filepath.Join(folder, "SKILL.md")); err == nil {
		name = frontMatterName(b)
	}
	if name == "" {
		name = t.name
		if t.sub != "" {
			name = t.sub[strings.LastIndex(t.sub, "/")+1:]
		}
	}
	if !validSkillName(name) {
		return "", fmt.Errorf("%w: %q", ErrBadName, clip(scan.SanitizeText(name)))
	}
	return name, nil
}

// frontMatterName reads "name" from the YAML front matter of a SKILL.md
// ("" when there is none or it cannot be read).
func frontMatterName(b []byte) string {
	b = bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf})
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	rest, ok := bytes.CutPrefix(b, []byte("---\n"))
	if !ok {
		return ""
	}
	end := bytes.Index(rest, []byte("\n---"))
	if end < 0 || end > maxFrontBytes {
		return ""
	}
	var fm struct {
		Name string `yaml:"name"`
	}
	if err := yaml.Unmarshal(rest[:end], &fm); err != nil {
		return ""
	}
	return strings.TrimSpace(fm.Name)
}

// launchOf builds the "claude mcp add" line of an MCP entry from its launch
// setting {command, args}; "" when the command is not known. downloads
// tells that the command fetches code when it starts.
func launchOf(e source.Entry) (line string, downloads bool) {
	l, ok := e.Config.Merged()["launch"].(map[string]any)
	if !ok {
		return "", false
	}
	cmd, _ := l["command"].(string)
	cmd = scan.SanitizeText(strings.TrimSpace(cmd))
	if cmd == "" {
		return "", false
	}
	parts := []string{"claude", "mcp", "add", "--scope", "user", strings.TrimPrefix(e.Key, "mcp."), "--", quoteArg(cmd)}
	var args []string
	switch a := l["args"].(type) {
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok {
				args = append(args, s)
			}
		}
	case []string:
		args = a
	}
	for _, a := range args {
		parts = append(parts, quoteArg(scan.SanitizeText(a)))
	}
	switch strings.ToLower(filepath.Base(cmd)) {
	case "npx", "uvx", "pipx", "bunx", "docker", "podman", "uv", "pnpm", "yarn":
		downloads = true
	}
	return strings.Join(parts, " "), downloads
}

// quoteArg quotes an argument holding spaces or quotes, for display.
func quoteArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t'\"\\$`") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// trustOf reads the trust note from the entry's last status.
func trustOf(e source.Entry) Trust {
	t := Trust{InCatalog: e.Origin == source.OriginCatalog}
	switch v := e.Status["stars"].(type) {
	case float64:
		t.Stars = int(v)
	case int:
		t.Stars = v
	}
	t.PushedAt, _ = e.Status["pushed_at"].(string)
	t.PushedAt = scan.SanitizeText(t.PushedAt)
	if a, ok := e.Status["archived"].(bool); ok {
		t.Archived = "no"
		if a {
			t.Archived = "yes"
		}
	}
	return t
}

// PreviewInstall downloads (or finds) the archive of sha and tells what an
// installation of e would bring and do. Nothing is written outside the data
// folder.
func PreviewInstall(ctx context.Context, d Deps, e source.Entry, sha string) (Preview, error) {
	t, err := targetOf(e, sha)
	if err != nil {
		return Preview{}, err
	}
	folder, root, err := t.fetch(ctx, d, e.Key)
	if err != nil {
		return Preview{}, err
	}
	files, err := listFiles(folder)
	if err != nil {
		return Preview{}, fmt.Errorf("cannot list the files of the archive: %w", err)
	}
	lic := DetectLicense(folder)
	if lic.SPDX == "unknown" && folder != root {
		lic = DetectLicense(root)
	}
	p := Preview{Key: e.Key, Repo: t.owner + "/" + t.name, SHA: sha, Files: files, License: lic,
		Declared: scan.SanitizeText(e.Config.Str("license")), Head: headOf(folder, root), Trust: trustOf(e)}
	if e.Kind == source.KindSkill {
		name, err := skillNameOf(folder, t)
		if err != nil {
			return Preview{}, err
		}
		if d.SkillsDir == "" {
			return Preview{}, fmt.Errorf("no skills folder")
		}
		skills, err := filepath.Abs(d.SkillsDir)
		if err != nil {
			return Preview{}, fmt.Errorf("cannot resolve the skills folder: %w", err)
		}
		p.WillWrite = filepath.Join(skills, name)
		// Install replaces the installed folder when the pinned version
		// has another name: shown before consent like an upgrade.
		p.OldDir = previousDir(e, p.WillWrite)
	} else {
		p.Launch, p.Downloads = launchOf(e)
	}
	return p, nil
}
