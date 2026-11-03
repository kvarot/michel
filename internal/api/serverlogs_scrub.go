package api

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// posteRoots are the folders of this computer that a text coming from a server
// must never carry: the user's home, the temporary and working folders, the
// configuration and cache folders, and the extra folders Michel knows (the data
// folder). Each is written in the forms a path can take here (native, with
// slashes, and the /c/... form of a POSIX shell on Windows). A server path
// below one of them is a path of this computer that got into the text, or the
// same path by chance: either way it does not go out.
func posteRoots(extra ...string) []string {
	var dirs []string
	add := func(d string, err error) {
		if err == nil {
			dirs = append(dirs, d)
		}
	}
	add(os.UserHomeDir())
	add(os.TempDir(), nil)
	add(os.Getwd())
	add(os.UserConfigDir())
	add(os.UserCacheDir())
	dirs = append(dirs, extra...)
	seen := map[string]bool{}
	var out []string
	put := func(r string) {
		r = strings.TrimRight(r, `/\`)
		// Not the root of a disk, not a name too short to be a folder.
		if len(r) < 3 || r == "" || seen[r] {
			return
		}
		seen[r] = true
		out = append(out, r)
	}
	for _, d := range dirs {
		if d == "" || !(filepath.IsAbs(d) || strings.HasPrefix(d, "/")) {
			continue
		}
		put(d)
		slash := filepath.ToSlash(d)
		put(slash)
		// The form a POSIX shell gives a Windows path: /c/work/...
		if len(slash) > 2 && slash[1] == ':' {
			put("/" + strings.ToLower(slash[:1]) + slash[2:])
		}
	}
	// The longest first, so that a folder inside another is cut whole.
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

func isPathByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("._+-", c) >= 0
}

// scrubPoste replaces by <path> every path of s that starts with one of roots:
// the root, then what follows up to a space, a quote or an angle bracket. A root
// only counts as a whole name: /tmp does not match /tmpfs, nor a longer name
// that merely ends with it.
func scrubPoste(s string, roots []string) string {
	for _, root := range roots {
		for from := 0; ; {
			i := strings.Index(s[from:], root)
			if i < 0 {
				break
			}
			i += from
			end := i + len(root)
			before := i == 0 || !isPathByte(s[i-1])
			after := end == len(s) || s[end] == '/' || s[end] == '\\' || !isPathByte(s[end])
			if !before || !after {
				from = end
				continue
			}
			j := end
			for j < len(s) && strings.IndexByte(" \t\"'<>", s[j]) < 0 {
				j++
			}
			s = s[:i] + "<path>" + s[j:]
			from = i + len("<path>")
		}
	}
	return s
}

// ServerText makes a text read on a server safe to show: control characters
// removed, a path of this computer replaced, the SSH user's home written ~. The
// page and the command line use the same one.
func ServerText(user, s string) string { return scrubPoste(srvText(user, s), posteRoots()) }

// logText is ServerText with the folders this handler knows besides.
func (s *server) logText(user, v string) string {
	return scrubPoste(srvText(user, v), posteRoots(s.deps.Servers.Home, s.deps.Sources.DataDir))
}
