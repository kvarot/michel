package serverlog

import (
	"fmt"
	"strings"
)

// maxPathLen bounds a declared path.
const maxPathLen = 1024

// ValidatePath checks a log source path: absolute, a file (not a folder), no
// "..", no control character, a wildcard only in the last segment. It accepts
// nothing the filter script would refuse: the characters are the plain class of
// Script, so a path that passes here is one Script builds. The errors never
// repeat the path.
func ValidatePath(p string) error {
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrInvalidPath, why) }
	switch {
	case p == "":
		return bad("the path is empty")
	case len(p) > maxPathLen:
		return bad("the path is too long")
	case !strings.HasPrefix(p, "/"):
		return bad("give an absolute path, starting with /")
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f {
			return bad("the path holds a control character")
		}
	}
	if strings.Contains(p, "..") {
		return bad("\"..\" is not allowed")
	}
	if err := checkSourcePath(p); err != nil {
		return bad("plain characters only, and a wildcard only in the last segment")
	}
	if last := p[strings.LastIndex(p, "/")+1:]; last == "" || last == "." {
		return bad("give a file, not a folder")
	}
	return nil
}
