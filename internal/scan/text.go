package scan

import "strings"

// SanitizeText removes the control characters of untrusted text (advisories,
// package names, changelogs, file names) before it is stored or printed, so
// it cannot drive the user's terminal: C0 controls except newline and tab,
// DEL and C1 controls (U+0080 to U+009F). Invalid UTF-8 becomes U+FFFD.
func SanitizeText(s string) string {
	clean := true
	for _, r := range s {
		if isControl(r) || r == '�' {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isControl(r) {
			return -1
		}
		return r
	}, s)
}

// SanitizeAll applies SanitizeText to every element, in a new slice.
func SanitizeAll(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = SanitizeText(s)
	}
	return out
}

func isControl(r rune) bool {
	if r == '\n' || r == '\t' {
		return false
	}
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}
