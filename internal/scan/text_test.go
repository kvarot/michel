package scan

import "testing"

func TestSanitizeTextStripsTerminalControls(t *testing.T) {
	cases := map[string]string{
		"title\x1b]0;x\x07 end":   "title]0;x end",
		"\x1b[2Kerased":           "[2Kerased",
		"keep\nnew\tline":         "keep\nnew\tline",
		"c1\u009b31m and del\x7f": "c131m and del",
		"plain café":              "plain café",
		"bad \xff byte":           "bad � byte",
		"cr\r":                    "cr",
	}
	for in, want := range cases {
		if got := SanitizeText(in); got != want {
			t.Errorf("SanitizeText(%q) = %q, want %q", in, got, want)
		}
	}
	if SanitizeAll(nil) != nil {
		t.Error("SanitizeAll(nil) must stay nil")
	}
}
