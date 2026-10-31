package serverrules

import "testing"

// A quoted value followed by an inline comment: PHP drops the comment
// outside the quotes, then the quotes.
func TestIsOnQuotedValueWithComment(t *testing.T) {
	for v, want := range map[string]bool{
		`"1" ; c`: true, `"On" ; dev`: true, `'yes' ;x`: true, `"1"`: true,
		`"0" ; 1`: false, `"0;1"`: false, `"off"`: false, `"" ; 1`: false,
	} {
		if got := isOn(v); got != want {
			t.Errorf("isOn(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestOpenBasedirRootIsRisky(t *testing.T) {
	set, err := Rules()
	if err != nil {
		t.Fatal(err)
	}
	var r ConfigRule
	for _, x := range set.Config {
		if x.Directive == "open_basedir" {
			r = x
		}
	}
	for v, want := range map[string]bool{
		"": true, `""`: true, `"" ; x`: true, "/": true, "/var/www:/": true, "/:/tmp": true, `"/"`: true,
		"/var/www:/tmp": false, "/var/www/demo/": false,
	} {
		if got := RiskyValue(r, v); got != want {
			t.Errorf("RiskyValue(open_basedir, %q) = %v, want %v", v, got, want)
		}
	}
}
