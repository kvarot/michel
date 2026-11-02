package serverrules

import "testing"

// An open_basedir entry that cleans to "/", or one that is empty, relative
// or holds dot segments, restricts nothing for sure: risky (fail closed).
func TestOpenBasedirPathCleaning(t *testing.T) {
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
		"//": true, "/./": true, "/tmp/..": true, " / ": true, "/var/www: / ": true, "///": true,
		"/var/www:": true, "::": true, ":/var/www": true, "var/www": true, "./": true, ".": true,
		"/var/www/../..": true, "/var/./www": true, "/var/www/.": true,
		"/var/www:/tmp": false, "/var/www/demo/": false, "/var/www//demo": false, " /var/www ": false,
		"/var/www/..demo": false, "/var/www/.cache": false,
	} {
		if got := RiskyValue(r, v); got != want {
			t.Errorf("RiskyValue(open_basedir, %q) = %v, want %v", v, got, want)
		}
	}
}
