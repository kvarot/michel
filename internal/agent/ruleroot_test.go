package agent

import (
	"runtime"
	"testing"
)

func TestRuleRoot(t *testing.T) {
	type tc struct {
		dir, want string
		ok        bool
	}
	cases := []tc{{"relative/data", "", false}}
	if runtime.GOOS == "windows" {
		cases = append(cases,
			tc{`C:\Work\michel`, "//c/Work/michel", true},
			tc{`\\?\E:\srv\michel`, "//e/srv/michel", true},
			tc{`\\server\share\michel`, "", false},
			tc{`\\?\UNC\server\share\michel`, "", false})
	} else {
		cases = append(cases, tc{"/home/demo/michel", "//home/demo/michel", true})
	}
	for _, c := range cases {
		got, err := ruleRoot(c.dir)
		if got != c.want || (err == nil) != c.ok {
			t.Errorf("ruleRoot(%q) = %q, %v; want %q, ok %t", c.dir, got, err, c.want, c.ok)
		}
	}
}

// A data folder the rules cannot name refuses the session instead of
// leaving Michel's data readable.
func TestSettingsRefuseAnUnnamableDataFolder(t *testing.T) {
	dir := "relative/data/worktrees/01PROJ/01ATTEMPT"
	if runtime.GOOS == "windows" {
		dir = `\\server\share\data\worktrees\01PROJ\01ATTEMPT`
	}
	if _, _, err := generated(Spec{Dir: dir}); err == nil {
		t.Error("generated named no data folder and did not fail")
	}
	if _, err := argv(Spec{Dir: dir}, "m", "s"); err == nil {
		t.Error("argv named no data folder and did not fail")
	}
}
