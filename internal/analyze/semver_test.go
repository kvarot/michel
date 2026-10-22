package analyze

import (
	"testing"

	"deps.dev/util/semver"
)

func TestPlanUpgrade(t *testing.T) {
	yes, no := true, false
	tests := []struct {
		name      string
		eco       string
		installed string
		fixed     []string
		cons      string
		target    string
		jump      Jump
		allows    *bool
	}{
		{"composer caret patch", "Packagist", "v7.4.0", []string{"7.4.5", "8.0.0"}, "^7.4", "7.4.5", "patch", &yes},
		{"npm tilde patch", "npm", "2.0.7", []string{"2.0.9"}, "~2.0.0", "2.0.9", "patch", &yes},
		{"npm caret major", "npm", "1.2.0", []string{"2.0.0"}, "^1.2.0", "2.0.0", "major", &no},
		{"composer tilde 1.2 allows minor", "Packagist", "1.2.0", []string{"1.5.0"}, "~1.2", "1.5.0", "minor", &yes},
		{"npm tilde 1.2 blocks minor", "npm", "1.2.0", []string{"1.5.0"}, "~1.2", "1.5.0", "minor", &no},
		{"unparsable installed", "Packagist", "dev-master", []string{"1.0.1"}, "*", "1.0.1", "unknown", nil},
		{"no fixed", "npm", "1.0.0", []string{}, "^1", "", "none", nil},
		{"skip lower and prerelease", "npm", "1.0.0", []string{"0.9.0", "1.0.0-beta.1", "1.0.1"}, "", "1.0.1", "patch", nil},
		{"unparsable constraint", "npm", "1.0.0", []string{"1.0.1"}, "not a range ???", "1.0.1", "patch", nil},
		{"unparsable fixed ignored", "npm", "1.0.0", []string{"garbage", "1.1.0"}, "", "1.1.0", "minor", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PlanUpgrade(tt.eco, tt.installed, tt.fixed, tt.cons)
			if got.Target != tt.target || got.Jump != tt.jump {
				t.Fatalf("got target=%q jump=%q, want %q %q", got.Target, got.Jump, tt.target, tt.jump)
			}
			if (got.ConstraintAllows == nil) != (tt.allows == nil) ||
				(got.ConstraintAllows != nil && *got.ConstraintAllows != *tt.allows) {
				t.Fatalf("ConstraintAllows = %v, want %v", got.ConstraintAllows, tt.allows)
			}
		})
	}
}

func TestPlanUpgradeUnsupportedEcosystem(t *testing.T) {
	got := PlanUpgrade("PyPI", "1.0.0", []string{"1.0.1"}, "")
	if got.Target != "" || got.Jump != JumpNone {
		t.Fatalf("got %+v", got)
	}
}

func TestNormalizeVersion(t *testing.T) {
	tests := []struct{ eco, in, want string }{
		{"npm", "v1.2.3", "1.2.3"},
		{"Packagist", " 1.2.3 ", "1.2.3"},
		{"Packagist", "V2.0.0", "2.0.0"},
		{"Packagist", "dev-main", ""},
		{"npm", "", ""},
	}
	for _, tt := range tests {
		if got := NormalizeVersion(tt.eco, tt.in); got != tt.want {
			t.Errorf("NormalizeVersion(%q,%q) = %q, want %q", tt.eco, tt.in, got, tt.want)
		}
	}
}

func TestComposerConstraints(t *testing.T) {
	tests := []struct {
		cons, ver string
		want      bool
		valid     bool
	}{
		{"^1.2.3", "1.9.0", true, true},
		{"^1.2.3", "2.0.0", false, true},
		{"^0.3", "0.3.9", true, true},
		{"^0.3", "0.4.0", false, true},
		{"~1.2.3", "1.2.9", true, true},
		{"~1.2.3", "1.3.0", false, true},
		{">=1.0 <2.0", "1.5.0", true, true},
		{">=1.0, <1.5", "1.5.0", false, true},
		{"^1.0 || ^2.0", "2.3.0", true, true},
		{"1.* ", "1.7.0", true, true},
		{"1.2 - 1.4", "1.3.0", true, true},
		{"*", "9.9.9", true, true},
		{"dev-master", "1.0.0", false, false},
	}
	for _, tt := range tests {
		v, _ := semver.Composer.Parse(tt.ver)
		got, ok := composerAllows(tt.cons, v)
		if ok != tt.valid || (ok && got != tt.want) {
			t.Errorf("composerAllows(%q,%q) = %v,%v want %v,%v", tt.cons, tt.ver, got, ok, tt.want, tt.valid)
		}
	}
}
