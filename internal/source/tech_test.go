package source

import (
	"reflect"
	"testing"
)

func TestTechAutoFromRulesAndEcosystem(t *testing.T) {
	_, rules, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ecos     []string
		packages map[string][]string
		want     []string
	}{
		{[]string{"Packagist"}, map[string][]string{"Packagist": {"symfony/console", "acme/lib"}}, []string{"php", "symfony"}},
		{[]string{"npm"}, map[string][]string{"npm": {"next", "react", "react-dom", "vue-router"}}, []string{"nextjs", "node", "react"}},
		// A package of another ecosystem never matches.
		{[]string{"npm"}, map[string][]string{"npm": {"laravel/framework"}}, []string{"node"}},
		{[]string{"Packagist", "npm"}, map[string][]string{"Packagist": {"drupal/core"}, "npm": {"@angular/core"}}, []string{"angular", "drupal", "node", "php"}},
		{nil, nil, []string{}},
		// An ecosystem seen only through its packages still counts.
		{nil, map[string][]string{"Packagist": {"laravel/framework"}}, []string{"laravel", "php"}},
	}
	for _, c := range cases {
		if got := TechAuto(rules, c.ecos, c.packages); !reflect.DeepEqual(got, c.want) {
			t.Errorf("TechAuto(%v, %v) = %v, want %v", c.ecos, c.packages, got, c.want)
		}
	}
	custom := []TechRule{{Ecosystem: "PyPI", Prefix: "django", Tag: "django"}}
	if got := TechAuto(custom, []string{"PyPI"}, map[string][]string{"PyPI": {"djangorestframework"}}); !reflect.DeepEqual(got, []string{"django"}) {
		t.Errorf("prefix rule = %v", got)
	}
}
