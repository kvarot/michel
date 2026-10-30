package gitrepo

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/scan"
)

// Discovery is a repository found by topic, "to discover". State is new,
// ignored or added.
type Discovery struct {
	Repo        string `json:"repo"`
	Topic       string `json:"topic"`
	Stars       int    `json:"stars"`
	Description string `json:"description"`
	HTMLURL     string `json:"html_url"`
	FirstSeenAt string `json:"first_seen_at"`
	State       string `json:"state"`
}

// Discovery states.
const (
	StateNew     = "new"
	StateIgnored = "ignored"
	StateAdded   = "added"
)

// topicPattern is a GitHub topic.
var topicPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,49}$`)

// maxDescription bounds a stored description, in characters.
const maxDescription = 300

// Discover searches the repositories of each topic, most starred first,
// 20 per topic: one request each, taken from budget (ErrBudget when it is
// spent, with what was found before). A topic that is not a GitHub topic
// is skipped. The request carries only the topic.
func Discover(ctx context.Context, client *http.Client, token string, topics []string, budget Budget) ([]Discovery, error) {
	out := []Discovery{}
	seen := map[string]bool{}
	for _, t := range topics {
		if !topicPattern.MatchString(t) {
			continue
		}
		if !take(budget, 1) {
			return out, ErrBudget
		}
		q := url.Values{"q": {"topic:" + t}, "sort": {"stars"}, "per_page": {"20"}}
		var res struct {
			Items []struct {
				FullName    string `json:"full_name"`
				Stars       int    `json:"stargazers_count"`
				Description string `json:"description"`
				HTMLURL     string `json:"html_url"`
			} `json:"items"`
		}
		if _, err := getJSON(ctx, client, apiBase+"/search/repositories?"+q.Encode(), token, &res); err != nil {
			return out, fmt.Errorf("GitHub search of topic %s: %w", t, err)
		}
		for _, it := range res.Items {
			if _, _, err := SplitRepo(it.FullName); err != nil {
				continue
			}
			key := strings.ToLower(it.FullName)
			if seen[key] {
				continue
			}
			seen[key] = true
			d := Discovery{Repo: it.FullName, Topic: t, Stars: it.Stars, Description: cleanDescription(it.Description), State: StateNew}
			if u := "https://github.com/" + it.FullName; strings.EqualFold(it.HTMLURL, u) {
				d.HTMLURL = u
			}
			out = append(out, d)
		}
	}
	return out, nil
}

// cleanDescription is a description on one line, without control
// characters, bounded.
func cleanDescription(s string) string {
	s = strings.Join(strings.Fields(scan.SanitizeText(s)), " ")
	if utf8.RuneCountInString(s) > maxDescription {
		s = string([]rune(s)[:maxDescription-1]) + "…"
	}
	return s
}
