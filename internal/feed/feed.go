// Package feed reads the "to read" sources (kind feed): RSS and Atom feeds,
// the security advisories of a GitHub repository and watched pages. Every
// read is bounded (MaxFeedBytes, MaxItemsPerRead), its text is stripped of
// HTML and control characters, and its items are stored in feed_item,
// deduplicated by (source, guid) and purged after Retention. An item is "to
// read" when its technologies or its title meet a declared technology
// (MatchTech). A feed never creates a finding: the installed version is not
// known.
package feed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

// Bounds of one read.
const (
	MaxFeedBytes    int64 = 5 << 20
	MaxItemsPerRead       = 200
	// MaxSummary is the longest summary kept, in characters.
	MaxSummary = 500
	// Retention is how long an item is kept; older items are purged at the
	// next read of their source, and not stored at all when published
	// before it.
	Retention = 180 * 24 * time.Hour
)

// Bounds of the other fields, in characters (bytes for the URL).
const (
	maxTitle = 300
	maxGUID  = 300
	maxURL   = 2048
)

// PageChangedTitle is the stored title of a watched page's change; it is
// shown translated (Title).
const PageChangedTitle = "page changed"

// pageGUIDPrefix starts the guid of a watched page's change.
const pageGUIDPrefix = "page:"

var (
	// ErrNotModified: the source answered that nothing changed since the
	// last read (304).
	ErrNotModified = errors.New("not modified since the last read")
	// ErrRateLimited: the source refused more requests for now (403, 429).
	ErrRateLimited = errors.New("the source asked to slow down")
	// ErrRateBudget: the GitHub request budget of this update is spent; no
	// request was made.
	ErrRateBudget = errors.New("the GitHub request budget is spent")
	// ErrTooLarge: the answer is bigger than MaxFeedBytes; nothing is stored.
	ErrTooLarge = fmt.Errorf("the answer is too large: Michel reads at most %d bytes", MaxFeedBytes)
)

// Item is one entry of a feed. Dates are RFC 3339 UTC ("" when unknown).
// SourceKey and SourceName are filled when listing.
type Item struct {
	ID          string   `json:"id"`
	SourceID    string   `json:"source_id"`
	SourceKey   string   `json:"source_key,omitempty"`
	SourceName  string   `json:"source,omitempty"`
	GUID        string   `json:"guid"`
	Title       string   `json:"title"`
	URL         string   `json:"url"`
	PublishedAt string   `json:"published_at"`
	Summary     string   `json:"summary"`
	Tech        []string `json:"tech"`
	SeenAt      string   `json:"seen_at"`
	ReadAt      string   `json:"read_at"`
}

// IsPageChange reports whether it is the change of a watched page.
func (it Item) IsPageChange() bool { return strings.HasPrefix(it.GUID, pageGUIDPrefix) }

// Title is the item's title as shown in lang: a page change is translated.
func Title(lang i18n.Lang, it Item) string {
	if it.IsPageChange() {
		return i18n.T(lang, "feed.page_changed")
	}
	return it.Title
}

// Reader turns a body into items, already cleaned (StripHTML, caps), in the
// order of the source, at most MaxItemsPerRead. The source and dates of
// reading are filled by ReadEntry.
type Reader interface {
	Parse(body []byte, e source.Entry) ([]Item, error)
}

// readers maps a format to its reader; "auto" is decided by Detect.
var readers = map[string]Reader{"rss": RSS{}, "atom": Atom{}, "github_advisories": GitHubAdvisories{}, "page": Page{}}

// Deps are what a read needs. Client must come from egress.Gateway.Client
// (purpose source.feed).
type Deps struct {
	Store   *store.Store
	Client  *http.Client
	Secrets secret.Store
	Now     func() time.Time
	// TakeGitHub spends one request of the GitHub budget and reports
	// whether it was available; nil means no budget.
	TakeGitHub func() bool
}

// ReadEntry reads e once and stores its new items. The request carries
// If-None-Match (or If-Modified-Since) from e.LastReadETag; a 304 is
// ErrNotModified. Format auto lets Detect choose rss or atom, else the
// body is a watched page. An item's Tech is the entry's tags plus the
// declared tags its title names (MatchTech). Items of e older than Retention
// are purged. It returns the number of new items and the validator to keep
// ("" when the server gave none).
func ReadEntry(ctx context.Context, deps Deps, e source.Entry, declared []string) (items int, etag string, err error) {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	format := strings.ToLower(strings.TrimSpace(e.Config.Str("format")))
	var body []byte
	switch format {
	case "github_advisories":
		body, etag, err = fetchGitHub(ctx, deps, e)
	case "", "auto", "rss", "atom", "page":
		var ct string
		body, ct, etag, err = fetch(ctx, deps.Client, e.URL, e.LastReadETag, nil, true)
		if err == nil && (format == "" || format == "auto") {
			format = Detect(ct, body)
			if format == "" {
				format = "page"
			}
		}
	default:
		return 0, "", fmt.Errorf("source %s has an unknown feed format %q (use auto, rss, atom, page or github_advisories)", e.Key, format)
	}
	if err != nil {
		return 0, "", err
	}
	parsed, err := readers[format].Parse(body, e)
	if err != nil {
		return 0, "", fmt.Errorf("cannot read the %s feed of %s: %w", format, e.Key, err)
	}
	now := deps.Now().UTC().Truncate(time.Second)
	stamp := now.Format(time.RFC3339)
	cutoff := now.Add(-Retention).Format(time.RFC3339)
	kept := parsed[:0]
	for _, it := range parsed {
		if it.IsPageChange() && it.PublishedAt == "" {
			it.PublishedAt = stamp
		}
		if it.PublishedAt != "" && it.PublishedAt < cutoff {
			continue
		}
		matched, _ := MatchTech(it.Title, nil, declared)
		tech, err := project.NormalizeTech(append(append([]string{}, e.Tech...), matched...))
		if err != nil {
			tech = append([]string{}, e.Tech...)
		}
		it.SourceID, it.Tech, it.SeenAt, it.ReadAt = e.ID, tech, stamp, ""
		kept = append(kept, it)
	}
	r := NewRepo(deps.Store)
	n, err := r.store(ctx, e.ID, kept, cutoff)
	if err != nil {
		return 0, "", err
	}
	return n, etag, nil
}

// lastModifiedPrefix marks a stored validator that is a Last-Modified date
// rather than an ETag.
const lastModifiedPrefix = "last-modified:"

// fetch GETs rawURL with the conditional header of validator and returns
// the body (at most MaxFeedBytes), its content type and the new validator.
// follow says whether redirects are followed (never with credentials).
func fetch(ctx context.Context, client *http.Client, rawURL, validator string, headers map[string]string, follow bool) (body []byte, contentType, newValidator string, err error) {
	if client == nil {
		return nil, "", "", errors.New("no HTTP client: build it with the egress gateway")
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, "", "", fmt.Errorf("the address %q is not an http(s) address", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", "", errors.New("cannot build the request")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if lm, ok := strings.CutPrefix(validator, lastModifiedPrefix); ok {
		req.Header.Set("If-Modified-Since", lm)
	} else if validator != "" {
		req.Header.Set("If-None-Match", validator)
	}
	c := *client // the caller's client is copied, not changed
	if !follow {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL wrapper: it may carry a query
		}
		return nil, "", "", fmt.Errorf("the request failed: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return nil, "", "", ErrNotModified
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
		return nil, "", "", ErrRateLimited
	case resp.StatusCode != http.StatusOK:
		return nil, "", "", fmt.Errorf("the server answered %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	case resp.ContentLength > MaxFeedBytes:
		return nil, "", "", ErrTooLarge
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, MaxFeedBytes+1))
	if err != nil {
		return nil, "", "", fmt.Errorf("cannot read the answer: %w", err)
	}
	if int64(len(body)) > MaxFeedBytes {
		return nil, "", "", ErrTooLarge
	}
	newValidator = resp.Header.Get("ETag")
	if newValidator == "" {
		if lm := resp.Header.Get("Last-Modified"); lm != "" {
			newValidator = lastModifiedPrefix + lm
		}
	}
	if len(newValidator) > 256 {
		newValidator = ""
	}
	return body, resp.Header.Get("Content-Type"), scan.SanitizeText(newValidator), nil
}

// StripHTML turns untrusted HTML or text into one line of plain text: tags,
// comments, scripts and styles removed, entities decoded, white space
// reduced, then scan.SanitizeText (no control character).
func StripHTML(s string) string {
	var b strings.Builder
	lower := strings.ToLower(s)
	for i := 0; i < len(s); {
		if s[i] != '<' {
			j := strings.IndexByte(s[i:], '<')
			if j < 0 {
				j = len(s) - i
			}
			b.WriteString(s[i : i+j])
			i += j
			continue
		}
		rest := lower[i:]
		switch {
		case strings.HasPrefix(rest, "<!--"):
			end := strings.Index(rest[4:], "-->")
			if end < 0 {
				i = len(s)
			} else {
				i += 4 + end + 3
			}
		case strings.HasPrefix(rest, "<script"), strings.HasPrefix(rest, "<style"):
			name := "</script"
			if strings.HasPrefix(rest, "<style") {
				name = "</style"
			}
			end := strings.Index(rest, name)
			if end < 0 {
				i = len(s)
				break
			}
			gt := strings.IndexByte(rest[end:], '>')
			if gt < 0 {
				i = len(s)
			} else {
				i += end + gt + 1
			}
		case len(rest) > 1 && (isASCIILetter(rest[1]) || rest[1] == '/' || rest[1] == '!' || rest[1] == '?'):
			gt := strings.IndexByte(rest, '>')
			if gt < 0 {
				i = len(s)
			} else {
				i += gt + 1
			}
			if !inlineTag(rest) {
				b.WriteByte(' ')
			}
		default:
			b.WriteByte('<')
			i++
		}
	}
	text := html.UnescapeString(b.String())
	return strings.Join(strings.Fields(scan.SanitizeText(text)), " ")
}

func isASCIILetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// inlineTags do not separate words: removing them leaves no space.
var inlineTags = map[string]bool{"a": true, "abbr": true, "b": true, "code": true, "em": true, "i": true, "kbd": true,
	"mark": true, "q": true, "s": true, "samp": true, "small": true, "span": true, "strong": true, "sub": true, "sup": true,
	"time": true, "u": true, "var": true}

// inlineTag reports whether tag (lowercase, starting with "<") opens or
// closes an inline element.
func inlineTag(tag string) bool {
	name := strings.TrimPrefix(tag[1:], "/")
	end := strings.IndexFunc(name, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') })
	if end >= 0 {
		name = name[:end]
	}
	return inlineTags[name]
}

// truncate keeps at most n characters of s, the last one an ellipsis when
// it cut.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// cleanText is untrusted text as stored: StripHTML, then at most n
// characters.
func cleanText(s string, n int) string { return truncate(StripHTML(s), n) }

// cleanURL resolves raw against base and keeps it when it is an absolute
// http(s) address of at most maxURL bytes; else "".
func cleanURL(raw, base string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if !u.IsAbs() && base != "" {
		b, err := url.Parse(base)
		if err != nil {
			return ""
		}
		u = b.ResolveReference(u)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return ""
	}
	s := u.String()
	if len(s) > maxURL || s != scan.SanitizeText(s) {
		return ""
	}
	return s
}

// cleanGUID keeps a short guid as read (without control characters), and
// replaces a long one by its hash.
func cleanGUID(g string) string {
	g = strings.TrimSpace(scan.SanitizeText(g))
	if utf8.RuneCountInString(g) > maxGUID {
		return "sha256:" + hashText(g)
	}
	return g
}

// hashText is the hex SHA-256 of s.
func hashText(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// fallbackGUID is the guid of an item without id: its link, else a hash of
// its title.
func fallbackGUID(link, title string) string {
	if link != "" {
		return cleanGUID(link)
	}
	return "title:" + hashText(title)
}

// dateLayouts are the date formats met in feeds.
var dateLayouts = []string{
	time.RFC3339, time.RFC3339Nano, time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822,
	"Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST", "2 Jan 2006 15:04:05 -0700",
	"Mon, 02 Jan 2006 15:04 -0700", "2006-01-02T15:04:05", "2006-01-02",
}

// parseDate reads a feed date into RFC 3339 UTC, "" when unknown.
func parseDate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, l := range dateLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return ""
}
