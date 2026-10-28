package feed

import "github.com/kvarot/michel/internal/source"

// Page watches a human page: the hash of its text (StripHTML: tags, scripts
// and styles removed, white space reduced) is the guid of one "page
// changed" item linking to the page. Nothing of the page is kept: a new
// hash is a new item, the same hash is the same item.
type Page struct{}

// Parse returns the page's one item, none when the page has no text.
func (Page) Parse(body []byte, e source.Entry) ([]Item, error) {
	text := StripHTML(string(body))
	if text == "" {
		return []Item{}, nil
	}
	return []Item{{GUID: pageGUIDPrefix + hashText(text), Title: PageChangedTitle, URL: cleanURL(e.URL, "")}}, nil
}
