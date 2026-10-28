package feed

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/source"
)

// detectBytes is how much of a body Detect looks at.
const detectBytes = 64 << 10

// Detect tells the format of a feed from its root element: "rss" for
// <rss>, "atom" for <feed>, "" for anything else (an HTML page, JSON, a
// body that is not XML). The content type is not trusted: servers often
// send feeds as text/html or text/xml.
func Detect(contentType string, body []byte) string {
	_ = contentType
	if len(body) > detectBytes {
		body = body[:detectBytes]
	}
	d := newDecoder(body)
	for {
		tok, err := d.Token()
		if err != nil {
			return ""
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "rss":
				return "rss"
			case "feed":
				return "atom"
			}
			return ""
		case xml.CharData:
			if len(bytes.TrimSpace(t)) > 0 {
				return ""
			}
		}
	}
}

// cleanXML drops what XML forbids and some servers send anyway: a byte
// order mark and the control characters other than tab, line feed and
// carriage return (they never occur inside a UTF-8 sequence).
func cleanXML(body []byte) []byte {
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	if bytes.IndexFunc(body, func(r rune) bool { return r < 0x20 && r != '\t' && r != '\n' && r != '\r' }) < 0 {
		return body
	}
	out := make([]byte, 0, len(body))
	for _, c := range body {
		if c >= 0x20 || c == '\t' || c == '\n' || c == '\r' {
			out = append(out, c)
		}
	}
	return out
}

// newDecoder reads untrusted XML: strict, the HTML named entities known
// (an internal table: no entity is ever fetched, a DOCTYPE is skipped),
// UTF-8, ASCII, ISO-8859-1 and windows-1252 only.
func newDecoder(body []byte) *xml.Decoder {
	d := xml.NewDecoder(bytes.NewReader(cleanXML(body)))
	d.Strict = true
	d.Entity = xml.HTMLEntity
	d.CharsetReader = charsetReader
	return d
}

func charsetReader(charset string, in io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(charset)) {
	case "", "utf-8", "utf8", "us-ascii", "ascii":
		return in, nil
	case "iso-8859-1", "iso8859-1", "latin1", "latin-1", "l1", "iso-8859-15", "windows-1252", "cp1252":
		b, err := io.ReadAll(in)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(decode1252(b)), nil
	}
	return nil, fmt.Errorf("the character set %q is not supported (use UTF-8)", charset)
}

// cp1252 maps the bytes 0x80 to 0x9F of windows-1252 (a superset of
// ISO-8859-1 for text) to their characters; 0 means undefined.
var cp1252 = [32]rune{
	0x20AC, 0, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0, 0x017D, 0,
	0, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0, 0x017E, 0x0178,
}

func decode1252(b []byte) []byte {
	out := make([]byte, 0, len(b)+len(b)/4)
	for _, c := range b {
		r := rune(c)
		if c >= 0x80 && c <= 0x9F {
			if r = cp1252[c-0x80]; r == 0 {
				r = utf8.RuneError
			}
		}
		out = utf8.AppendRune(out, r)
	}
	return out
}

// RSS reads an RSS 2.0 (or 0.9x) feed.
type RSS struct{}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	GUID        string `xml:"guid"`
	PubDate     string `xml:"pubDate"`
	DCDate      string `xml:"http://purl.org/dc/elements/1.1/ date"`
	Description string `xml:"description"`
}

type rssDoc struct {
	XMLName xml.Name  `xml:"rss"`
	Items   []rssItem `xml:"channel>item"`
}

// Parse reads the first MaxItemsPerRead items of body.
func (RSS) Parse(body []byte, e source.Entry) ([]Item, error) {
	var doc rssDoc
	if err := newDecoder(body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("not a readable RSS feed: %w", err)
	}
	out := []Item{}
	for _, it := range doc.Items {
		if len(out) == MaxItemsPerRead {
			break
		}
		title := cleanText(it.Title, maxTitle)
		link := cleanURL(it.Link, e.URL)
		guid := cleanGUID(it.GUID)
		if guid == "" {
			guid = fallbackGUID(link, title)
		}
		date := parseDate(it.PubDate)
		if date == "" {
			date = parseDate(it.DCDate)
		}
		out = append(out, Item{GUID: guid, Title: title, URL: link, PublishedAt: date, Summary: cleanText(it.Description, MaxSummary)})
	}
	return out, nil
}

// Atom reads an Atom 1.0 feed.
type Atom struct{}

// atomText is a text construct: type text or html is character data (html
// escaped once more), xhtml is markup.
type atomText struct {
	Type  string `xml:"type,attr"`
	Text  string `xml:",chardata"`
	Inner string `xml:",innerxml"`
}

func (t atomText) clean(n int) string {
	if strings.EqualFold(t.Type, "xhtml") {
		return cleanText(t.Inner, n)
	}
	return cleanText(t.Text, n)
}

type atomLink struct {
	Rel  string `xml:"rel,attr"`
	Href string `xml:"href,attr"`
}

type atomEntry struct {
	ID        string     `xml:"id"`
	Title     atomText   `xml:"title"`
	Links     []atomLink `xml:"link"`
	Published string     `xml:"published"`
	Updated   string     `xml:"updated"`
	Summary   atomText   `xml:"summary"`
	Content   atomText   `xml:"content"`
}

type atomDoc struct {
	XMLName xml.Name    `xml:"feed"`
	Entries []atomEntry `xml:"entry"`
}

// Parse reads the first MaxItemsPerRead entries of body.
func (Atom) Parse(body []byte, e source.Entry) ([]Item, error) {
	var doc atomDoc
	if err := newDecoder(body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("not a readable Atom feed: %w", err)
	}
	out := []Item{}
	for _, en := range doc.Entries {
		if len(out) == MaxItemsPerRead {
			break
		}
		title := en.Title.clean(maxTitle)
		link := ""
		for _, l := range en.Links {
			if l.Rel == "" || l.Rel == "alternate" {
				link = cleanURL(l.Href, e.URL)
				break
			}
		}
		guid := cleanGUID(en.ID)
		if guid == "" {
			guid = fallbackGUID(link, title)
		}
		date := parseDate(en.Published)
		if date == "" {
			date = parseDate(en.Updated)
		}
		summary := en.Summary.clean(MaxSummary)
		if summary == "" {
			summary = en.Content.clean(MaxSummary)
		}
		out = append(out, Item{GUID: guid, Title: title, URL: link, PublishedAt: date, Summary: summary})
	}
	return out, nil
}
