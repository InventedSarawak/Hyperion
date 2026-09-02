// Package osint is an OUTBOUND adapter for OSINT feeds — security mailing
// lists and researcher RSS/Atom feeds such as Full Disclosure, where issues are
// often discussed before a formal advisory exists.
//
// No credential is required; these are plain RSS documents. Only items that
// mention a CVE id are emitted, since the domain keys signals by CVE.
package osint

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/cveid"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// DefaultFeedURL is the Full Disclosure mailing list feed.
const DefaultFeedURL = "https://seclists.org/rss/fulldisclosure.rss"

// requestDelay keeps polling courteous for static feed files.
const requestDelay = 3 * time.Second

// Client fetches and parses OSINT feeds.
type Client struct {
	http  *sourcehttp.Client
	feeds []string
}

// New builds an OSINT client over one or more feed URLs.
func New(feeds []string, opts ...sourcehttp.Option) *Client {
	if len(feeds) == 0 {
		feeds = []string{DefaultFeedURL}
	}
	return &Client{http: sourcehttp.New(requestDelay, opts...), feeds: feeds}
}

// Kind reports the source this client speaks for.
func (c *Client) Kind() valueobject.SourceKind { return valueobject.SourceKindOSINT }

// Fetch reads every configured feed and emits a signal per CVE mentioned.
func (c *Client) Fetch(ctx context.Context, since time.Time) ([]model.SourceSignal, error) {
	var (
		signals []model.SourceSignal
		errs    []string
	)

	for _, feed := range c.feeds {
		items, err := c.fetchFeed(ctx, feed)
		if err != nil {
			// A dead feed should not kill the others.
			errs = append(errs, err.Error())
			continue
		}

		for _, item := range items {
			published := parseTime(item.PubDate)
			if !since.IsZero() && !published.IsZero() && published.Before(since) {
				continue
			}

			text := item.Title + " " + item.Description
			for _, id := range cveid.All(text) {
				signals = append(signals, model.SourceSignal{
					CVEID:       id,
					Title:       strings.TrimSpace(item.Title),
					Description: summarize(item),
					References:  references(item),
					PublishedAt: published,
					ModifiedAt:  published,
				})
			}
		}
	}

	if len(signals) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("osint: all feeds failed: %s", strings.Join(errs, "; "))
	}
	return signals, nil
}

func (c *Client) fetchFeed(ctx context.Context, feedURL string) ([]rssItem, error) {
	body, err := c.http.GetBytes(ctx, feedURL)
	if err != nil {
		return nil, fmt.Errorf("osint: %w", err)
	}

	var doc rssFeed
	if err := xml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("osint: parse %s: %w", feedURL, err)
	}
	return doc.Channel.Items, nil
}

// --- RSS wire DTOs (private to the adapter) ---

type rssFeed struct {
	Channel struct {
		Items []rssItem `xml:"item"`
	} `xml:"channel"`
}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
}

// --- mapping helpers ---

func summarize(item rssItem) string {
	body := strings.TrimSpace(item.Description)
	if body == "" {
		body = strings.TrimSpace(item.Title)
	}
	return "Discussed on an OSINT feed (pre-advisory chatter): " + body
}

func references(item rssItem) []string {
	if item.Link == "" {
		return nil
	}
	return []string{item.Link}
}

func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
