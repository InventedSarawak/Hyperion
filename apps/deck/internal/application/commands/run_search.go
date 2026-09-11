// Package commands holds deck's use cases that act on user intent.
package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/ports"
)

// Default and maximum result counts for one page.
const (
	DefaultPageSize = 25
	MaxPageSize     = 200
)

// RunSearch loads the feed: the first page, and each page after it.
type RunSearch struct {
	api ports.IntelligenceAPI
}

// NewRunSearch wires the use case with its outbound port.
func NewRunSearch(api ports.IntelligenceAPI) *RunSearch { return &RunSearch{api: api} }

// Handle loads the first page of a feed.
//
// No query means "the latest findings", which only makes sense newest-first:
// under relevance every record would score the same. So an empty query always
// sorts by newest, and a query defaults to best match unless asked otherwise.
func (c *RunSearch) Handle(ctx context.Context, query string, sort model.SearchSort, includeMalware bool, pageSize int) (model.Feed, error) {
	if c.api == nil {
		return model.Feed{}, fmt.Errorf("search: not connected to the intelligence service")
	}

	query = strings.TrimSpace(query)
	switch {
	case query == "":
		sort = model.SortNewest
	case sort != model.SortNewest:
		sort = model.SortRelevance
	}

	page, err := c.api.Search(ctx, query, sort, kindsFor(includeMalware), clampPageSize(pageSize), "")
	if err != nil {
		return model.Feed{}, err
	}
	return model.Feed{Query: query, Sort: sort, IncludeMalware: includeMalware}.Append(page), nil
}

// More loads the page after the last one in feed and appends it. A feed with
// no next page is returned unchanged.
func (c *RunSearch) More(ctx context.Context, feed model.Feed, pageSize int) (model.Feed, error) {
	if !feed.HasMore() {
		return feed, nil
	}
	if c.api == nil {
		return feed, fmt.Errorf("search: not connected to the intelligence service")
	}

	page, err := c.api.Search(ctx, feed.Query, feed.Sort, kindsFor(feed.IncludeMalware), clampPageSize(pageSize), feed.NextPageToken)
	if err != nil {
		return feed, err
	}
	return feed.Append(page), nil
}

// kindsFor is what a feed asks for. Malware is left out unless asked for:
// OSV alone lists a quarter of a million malicious packages, nearly all
// typosquats nobody installed, and they would bury every search. Searching
// for a finding's exact id finds it either way.
func kindsFor(includeMalware bool) []model.FindingKind {
	if includeMalware {
		return nil
	}
	return []model.FindingKind{model.KindVulnerability}
}

func clampPageSize(n int) int {
	switch {
	case n <= 0:
		return DefaultPageSize
	case n > MaxPageSize:
		return MaxPageSize
	default:
		return n
	}
}
