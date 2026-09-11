// Package queries holds cortex's read-side use cases.
package queries

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// Default and maximum page sizes for a search request.
const (
	DefaultPageSize = 25
	MaxPageSize     = 200
	// MaxResultWindow is the deepest offset the index will page to. Past it a
	// query has to be narrowed, not paged.
	MaxResultWindow = 10000
)

// Search is the read use case: one page of a query over indexed findings.
type Search struct {
	index ports.SearchIndex
}

// NewSearch wires the use case with its search port.
func NewSearch(index ports.SearchIndex) *Search { return &Search{index: index} }

// Result carries one page, the token for the next, and how much there is.
type Result struct {
	Hits              []model.SearchHit
	NextPageToken     string
	Total             int64
	TotalIsLowerBound bool
}

// Handle validates the request, runs it, and works out whether there is a
// next page.
//
// An empty query is accepted only when sorting by newest: "show me the latest
// findings" is a bounded, paged read. Under relevance an empty query has no
// meaning — every record would score the same — so it is rejected rather than
// quietly returning an arbitrary slice of the index.
func (q *Search) Handle(ctx context.Context, query string, sort model.SearchSort, pageSize int, pageToken string) (Result, error) {
	query = strings.TrimSpace(query)
	if sort != model.SortNewest {
		sort = model.SortRelevance
	}
	if query == "" && sort == model.SortRelevance {
		return Result{}, fmt.Errorf("search: query must not be empty when sorting by relevance")
	}

	size := pageSize
	switch {
	case size <= 0:
		size = DefaultPageSize
	case size > MaxPageSize:
		size = MaxPageSize
	}

	offset, err := decodePageToken(pageToken)
	if err != nil {
		return Result{}, err
	}
	if offset >= MaxResultWindow {
		return Result{}, fmt.Errorf("search: cannot page past result %d; narrow the query", MaxResultWindow)
	}
	// Shrink the last page rather than fail: the window is a ceiling on how
	// deep paging reaches, not a reason to refuse the final page.
	size = min(size, MaxResultWindow-offset)

	page, err := q.index.Search(ctx, model.SearchQuery{Text: query, Sort: sort, Size: size, Offset: offset})
	if err != nil {
		return Result{}, fmt.Errorf("search: %w", err)
	}

	return Result{
		Hits:              page.Hits,
		NextPageToken:     nextPageToken(offset, size, len(page.Hits), page.Total),
		Total:             page.Total,
		TotalIsLowerBound: page.TotalIsLowerBound,
	}, nil
}

// nextPageToken returns the offset of the following page, or "" when this was
// the last. With a total it is exact; without one (an index that does not
// count), a full page is the only hint that more may follow.
func nextPageToken(offset, size, returned int, total int64) string {
	next := offset + returned
	if returned == 0 || next >= MaxResultWindow {
		return ""
	}
	if total > 0 {
		if int64(next) >= total {
			return ""
		}
		return strconv.Itoa(next)
	}
	if returned < size {
		return ""
	}
	return strconv.Itoa(next)
}

// decodePageToken turns the opaque token back into an offset.
func decodePageToken(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	offset, err := strconv.Atoi(token)
	if err != nil || offset < 0 {
		return 0, fmt.Errorf("search: invalid page token %q", token)
	}
	return offset, nil
}
