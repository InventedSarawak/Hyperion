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
)

// Search is the read use case: full-text query over indexed vulnerabilities.
type Search struct {
	index ports.SearchIndex
}

// NewSearch wires the use case with its search port.
func NewSearch(index ports.SearchIndex) *Search { return &Search{index: index} }

// Result carries the hits plus the token for the next page, if any.
type Result struct {
	Hits          []model.SearchHit
	NextPageToken string
}

// Handle validates paging inputs, runs the query, and computes the next page
// token. An empty query is rejected: cortex will not scan the whole index.
func (q *Search) Handle(ctx context.Context, query string, pageSize int, pageToken string) (Result, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return Result{}, fmt.Errorf("search: query must not be empty")
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

	hits, err := q.index.Search(ctx, query, size, offset)
	if err != nil {
		return Result{}, fmt.Errorf("search: %w", err)
	}

	// A full page implies there may be more; anything shorter ends the walk.
	next := ""
	if len(hits) == size {
		next = strconv.Itoa(offset + size)
	}
	return Result{Hits: hits, NextPageToken: next}, nil
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
