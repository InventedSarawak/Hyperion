// Package commands holds deck's use cases that act on user intent.
package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/ports"
)

// Default and maximum result counts for one feed refresh.
const (
	DefaultPageSize = 25
	MaxPageSize     = 200
)

// RunSearch fetches the findings behind the live feed.
type RunSearch struct {
	api ports.IntelligenceAPI
}

// NewRunSearch wires the use case with its outbound port.
func NewRunSearch(api ports.IntelligenceAPI) *RunSearch { return &RunSearch{api: api} }

// Handle validates the query and returns a refreshed feed. An empty query is
// rejected here rather than at the server: the service will not scan its whole
// index, and failing locally keeps the round trip off the wire.
func (c *RunSearch) Handle(ctx context.Context, query string, pageSize int) (model.Feed, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return model.Feed{}, fmt.Errorf("search: enter a term to search for")
	}
	if c.api == nil {
		return model.Feed{}, fmt.Errorf("search: not connected to the intelligence service")
	}

	switch {
	case pageSize <= 0:
		pageSize = DefaultPageSize
	case pageSize > MaxPageSize:
		pageSize = MaxPageSize
	}

	hits, err := c.api.Search(ctx, query, pageSize)
	if err != nil {
		return model.Feed{}, err
	}
	return model.Feed{Query: query, Hits: hits}, nil
}
