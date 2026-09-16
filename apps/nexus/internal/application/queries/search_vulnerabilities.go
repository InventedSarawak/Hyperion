// Package queries holds nexus's read use cases.
package queries

import (
	"context"
	"fmt"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/ports"
)

// SearchVulnerabilities is the gateway use case backing the GraphQL `search`
// query. It validates input and delegates to the intelligence service.
type SearchVulnerabilities struct {
	intelligence ports.IntelligenceClient
}

// NewSearchVulnerabilities wires the use case with its outbound port.
func NewSearchVulnerabilities(intelligence ports.IntelligenceClient) *SearchVulnerabilities {
	return &SearchVulnerabilities{intelligence: intelligence}
}

// Handle runs the search. An empty term is accepted only when sorting by
// newest — "the latest findings" — because under relevance every record would
// score the same and the result would be an arbitrary slice.
func (q *SearchVulnerabilities) Handle(ctx context.Context, term string, sort model.SearchSort, kinds []model.FindingKind, pageSize int, pageToken string) (model.SearchResult, error) {
	term = strings.TrimSpace(term)
	if sort != model.SortNewest {
		sort = model.SortRelevance
	}
	if term == "" && sort == model.SortRelevance {
		return model.SearchResult{}, fmt.Errorf("enter a search term, or sort by NEWEST to see the latest findings")
	}

	result, err := q.intelligence.Search(ctx, term, sort, kinds, pageSize, pageToken)
	if err != nil {
		return model.SearchResult{}, err
	}
	return result, nil
}
