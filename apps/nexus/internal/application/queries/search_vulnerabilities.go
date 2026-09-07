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

// Handle runs the search after rejecting an empty term.
func (q *SearchVulnerabilities) Handle(ctx context.Context, term string, pageSize int, pageToken string) (model.SearchResult, error) {
	term = strings.TrimSpace(term)
	if term == "" {
		return model.SearchResult{}, fmt.Errorf("search: term must not be empty")
	}

	result, err := q.intelligence.Search(ctx, term, pageSize, pageToken)
	if err != nil {
		return model.SearchResult{}, fmt.Errorf("search %q: %w", term, err)
	}
	return result, nil
}
