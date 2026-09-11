package queries

import (
	"context"
	"errors"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/ports"
)

// GetRepositoryExposure backs the GraphQL `repositoryExposure` query: which
// vulnerabilities a repository has — blast radius read from its side.
type GetRepositoryExposure struct {
	intelligence ports.IntelligenceClient
}

// NewGetRepositoryExposure wires the use case with its outbound port.
func NewGetRepositoryExposure(intelligence ports.IntelligenceClient) *GetRepositoryExposure {
	return &GetRepositoryExposure{intelligence: intelligence}
}

// Handle rejects an empty name before it costs a round trip.
func (q *GetRepositoryExposure) Handle(ctx context.Context, fullName string, includeUnaffected bool) (model.RepositoryExposure, error) {
	fullName = strings.TrimSpace(fullName)
	if fullName == "" {
		return model.RepositoryExposure{}, errors.New("enter a repository as owner/name")
	}
	return q.intelligence.RepositoryExposure(ctx, fullName, includeUnaffected)
}
