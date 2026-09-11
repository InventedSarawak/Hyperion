package queries

import (
	"context"
	"errors"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/ports"
)

// GetRepositoryExposure loads which vulnerabilities a repository has.
type GetRepositoryExposure struct {
	api ports.IntelligenceAPI
}

// NewGetRepositoryExposure wires the use case with its outbound port.
func NewGetRepositoryExposure(api ports.IntelligenceAPI) *GetRepositoryExposure {
	return &GetRepositoryExposure{api: api}
}

// Handle loads one repository's findings.
func (q *GetRepositoryExposure) Handle(ctx context.Context, fullName string, includeUnaffected bool) (model.RepositoryExposure, error) {
	fullName = strings.TrimSpace(fullName)
	if fullName == "" {
		return model.RepositoryExposure{}, errors.New("findings: select a repository first")
	}
	if q.api == nil {
		return model.RepositoryExposure{}, errors.New("findings: not connected to the intelligence service")
	}
	return q.api.RepositoryExposure(ctx, fullName, includeUnaffected)
}
