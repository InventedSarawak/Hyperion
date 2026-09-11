package queries

import (
	"context"
	"fmt"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/ports"
)

// Bounds applied at the edge. cortex clamps again; the gateway rejects
// obvious nonsense before it costs a round trip.
const (
	DefaultBlastRadiusDepth = 3
	MaxBlastRadiusDepth     = 10
	DefaultBlastRadiusLimit = 100
	MaxBlastRadiusLimit     = 1000
)

// GetBlastRadius is the gateway use case backing the GraphQL `blastRadius`
// query.
type GetBlastRadius struct {
	intelligence ports.IntelligenceClient
}

// NewGetBlastRadius wires the use case with its outbound port.
func NewGetBlastRadius(intelligence ports.IntelligenceClient) *GetBlastRadius {
	return &GetBlastRadius{intelligence: intelligence}
}

// Handle validates and clamps the request, then delegates.
func (q *GetBlastRadius) Handle(ctx context.Context, cveID string, maxDepth, limit int) (model.BlastRadius, error) {
	cveID = strings.TrimSpace(cveID)
	if cveID == "" {
		return model.BlastRadius{}, fmt.Errorf("enter a finding id to trace — a CVE, GHSA or MAL id")
	}

	switch {
	case maxDepth <= 0:
		maxDepth = DefaultBlastRadiusDepth
	case maxDepth > MaxBlastRadiusDepth:
		maxDepth = MaxBlastRadiusDepth
	}
	switch {
	case limit <= 0:
		limit = DefaultBlastRadiusLimit
	case limit > MaxBlastRadiusLimit:
		limit = MaxBlastRadiusLimit
	}

	radius, err := q.intelligence.BlastRadius(ctx, cveID, maxDepth, limit)
	if err != nil {
		return model.BlastRadius{}, err
	}
	return radius, nil
}
