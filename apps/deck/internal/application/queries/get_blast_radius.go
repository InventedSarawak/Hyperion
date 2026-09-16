// Package queries holds deck's read-side use cases.
package queries

import (
	"context"
	"fmt"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/ports"
)

// DefaultDepth is how far the graph explorer walks unless told otherwise.
const DefaultDepth = 3

// GetBlastRadius fetches the repositories a vulnerability reaches.
type GetBlastRadius struct {
	api ports.IntelligenceAPI
}

// NewGetBlastRadius wires the use case with its outbound port.
func NewGetBlastRadius(api ports.IntelligenceAPI) *GetBlastRadius {
	return &GetBlastRadius{api: api}
}

// Handle validates the identifier and walks the graph.
func (q *GetBlastRadius) Handle(ctx context.Context, cveID string, maxDepth int) (model.BlastRadius, error) {
	cveID = strings.TrimSpace(cveID)
	if cveID == "" {
		return model.BlastRadius{}, fmt.Errorf("blast radius: select a vulnerability first")
	}
	if q.api == nil {
		return model.BlastRadius{}, fmt.Errorf("blast radius: not connected to the intelligence service")
	}
	if maxDepth <= 0 {
		maxDepth = DefaultDepth
	}
	return q.api.BlastRadius(ctx, cveID, maxDepth)
}
