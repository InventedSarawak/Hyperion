package queries

import (
	"context"
	"fmt"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// Bounds on a blast-radius traversal. Depth is capped because the cost of a
// variable-length graph walk grows with the branching factor: an unbounded
// query on a dense graph is a denial of service against our own database.
const (
	DefaultBlastRadiusDepth = 3
	MaxBlastRadiusDepth     = 10
	DefaultBlastRadiusLimit = 100
	MaxBlastRadiusLimit     = 1000
)

// CalculateBlastRadius is the read use case behind the platform's core
// question: given a vulnerability, which repositories does it actually reach?
type CalculateBlastRadius struct {
	graph        ports.DependencyGraph
	defaultDepth int
}

// NewCalculateBlastRadius wires the use case with the graph port.
// defaultDepth <= 0 falls back to DefaultBlastRadiusDepth.
func NewCalculateBlastRadius(graph ports.DependencyGraph, defaultDepth int) *CalculateBlastRadius {
	if defaultDepth <= 0 {
		defaultDepth = DefaultBlastRadiusDepth
	}
	if defaultDepth > MaxBlastRadiusDepth {
		defaultDepth = MaxBlastRadiusDepth
	}
	return &CalculateBlastRadius{graph: graph, defaultDepth: defaultDepth}
}

// Handle validates and clamps the request, then walks the graph. An empty CVE
// id is rejected: cortex will not enumerate the whole graph.
func (q *CalculateBlastRadius) Handle(ctx context.Context, cveID string, maxDepth, limit int) (model.BlastRadius, error) {
	cveID = valueobject.NormalizeCVEID(cveID)
	if cveID == "" {
		return model.BlastRadius{}, fmt.Errorf("blast radius: cve id must not be empty")
	}
	if q.graph == nil {
		return model.BlastRadius{}, ports.ErrGraphUnavailable
	}

	depth := maxDepth
	switch {
	case depth <= 0:
		depth = q.defaultDepth
	case depth > MaxBlastRadiusDepth:
		depth = MaxBlastRadiusDepth
	}

	size := limit
	switch {
	case size <= 0:
		size = DefaultBlastRadiusLimit
	case size > MaxBlastRadiusLimit:
		size = MaxBlastRadiusLimit
	}

	radius, err := q.graph.FindBlastRadius(ctx, cveID, depth, size)
	if err != nil {
		return model.BlastRadius{}, fmt.Errorf("blast radius %s: %w", cveID, err)
	}
	radius.CVEID = cveID
	return radius, nil
}
