// Package ports declares the interfaces deck's core depends on, implemented by
// adapters. deck knows nothing of gRPC: swap the transport and only the
// adapter changes.
package ports

import (
	"context"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// IntelligenceAPI is an OUTBOUND port: query the intelligence service.
// Implemented by adapters/outbound/grpc.
type IntelligenceAPI interface {
	// Search runs a full-text query over indexed vulnerabilities.
	Search(ctx context.Context, query string, pageSize int) ([]model.SearchHit, error)
	// BlastRadius returns the repositories a vulnerability reaches.
	BlastRadius(ctx context.Context, cveID string, maxDepth int) (model.BlastRadius, error)
}
