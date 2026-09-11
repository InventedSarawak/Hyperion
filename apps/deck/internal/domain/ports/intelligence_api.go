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
	// Search returns one page of results. An empty query is allowed only with
	// SortNewest; pageToken is "" for the first page.
	Search(ctx context.Context, query string, sort model.SearchSort, pageSize int, pageToken string) (model.SearchPage, error)
	// BlastRadius returns the repositories a vulnerability reaches.
	BlastRadius(ctx context.Context, cveID string, maxDepth int) (model.BlastRadius, error)
}
