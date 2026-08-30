// Package ports declares the interfaces nexus's core depends on.
package ports

import (
	"context"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
)

// IntelligenceClient is an OUTBOUND port: query the intelligence service
// (cortex). Implemented by adapters/outbound/grpc. The core knows nothing of
// gRPC — swap the transport and only the adapter changes.
type IntelligenceClient interface {
	Search(ctx context.Context, query string, pageSize int, pageToken string) (model.SearchResult, error)
}
