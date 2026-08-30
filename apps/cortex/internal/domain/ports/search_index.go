package ports

import (
	"context"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// SearchIndex is an OUTBOUND port: full-text indexing and querying of
// vulnerabilities. Implemented by adapters/outbound/elasticsearch; a no-op
// implementation is used when no search backend is configured.
type SearchIndex interface {
	// Index makes (or refreshes) the searchable document for v.
	Index(ctx context.Context, v model.Vulnerability) error
	// Search runs a full-text query, returning scored hits.
	Search(ctx context.Context, query string, size, offset int) ([]model.SearchHit, error)
	// Ready reports whether the backend is reachable and usable.
	Ready(ctx context.Context) error
}
