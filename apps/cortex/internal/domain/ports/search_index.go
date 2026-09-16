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
	// Search returns one page of results for a query.
	Search(ctx context.Context, q model.SearchQuery) (model.SearchPage, error)
	// Ready reports whether the backend is reachable and usable.
	Ready(ctx context.Context) error
	// IDs lists the id of every indexed document, so the index can be
	// reconciled against the store it mirrors.
	IDs(ctx context.Context) ([]string, error)
	// Delete removes one document. Removing one that is absent succeeds.
	Delete(ctx context.Context, id string) error
}
