// Package noopindex is a null OUTBOUND adapter for ports.SearchIndex. It lets
// cortex run (ingest + store) when no search backend is configured; searches
// simply return nothing rather than failing the whole service.
package noopindex

import (
	"context"
	"errors"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// ErrNoSearchBackend is returned by Ready to signal search is unavailable.
var ErrNoSearchBackend = errors.New("no search backend configured")

// Index does nothing and finds nothing.
type Index struct{}

// New builds the no-op index.
func New() *Index { return &Index{} }

// Index discards the document.
func (i *Index) Index(context.Context, model.Vulnerability) error { return nil }

// Search always returns no hits.
func (i *Index) Search(context.Context, model.SearchQuery) (model.SearchPage, error) {
	return model.SearchPage{}, nil
}

// Ready always reports that no backend is configured.
func (i *Index) Ready(context.Context) error { return ErrNoSearchBackend }

// IDs reports an empty index.
func (i *Index) IDs(context.Context) ([]string, error) { return nil, nil }

// Delete does nothing.
func (i *Index) Delete(context.Context, string) error { return nil }
