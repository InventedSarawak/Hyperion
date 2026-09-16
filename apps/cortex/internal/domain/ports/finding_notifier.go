package ports

import (
	"context"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// FindingNotifier is an OUTBOUND port: announce that a finding has been
// stored, so anything watching can react without polling for it.
//
// Notify must not block. Ingestion is the system's primary work and a live
// feed is a convenience on top of it: a viewer that has stopped reading must
// lose updates, never hold up the pipeline that produces them.
type FindingNotifier interface {
	Notify(ctx context.Context, v model.Vulnerability)
}
