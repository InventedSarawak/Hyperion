// Package commands holds cortex's write-side use cases.
package commands

import (
	"context"
	"errors"
	"fmt"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// IngestSignal stores an incoming vulnerability, reconciling it with any
// existing record via the domain's Merge rule.
type IngestSignal struct {
	repo ports.VulnerabilityRepo
}

// NewIngestSignal wires the use case with its storage port.
func NewIngestSignal(repo ports.VulnerabilityRepo) *IngestSignal {
	return &IngestSignal{repo: repo}
}

// Handle validates, merges with any existing record, and persists.
func (c *IngestSignal) Handle(ctx context.Context, incoming model.Vulnerability) error {
	if err := incoming.Validate(); err != nil {
		return err
	}

	existing, err := c.repo.GetByCVE(ctx, incoming.CVEID)
	switch {
	case err == nil:
		incoming = existing.Merge(incoming)
	case errors.Is(err, ports.ErrNotFound):
		// first time we've seen this CVE
	default:
		return fmt.Errorf("ingest: load existing %s: %w", incoming.CVEID, err)
	}

	if err := c.repo.Upsert(ctx, incoming); err != nil {
		return fmt.Errorf("ingest: upsert %s: %w", incoming.CVEID, err)
	}
	return nil
}
