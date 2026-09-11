// Package noopgraph is the OUTBOUND adapter used when no graph backend is
// configured. Unlike the no-op search index, it does not pretend to succeed:
// every call returns ports.ErrGraphUnavailable.
//
// An empty blast radius is indistinguishable from "nothing is affected", and
// answering a security question that way when the truth is "we never looked"
// is worse than answering not at all.
package noopgraph

import (
	"context"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// Graph implements ports.DependencyGraph by refusing every operation.
type Graph struct{}

// New builds the disabled graph adapter.
func New() *Graph { return &Graph{} }

// UpsertRepositorySnapshot reports that there is no graph to write to.
func (g *Graph) UpsertRepositorySnapshot(context.Context, model.RepositorySnapshot) (int, error) {
	return 0, ports.ErrGraphUnavailable
}

// LinkVulnerability reports that there is no graph to write to.
func (g *Graph) LinkVulnerability(context.Context, string, []valueobject.PackageRef) error {
	return ports.ErrGraphUnavailable
}

// RemoveVulnerabilities reports that there is no graph to remove from.
func (g *Graph) RemoveVulnerabilities(context.Context, []string) error {
	return ports.ErrGraphUnavailable
}

// FindBlastRadius reports that the question cannot be answered.
func (g *Graph) FindBlastRadius(context.Context, string, int, int) (model.BlastRadius, error) {
	return model.BlastRadius{}, ports.ErrGraphUnavailable
}

// FindRepositoryExposures reports that the question cannot be answered.
func (g *Graph) FindRepositoryExposures(context.Context, []string, int) ([]model.Exposure, error) {
	return nil, ports.ErrGraphUnavailable
}

// HasRepository reports that the question cannot be answered.
func (g *Graph) HasRepository(context.Context, string) (bool, error) {
	return false, ports.ErrGraphUnavailable
}

// Ready reports that no backend is configured.
func (g *Graph) Ready(context.Context) error { return ports.ErrGraphUnavailable }

// RemoveRepository reports that there is no graph to remove from.
func (g *Graph) RemoveRepository(context.Context, string) error { return ports.ErrGraphUnavailable }
