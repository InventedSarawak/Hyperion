package consumer

import (
	"context"
	"log/slog"
	"sync/atomic"

	eventsv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/events/v1"

	"github.com/inventedsarawak/hyperion/packages/common/kafka"
	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// DependencyIngester is the use case this adapter drives.
type DependencyIngester interface {
	Handle(ctx context.Context, snapshot model.RepositorySnapshot) (int, error)
}

// DependencyHandler writes observed manifests into the dependency graph.
//
// It is the event-driven counterpart of the IngestDependencies RPC: the same
// use case, reached over the topic rather than over a connection siphon has to
// hold open. The RPC remains for callers that want the edge count back.
type DependencyHandler struct {
	ingester DependencyIngester
	log      *slog.Logger

	observed atomic.Int64
	written  atomic.Int64
}

// NewDependencyHandler wires the adapter to the use case.
func NewDependencyHandler(ingester DependencyIngester, log *slog.Logger) *DependencyHandler {
	if log == nil {
		log = slog.Default()
	}
	return &DependencyHandler{ingester: ingester, log: log}
}

// Handle records one observation.
//
// A graph that is unavailable is an ordinary failure here, not an
// unprocessable record: it is retried, and if it keeps failing the record is
// set aside rather than dropped. That is the difference the topic buys — a
// scan taken while Neo4j was down is not lost, it is waiting.
func (h *DependencyHandler) Handle(ctx context.Context, msg kafka.Message) error {
	var evt eventsv1.DependencyObserved
	if err := msg.Into(&evt); err != nil {
		return err
	}

	snapshot := toDomainSnapshot(&evt)
	written, err := h.ingester.Handle(ctx, snapshot)
	if err != nil {
		return err
	}

	h.observed.Add(1)
	h.written.Add(int64(written))
	h.log.Info("repository dependencies recorded",
		"repository", snapshot.Repository.FullName(),
		"dependencies", len(snapshot.Dependencies), "edges_written", written,
		"partition", msg.Partition, "offset", msg.Offset)
	return nil
}

// Observed reports how many repository observations this handler has recorded.
func (h *DependencyHandler) Observed() int64 { return h.observed.Load() }

// --- mapping: wire contract -> cortex domain ---

func toDomainSnapshot(evt *eventsv1.DependencyObserved) model.RepositorySnapshot {
	repo := evt.GetRepository()
	return model.RepositorySnapshot{
		Repository: model.Repository{
			Owner:         repo.GetOwner(),
			Name:          repo.GetName(),
			URL:           repo.GetUrl(),
			DefaultBranch: repo.GetDefaultBranch(),
		},
		Author: model.Author{
			Login: evt.GetAuthor().GetLogin(),
			Name:  evt.GetAuthor().GetName(),
			URL:   evt.GetAuthor().GetUrl(),
		},
		Publishes:    toDomainPackageRef(evt.GetPublishes()),
		Dependencies: toDomainDependencies(evt.GetDependencies()),
		ObservedAt:   fromTimestamp(evt.GetObservedAt()),
	}
}

func toDomainDependencies(deps []*commonv1.Dependency) []model.Dependency {
	if len(deps) == 0 {
		return nil
	}
	out := make([]model.Dependency, 0, len(deps))
	for _, d := range deps {
		out = append(out, model.Dependency{
			Package:      toDomainPackageRef(d.GetPackage()),
			Direct:       d.GetDirect(),
			ManifestPath: d.GetManifestPath(),
			Locked:       d.GetLocked(),
		})
	}
	return out
}

func toDomainPackageRef(ref *commonv1.PackageRef) valueobject.PackageRef {
	if ref == nil {
		return valueobject.PackageRef{}
	}
	return valueobject.PackageRef{
		Ecosystem: toEcosystem(ref.GetEcosystem()),
		Name:      ref.GetName(),
		Version:   ref.GetVersion(),
	}
}
