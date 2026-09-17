package publisher

import (
	"context"
	"fmt"
	"log/slog"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	eventsv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/events/v1"

	"github.com/inventedsarawak/hyperion/packages/common/kafka"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// KafkaDependencies publishes manifest reads to the dependency topic. It
// implements ports.DependencyPublisher, the same port the gRPC client
// implements — the scan workflow cannot tell which one it is talking to.
type KafkaDependencies struct {
	producer *kafka.Producer
	log      *slog.Logger
}

// KafkaDependenciesConfig says where observations go.
type KafkaDependenciesConfig struct {
	Brokers []string
	Topic   string
	// Partitions is used only when the topic has to be created.
	Partitions int32
}

// NewKafkaDependencies connects to the cluster and ensures the topic exists.
func NewKafkaDependencies(ctx context.Context, cfg KafkaDependenciesConfig, log *slog.Logger) (*KafkaDependencies, error) {
	if log == nil {
		log = slog.Default()
	}
	topic := cfg.Topic
	if topic == "" {
		topic = kafka.TopicDependencies
	}

	clientCfg := kafka.Config{Brokers: cfg.Brokers, ClientID: "siphon"}
	if err := kafka.EnsureTopic(ctx, clientCfg, topic, cfg.Partitions); err != nil {
		return nil, fmt.Errorf("publisher: ensure topic: %w", err)
	}

	producer, err := kafka.NewProducer(clientCfg, topic, kafka.WithProducerLogger(log))
	if err != nil {
		return nil, fmt.Errorf("publisher: dependency producer: %w", err)
	}
	if err := producer.Ping(ctx); err != nil {
		producer.Close()
		return nil, fmt.Errorf("publisher: %w", err)
	}

	log.Info("publishing dependency observations to kafka", "brokers", cfg.Brokers, "topic", topic)
	return &KafkaDependencies{producer: producer, log: log}, nil
}

// Publish maps the snapshot onto the wire contract and sends it.
//
// The key is the repository's full name, so every observation of one
// repository lands on one partition and is applied in the order it was read.
// Two reads of the same repository racing each other would otherwise let an
// older manifest overwrite a newer one.
//
// It flushes before returning: a scan reports itself complete to the watchlist
// straight afterwards, and a record still sitting in a producer buffer at that
// moment would be a scan recorded as done that never happened.
func (p *KafkaDependencies) Publish(ctx context.Context, snapshot model.RepositorySnapshot) error {
	if err := snapshot.Validate(); err != nil {
		return err
	}

	key := snapshot.Repository.FullName()
	if err := p.producer.Publish(ctx, key, toDependencyProto(snapshot)); err != nil {
		return err
	}
	return p.producer.Flush(ctx)
}

// Close flushes and disconnects.
func (p *KafkaDependencies) Close() error { return p.producer.Close() }

// --- mapping: domain -> wire contract ---

func toDependencyProto(s model.RepositorySnapshot) *eventsv1.DependencyObserved {
	return &eventsv1.DependencyObserved{
		ObservationId: fmt.Sprintf("%s@%d", s.Repository.FullName(), s.ObservedAt.UTC().UnixNano()),
		Repository: &commonv1.Repository{
			Owner:         s.Repository.Owner,
			Name:          s.Repository.Name,
			Url:           s.Repository.URL,
			DefaultBranch: s.Repository.DefaultBranch,
		},
		Author:       toProtoAuthorRef(s.Author),
		Publishes:    toProtoPackage(s.Publishes),
		Dependencies: toProtoDependencies(s.Dependencies),
		ObservedAt:   toTimestamp(s.ObservedAt),
	}
}

// toProtoAuthorRef leaves ownership out when the forge did not report it:
// an empty Author message would claim a maintainer with no handle.
func toProtoAuthorRef(a model.Author) *commonv1.Author {
	if a.IsZero() {
		return nil
	}
	return &commonv1.Author{Login: a.Login, Name: a.Name, Url: a.URL}
}

func toProtoPackage(ref valueobject.PackageRef) *commonv1.PackageRef {
	if ref.IsZero() {
		return nil
	}
	return &commonv1.PackageRef{
		Ecosystem: toProtoEcosystem(ref.Ecosystem),
		Name:      ref.Name,
		Version:   ref.Version,
	}
}

func toProtoDependencies(deps []model.Dependency) []*commonv1.Dependency {
	if len(deps) == 0 {
		return nil
	}
	out := make([]*commonv1.Dependency, 0, len(deps))
	for _, d := range deps {
		// A requirement that does not name a package cannot become an edge,
		// and sending it would only make cortex discard it later.
		if d.Validate() != nil {
			continue
		}
		out = append(out, &commonv1.Dependency{
			Package:      toProtoPackage(d.Package),
			Direct:       d.Direct,
			ManifestPath: d.ManifestPath,
			Locked:       d.Locked,
		})
	}
	return out
}
