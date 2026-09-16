package publisher

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/inventedsarawak/hyperion/packages/common/kafka"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/events"
)

// Kafka publishes each event to the signal topic. It is the same mapping the
// stdout publisher does — domain event to hyperion.events.v1.SignalDiscovered
// — with a broker underneath instead of a file descriptor. Both satisfy
// ports.SignalPublisher, and nothing above this package knows which is in use.
type Kafka struct {
	producer *kafka.Producer
	log      *slog.Logger
}

// KafkaConfig says where to publish.
type KafkaConfig struct {
	Brokers []string
	Topic   string
	// Partitions is used only when the topic has to be created. Zero takes
	// the Hyperion default.
	Partitions int32
}

// NewKafka connects to the cluster and ensures the topic exists.
//
// Creating the topic here rather than letting the broker auto-create it is
// deliberate: an auto-created topic gets whatever partition count the broker
// defaults to, and the partition count is what bounds how many consumers can
// share the work.
func NewKafka(ctx context.Context, cfg KafkaConfig, log *slog.Logger) (*Kafka, error) {
	if log == nil {
		log = slog.Default()
	}
	topic := cfg.Topic
	if topic == "" {
		topic = kafka.TopicSignals
	}

	clientCfg := kafka.Config{Brokers: cfg.Brokers, ClientID: "siphon"}
	if err := kafka.EnsureTopic(ctx, clientCfg, topic, cfg.Partitions); err != nil {
		return nil, fmt.Errorf("publisher: ensure topic: %w", err)
	}

	producer, err := kafka.NewProducer(clientCfg, topic, kafka.WithProducerLogger(log))
	if err != nil {
		return nil, fmt.Errorf("publisher: producer: %w", err)
	}
	if err := producer.Ping(ctx); err != nil {
		producer.Close()
		return nil, fmt.Errorf("publisher: %w", err)
	}

	log.Info("publishing signals to kafka", "brokers", cfg.Brokers, "topic", topic)
	return &Kafka{producer: producer, log: log}, nil
}

// Publish maps the domain event to its protobuf form and queues it under the
// finding's id.
//
// The key is the identity, not the signal id: every source reporting the same
// CVE produces the same key, so all reports of one finding land on one
// partition and are merged in arrival order by one consumer. Keying by the
// per-observation signal id would scatter them across partitions and let two
// consumers merge the same record at once, each overwriting the other's work.
func (p *Kafka) Publish(ctx context.Context, evt events.SignalDiscovered) error {
	return p.producer.Publish(ctx, evt.Signal.CVEID, toProto(evt))
}

// Flush blocks until the broker has acknowledged everything published so far.
func (p *Kafka) Flush(ctx context.Context) error { return p.producer.Flush(ctx) }

// Close flushes and disconnects.
func (p *Kafka) Close() error { return p.producer.Close() }
