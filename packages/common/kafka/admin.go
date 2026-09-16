package kafka

import (
	"context"
	"errors"
	"fmt"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
)

// DefaultPartitions is how many partitions a Hyperion topic gets.
//
// Partitions are the unit of parallelism and the unit of ordering at once:
// more of them lets more consumers work, and each one is an independent
// ordered log. Six is chosen to sit under the ingest worker count so no
// consumer is idle, and it is a ceiling that can be raised later but never
// lowered — raising it re-partitions new records, so keys that used to share a
// partition may stop sharing one. Do that only when nothing in flight cares.
const DefaultPartitions = 6

// EnsureTopic creates the topic if it is not there, and says nothing if it
// already is. This is a convenience for local development: in v4 the topics
// are declared with the rest of the infrastructure, not by the services that
// use them. Auto-creation by the broker is deliberately not relied on — it
// would give whatever partition count the broker defaults to.
func EnsureTopic(ctx context.Context, cfg Config, topic string, partitions int32) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if partitions <= 0 {
		partitions = DefaultPartitions
	}

	cl, err := kgo.NewClient(cfg.baseOptions()...)
	if err != nil {
		return fmt.Errorf("kafka: admin client: %w", err)
	}
	defer cl.Close()

	adm := kadm.NewClient(cl)
	// One broker locally, so one replica is all there is to ask for.
	resp, err := adm.CreateTopics(ctx, partitions, 1, nil, topic)
	if err != nil {
		return fmt.Errorf("kafka: create topic %s: %w", topic, err)
	}
	for _, r := range resp {
		if r.Err != nil && !errors.Is(r.Err, kerr.TopicAlreadyExists) {
			return fmt.Errorf("kafka: create topic %s: %w", r.Topic, r.Err)
		}
	}
	return nil
}

// groupLag reports, per partition, how many records the group has not read
// yet. It is the number to watch: a consumer that is merely slow shows steady
// lag, and one that has stopped shows lag climbing without bound.
func groupLag(ctx context.Context, cl *kgo.Client, topic, group string) (map[int32]int64, error) {
	described, err := kadm.NewClient(cl).Lag(ctx, group)
	if err != nil {
		return nil, fmt.Errorf("kafka: lag for %s: %w", group, err)
	}
	out := make(map[int32]int64)
	for _, g := range described {
		for partition, l := range g.Lag[topic] {
			out[partition] = l.Lag
		}
	}
	return out, nil
}

// DeleteTopic removes a topic and everything on it. It is meant for tests and
// local cleanup: a topic per test run would otherwise accumulate forever, and
// every one of them shows up in the console alongside the real ones.
//
// A topic that is not there is not an error — the point is that it is gone.
func DeleteTopic(ctx context.Context, cfg Config, topics ...string) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if len(topics) == 0 {
		return nil
	}

	cl, err := kgo.NewClient(cfg.baseOptions()...)
	if err != nil {
		return fmt.Errorf("kafka: admin client: %w", err)
	}
	defer cl.Close()

	resp, err := kadm.NewClient(cl).DeleteTopics(ctx, topics...)
	if err != nil {
		return fmt.Errorf("kafka: delete topics %v: %w", topics, err)
	}
	for _, r := range resp {
		if r.Err != nil && !errors.Is(r.Err, kerr.UnknownTopicOrPartition) {
			return fmt.Errorf("kafka: delete topic %s: %w", r.Topic, r.Err)
		}
	}
	return nil
}
