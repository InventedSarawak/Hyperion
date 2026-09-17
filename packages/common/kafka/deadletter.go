package kafka

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// Dead-letter headers. The original record's value is forwarded byte for byte,
// so everything about *why* it is here lives in headers — which also means a
// record can be replayed onto the main topic unchanged.
const (
	HeaderDLQError     = "dlq-error"
	HeaderDLQTopic     = "dlq-origin-topic"
	HeaderDLQPartition = "dlq-origin-partition"
	HeaderDLQOffset    = "dlq-origin-offset"
	HeaderDLQAttempts  = "dlq-attempts"
	HeaderDLQAt        = "dlq-at"
)

// DeadLetterSuffix names the dead-letter topic for a topic that does not say.
const DeadLetterSuffix = ".dlq"

// DeadLetter is where records go when they cannot be processed.
//
// It exists to separate two failures a consumer otherwise cannot tell apart.
// One record that will never succeed should not block every record behind it
// on its partition, forever. But a database that is down makes *every* record
// fail, and draining the whole topic into a dead-letter queue would turn an
// outage into a silent data migration. So the consumer pairs this with a limit
// on consecutive failures: isolated ones are set aside, a run of them stops the
// consumer instead.
type DeadLetter struct {
	producer *Producer
	topic    string
	log      *slog.Logger
}

// NewDeadLetter connects a producer for the dead-letter topic and ensures it
// exists. An empty topic derives one from source by appending ".dlq".
func NewDeadLetter(ctx context.Context, cfg Config, source, topic string, log *slog.Logger) (*DeadLetter, error) {
	if log == nil {
		log = slog.Default()
	}
	if topic == "" {
		if source == "" {
			return nil, fmt.Errorf("kafka: dead-letter needs a topic")
		}
		topic = source + DeadLetterSuffix
	}

	// One partition is enough: this topic should be empty, and a human reads
	// it in order when it is not.
	if err := EnsureTopic(ctx, cfg, topic, 1); err != nil {
		return nil, fmt.Errorf("kafka: dead-letter topic: %w", err)
	}
	producer, err := NewProducer(cfg, topic, WithProducerLogger(log))
	if err != nil {
		return nil, fmt.Errorf("kafka: dead-letter producer: %w", err)
	}
	return &DeadLetter{producer: producer, topic: topic, log: log}, nil
}

// Topic reports where dead-lettered records go.
func (d *DeadLetter) Topic() string { return d.topic }

// Send forwards a record that could not be processed, and blocks until the
// broker has it.
//
// The flush is the point: the consumer commits past this record immediately
// afterwards, so if the record were still sitting in a producer buffer when
// the process died, it would be gone from both topics at once.
func (d *DeadLetter) Send(ctx context.Context, msg Message, cause error, attempts int) error {
	headers := []kgo.RecordHeader{
		{Key: HeaderDLQError, Value: []byte(cause.Error())},
		{Key: HeaderDLQTopic, Value: []byte(msg.Topic)},
		{Key: HeaderDLQPartition, Value: []byte(strconv.FormatInt(int64(msg.Partition), 10))},
		{Key: HeaderDLQOffset, Value: []byte(strconv.FormatInt(msg.Offset, 10))},
		{Key: HeaderDLQAttempts, Value: []byte(strconv.Itoa(attempts))},
		{Key: HeaderDLQAt, Value: []byte(time.Now().UTC().Format(time.RFC3339))},
	}
	if msg.EventType != "" {
		headers = append(headers, kgo.RecordHeader{Key: HeaderEventType, Value: []byte(msg.EventType)})
		headers = append(headers, kgo.RecordHeader{Key: HeaderContentType, Value: []byte(ContentTypeProtobuf)})
	}

	if err := d.producer.publishRaw(ctx, msg.Key, msg.Value, headers); err != nil {
		return err
	}
	return d.producer.Flush(ctx)
}

// Close flushes and disconnects.
func (d *DeadLetter) Close() error { return d.producer.Close() }
