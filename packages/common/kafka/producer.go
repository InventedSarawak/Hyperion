package kafka

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"
)

// MaxRecordBytes is the largest record Hyperion produces or accepts. The Kafka
// default is 1MiB, which a long advisory can exceed: some NVD and OSV records
// carry hundreds of references and a description of several thousand words.
// The broker is configured to match in deploy/docker-compose.yml — a producer
// limit above the broker's would only turn a local error into a remote one.
const MaxRecordBytes = 5 << 20

// Producer publishes contract messages to one topic.
//
// Publishing is asynchronous, and that choice has a consequence the caller
// must respect: a nil from Publish means the record was accepted into the
// client's buffer, NOT that the broker stored it. Batching is where Kafka's
// throughput comes from — waiting for an acknowledgement per record turns a
// backfill of several hundred thousand findings into hours of round trips —
// but it means anything that records progress (a watermark, a checkpoint,
// "this poll succeeded") must call Flush first and check its error.
type Producer struct {
	cl    *kgo.Client
	topic string
	log   *slog.Logger

	mu  sync.Mutex
	err error // first delivery failure since the last Flush
}

// ProducerOption customizes a Producer.
type ProducerOption func(*producerSettings)

type producerSettings struct {
	deliveryTimeout time.Duration
	log             *slog.Logger
	extra           []kgo.Opt
}

// WithDeliveryTimeout bounds how long the client keeps retrying a record
// before giving up on it. Without a bound, a broker that is simply down means
// Publish never returns an error — it buffers until it blocks, and the service
// looks healthy while nothing is being stored.
func WithDeliveryTimeout(d time.Duration) ProducerOption {
	return func(s *producerSettings) {
		if d > 0 {
			s.deliveryTimeout = d
		}
	}
}

// WithProducerLogger sends the producer's own logging somewhere other than the
// default logger.
func WithProducerLogger(l *slog.Logger) ProducerOption {
	return func(s *producerSettings) {
		if l != nil {
			s.log = l
		}
	}
}

// WithProducerOptions passes raw franz-go options through, for the cases this
// wrapper deliberately does not model.
func WithProducerOptions(opts ...kgo.Opt) ProducerOption {
	return func(s *producerSettings) { s.extra = append(s.extra, opts...) }
}

// NewProducer connects to the cluster and returns a producer for one topic.
func NewProducer(cfg Config, topic string, opts ...ProducerOption) (*Producer, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if topic == "" {
		return nil, fmt.Errorf("kafka: producer needs a topic")
	}

	settings := producerSettings{deliveryTimeout: time.Minute, log: slog.Default()}
	for _, opt := range opts {
		opt(&settings)
	}

	options := append(cfg.baseOptions(),
		kgo.DefaultProduceTopic(topic),
		// Idempotent production is franz-go's default and is left on: a
		// retried record is deduplicated by the broker using a sequence
		// number, so an ordinary network retry cannot silently duplicate a
		// finding. It also pins acks to all in-sync replicas.
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProducerBatchMaxBytes(MaxRecordBytes),
		// lz4 costs little CPU and roughly halves what a backfill writes to
		// disk; NoCompression is the fallback if a broker refuses lz4.
		kgo.ProducerBatchCompression(kgo.Lz4Compression(), kgo.NoCompression()),
		kgo.RecordDeliveryTimeout(settings.deliveryTimeout),
	)
	options = append(options, settings.extra...)

	cl, err := kgo.NewClient(options...)
	if err != nil {
		return nil, fmt.Errorf("kafka: producer client: %w", err)
	}
	return &Producer{cl: cl, topic: topic, log: settings.log}, nil
}

// Publish queues a message for the topic under the given key.
//
// The key decides the partition, and a partition is the only ordering Kafka
// guarantees — so the key must be whatever identity the consumer needs to see
// in order. For findings that is the normalized id: every report of one CVE
// lands on one partition, read by one consumer, in the order it was produced.
// An empty key is allowed and spreads records round-robin; use it only when
// the records are genuinely independent.
func (p *Producer) Publish(ctx context.Context, key string, m proto.Message) error {
	value, err := Encode(m)
	if err != nil {
		return err
	}
	if len(value) > MaxRecordBytes {
		return fmt.Errorf("kafka: record for key %q is %d bytes, over the %d limit", key, len(value), MaxRecordBytes)
	}

	rec := &kgo.Record{
		Topic:   p.topic,
		Key:     []byte(key),
		Value:   value,
		Headers: headersFor(m),
	}

	p.cl.Produce(ctx, rec, func(r *kgo.Record, err error) {
		if err == nil {
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.err == nil {
			p.err = fmt.Errorf("kafka: deliver key %q to %s: %w", string(r.Key), r.Topic, err)
		}
		p.log.Error("kafka delivery failed", "topic", r.Topic, "key", string(r.Key), "error", err)
	})

	// Surface an earlier delivery failure now rather than at Flush: a caller
	// publishing thousands of records should stop as soon as the broker has
	// started refusing them.
	return p.takeErr()
}

// Flush blocks until every record published so far has been acknowledged by
// the broker, and reports the first delivery failure if there was one.
//
// Call it before recording that the work succeeded. It clears the remembered
// error, so a failed batch does not poison every later one — the caller is
// expected not to advance its watermark, and to produce those records again.
func (p *Producer) Flush(ctx context.Context) error {
	if err := p.cl.Flush(ctx); err != nil {
		return fmt.Errorf("kafka: flush %s: %w", p.topic, err)
	}
	return p.takeErr()
}

// Close flushes what is buffered and releases the connection.
func (p *Producer) Close() error {
	err := p.Flush(context.Background())
	p.cl.Close()
	return err
}

// Ping checks the cluster is reachable, for a startup or health probe.
func (p *Producer) Ping(ctx context.Context) error {
	if err := p.cl.Ping(ctx); err != nil {
		return fmt.Errorf("kafka: ping %v: %w", p.cl.SeedBrokers(), err)
	}
	return nil
}

// takeErr returns and clears the remembered delivery failure.
func (p *Producer) takeErr() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	err := p.err
	p.err = nil
	return err
}
