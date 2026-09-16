package kafka

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"
)

// ErrUnprocessable is how a handler says a record can never succeed, however
// many times it is tried — a value that will not decode, a field that will
// never be valid. Such a record is logged, skipped and committed past.
//
// Every other error is treated as the world being temporarily broken (the
// database is down, the index is refusing writes) and is retried; when the
// retries run out the consumer stops with that error and commits nothing, so
// a restart replays from the last committed offset. The distinction matters:
// skipping an infrastructure failure loses data silently, and retrying a
// poison record forever wedges the partition behind it.
var ErrUnprocessable = errors.New("kafka: record cannot be processed")

// Message is one record, in terms that keep franz-go out of service code.
// Only this package imports the Kafka client; an adapter depends on this type.
type Message struct {
	Topic     string
	Key       string
	Value     []byte
	Partition int32
	Offset    int64
	Timestamp time.Time
	EventType string
}

// Into decodes the record value into dst.
func (m Message) Into(dst proto.Message) error {
	if m.EventType != "" && m.EventType != MessageName(dst) {
		return fmt.Errorf("%w: record on %s is %s, want %s",
			ErrUnprocessable, m.Topic, m.EventType, MessageName(dst))
	}
	if err := Decode(m.Value, dst); err != nil {
		return fmt.Errorf("%w: %s", ErrUnprocessable, err)
	}
	return nil
}

// Handler processes one record. Returning nil means the record is done with
// and its offset may be committed.
type Handler interface {
	Handle(ctx context.Context, msg Message) error
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, msg Message) error

// Handle calls f.
func (f HandlerFunc) Handle(ctx context.Context, msg Message) error { return f(ctx, msg) }

// Consumer reads one topic as part of a consumer group.
//
// The group is what makes this horizontal: Kafka assigns each partition to
// exactly one member, so running a second copy of the service halves the
// partitions each one owns, with no coordination written by us.
type Consumer struct {
	cl       *kgo.Client
	topic    string
	group    string
	maxPoll  int
	attempts int
	backoff  time.Duration
	log      *slog.Logger
}

// ConsumerOption customizes a Consumer.
type ConsumerOption func(*consumerSettings)

type consumerSettings struct {
	maxPoll   int
	attempts  int
	backoff   time.Duration
	fromStart bool
	log       *slog.Logger
	extra     []kgo.Opt
}

// WithMaxPollRecords caps how many records one poll returns.
func WithMaxPollRecords(n int) ConsumerOption {
	return func(s *consumerSettings) {
		if n > 0 {
			s.maxPoll = n
		}
	}
}

// WithRetries sets how many times a record is retried before the consumer
// gives up and stops, and the delay between attempts (doubling each time).
func WithRetries(attempts int, backoff time.Duration) ConsumerOption {
	return func(s *consumerSettings) {
		if attempts > 0 {
			s.attempts = attempts
		}
		if backoff > 0 {
			s.backoff = backoff
		}
	}
}

// WithFromLatest starts a group with no committed offsets at the end of the
// topic instead of the beginning. The default is the beginning: a new or
// rebuilt consumer should see the history the topic still holds, not silently
// skip it.
func WithFromLatest() ConsumerOption {
	return func(s *consumerSettings) { s.fromStart = false }
}

// WithConsumerLogger sends the consumer's own logging somewhere other than the
// default logger.
func WithConsumerLogger(l *slog.Logger) ConsumerOption {
	return func(s *consumerSettings) {
		if l != nil {
			s.log = l
		}
	}
}

// WithConsumerOptions passes raw franz-go options through.
func WithConsumerOptions(opts ...kgo.Opt) ConsumerOption {
	return func(s *consumerSettings) { s.extra = append(s.extra, opts...) }
}

// NewConsumer joins the group and returns a consumer for one topic.
func NewConsumer(cfg Config, topic, group string, opts ...ConsumerOption) (*Consumer, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if topic == "" || group == "" {
		return nil, fmt.Errorf("kafka: consumer needs a topic and a group")
	}

	settings := consumerSettings{
		maxPoll:   500,
		attempts:  5,
		backoff:   time.Second,
		fromStart: true,
		log:       slog.Default(),
	}
	for _, opt := range opts {
		opt(&settings)
	}

	reset := kgo.NewOffset().AtEnd()
	if settings.fromStart {
		reset = kgo.NewOffset().AtStart()
	}

	options := append(cfg.baseOptions(),
		kgo.ConsumeTopics(topic),
		kgo.ConsumerGroup(group),
		kgo.ConsumeResetOffset(reset),
		// Offsets are committed by us, after the records they cover have been
		// handled. Automatic commits would acknowledge records on a timer,
		// which acknowledges work that has not happened yet.
		kgo.DisableAutoCommit(),
		// Hold off a group rebalance until the batch in hand is processed and
		// committed, so a partition is never reassigned mid-batch and its
		// records redelivered to two members at once.
		kgo.BlockRebalanceOnPoll(),
		kgo.FetchMaxPartitionBytes(MaxRecordBytes),
	)
	options = append(options, settings.extra...)

	cl, err := kgo.NewClient(options...)
	if err != nil {
		return nil, fmt.Errorf("kafka: consumer client: %w", err)
	}
	return &Consumer{
		cl:       cl,
		topic:    topic,
		group:    group,
		maxPoll:  settings.maxPoll,
		attempts: settings.attempts,
		backoff:  settings.backoff,
		log:      settings.log,
	}, nil
}

// Run consumes until ctx is cancelled or a record fails past its retries.
//
// Records are handled one partition at a time in parallel, and serially within
// a partition. That is the ordering contract the producer's key buys: all
// reports of one finding share a key, so they share a partition, so they are
// merged in the order they arrived rather than racing each other.
func (c *Consumer) Run(ctx context.Context, h Handler) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		closed, err := c.pollOnce(ctx, h)
		if err != nil {
			return err
		}
		if closed {
			return nil
		}
	}
}

// pollOnce fetches one batch, handles it and commits the offsets it covers.
// It reports whether the client has been closed underneath us.
func (c *Consumer) pollOnce(ctx context.Context, h Handler) (bool, error) {
	fetches := c.cl.PollRecords(ctx, c.maxPoll)

	// A poll blocks group rebalancing until it is explicitly allowed again
	// (kgo.BlockRebalanceOnPoll, set in NewConsumer). Every path out of this
	// function must re-allow it — including a cancelled context and a failed
	// commit — or the client is left wedged, with Close waiting on a
	// rebalance that can never happen.
	defer c.cl.AllowRebalance()

	if fetches.IsClientClosed() {
		return true, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	for _, fe := range fetches.Errors() {
		// Fetch errors are the cluster being unsettled — a leader moving, a
		// broker restarting. The client recovers on its own; log and carry on
		// rather than tearing the service down.
		if !errors.Is(fe.Err, context.Canceled) {
			c.log.Warn("kafka fetch error", "topic", fe.Topic, "partition", fe.Partition, "error", fe.Err)
		}
	}

	// Offsets are committed only once every record they cover has been
	// handled. A batch that failed commits nothing, so a restart replays it.
	if err := c.handleBatch(ctx, fetches, h); err != nil {
		return false, err
	}
	if err := c.cl.CommitUncommittedOffsets(ctx); err != nil {
		return false, fmt.Errorf("kafka: commit %s/%s: %w", c.topic, c.group, err)
	}
	return false, nil
}

// handleBatch processes every partition in the fetch, in parallel, and
// returns the first failure that survived its retries.
func (c *Consumer) handleBatch(ctx context.Context, fetches kgo.Fetches, h Handler) error {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	fail := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if firstErr == nil {
			firstErr = err
		}
	}

	fetches.EachPartition(func(p kgo.FetchTopicPartition) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, rec := range p.Records {
				if err := ctx.Err(); err != nil {
					fail(err)
					return
				}
				if err := c.handleRecord(ctx, h, rec); err != nil {
					fail(err)
					return // stop this partition: its later records must not overtake
				}
			}
		}()
	})
	wg.Wait()
	return firstErr
}

// handleRecord applies the retry policy to a single record.
func (c *Consumer) handleRecord(ctx context.Context, h Handler, rec *kgo.Record) error {
	msg := Message{
		Topic:     rec.Topic,
		Key:       string(rec.Key),
		Value:     rec.Value,
		Partition: rec.Partition,
		Offset:    rec.Offset,
		Timestamp: rec.Timestamp,
		EventType: Header(rec, HeaderEventType),
	}

	wait := c.backoff
	for attempt := 1; ; attempt++ {
		err := h.Handle(ctx, msg)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, ErrUnprocessable):
			c.log.Warn("skipping unprocessable record",
				"topic", msg.Topic, "partition", msg.Partition, "offset", msg.Offset,
				"key", msg.Key, "error", err)
			return nil
		case attempt >= c.attempts:
			return fmt.Errorf("kafka: %s partition %d offset %d failed after %d attempts: %w",
				msg.Topic, msg.Partition, msg.Offset, attempt, err)
		}

		c.log.Warn("retrying record",
			"topic", msg.Topic, "partition", msg.Partition, "offset", msg.Offset,
			"attempt", attempt, "in", wait, "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait *= 2
	}
}

// Lag reports how far behind the group is on each partition of the topic.
func (c *Consumer) Lag(ctx context.Context) (map[int32]int64, error) {
	return groupLag(ctx, c.cl, c.topic, c.group)
}

// Close leaves the group and releases the connection. Leaving cleanly means
// the remaining members are reassigned immediately rather than after the
// session timeout expires.
func (c *Consumer) Close() {
	c.cl.Close()
}
