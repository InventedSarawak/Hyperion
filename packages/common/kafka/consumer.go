package kafka

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
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
	// Headers carries the record's headers, so a reader can see why a record
	// was set aside without decoding its value.
	Headers map[string]string
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

	// deadLetter, when set, receives records that exhausted their retries
	// instead of stopping the consumer.
	deadLetter *DeadLetter
	// maxConsecutiveDeadLetters stops the consumer once this many records in
	// a row have been set aside — the signal that the failure is the world,
	// not the records.
	maxConsecutiveDeadLetters int64
	consecutiveDeadLetters    atomic.Int64

	// grace is how long a batch already in hand may keep working after
	// shutdown is asked for.
	grace time.Duration
}

// ConsumerOption customizes a Consumer.
type ConsumerOption func(*consumerSettings)

type consumerSettings struct {
	maxPoll        int
	attempts       int
	backoff        time.Duration
	fromStart      bool
	log            *slog.Logger
	extra          []kgo.Opt
	deadLetter     *DeadLetter
	maxConsecutive int64
	grace          time.Duration
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

// WithDeadLetter sends records that exhaust their retries to another topic and
// commits past them, instead of stopping the consumer.
//
// maxConsecutive bounds how far that goes: once this many records in a row have
// been set aside, the consumer stops anyway. One poisonous record is a record;
// two hundred in a row is the database being down, and quietly moving the whole
// topic into a dead-letter queue would be the worst of both behaviours. Zero
// takes a sensible default.
func WithDeadLetter(dl *DeadLetter, maxConsecutive int) ConsumerOption {
	return func(s *consumerSettings) {
		if dl == nil {
			return
		}
		s.deadLetter = dl
		if maxConsecutive > 0 {
			s.maxConsecutive = int64(maxConsecutive)
		}
	}
}

// WithShutdownGrace gives a batch already being handled this long to finish
// after the context is cancelled.
//
// Without it, Ctrl-C aborts mid-record: the offset is not committed, so nothing
// is lost, but the half-finished record leaves the stores briefly disagreeing
// (written to one, not yet the next) and the whole batch is replayed on the
// next start. Finishing what is in hand and committing it is a cleaner stop and
// a faster restart. Zero takes a sensible default.
func WithShutdownGrace(d time.Duration) ConsumerOption {
	return func(s *consumerSettings) {
		if d > 0 {
			s.grace = d
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
		maxPoll:        500,
		attempts:       5,
		backoff:        time.Second,
		fromStart:      true,
		log:            slog.Default(),
		maxConsecutive: 10,
		grace:          30 * time.Second,
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
		cl:                        cl,
		topic:                     topic,
		group:                     group,
		maxPoll:                   settings.maxPoll,
		attempts:                  settings.attempts,
		backoff:                   settings.backoff,
		log:                       settings.log,
		deadLetter:                settings.deadLetter,
		maxConsecutiveDeadLetters: settings.maxConsecutive,
		grace:                     settings.grace,
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
	if err := ctx.Err(); err != nil && fetches.NumRecords() == 0 {
		// Nothing in hand, and shutdown has been asked for: stop here.
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

	// The batch in hand finishes even if shutdown has been asked for, within a
	// bounded grace period. A cancelled context here would abandon a record
	// half-written — stored in one place and not yet the next — and replay the
	// whole batch on the next start.
	work, release := context.WithTimeout(context.WithoutCancel(ctx), c.grace)
	defer release()

	// Offsets are committed only once every record they cover has been
	// handled. A batch that failed commits nothing, so a restart replays it.
	if err := c.handleBatch(work, fetches, h); err != nil {
		return false, err
	}
	if err := c.cl.CommitUncommittedOffsets(work); err != nil {
		return false, fmt.Errorf("kafka: commit %s/%s: %w", c.topic, c.group, err)
	}

	// Committed what was in hand; now honour the shutdown.
	if err := ctx.Err(); err != nil {
		c.log.Info("finished the batch in hand before stopping",
			"topic", c.topic, "records", fetches.NumRecords())
		return false, err
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
	msg := messageFrom(rec)

	wait := c.backoff
	for attempt := 1; ; attempt++ {
		err := h.Handle(ctx, msg)
		switch {
		case err == nil:
			// A success breaks the run: the limit is about consecutive
			// failures, not a total that creeps up over days of healthy
			// operation.
			c.consecutiveDeadLetters.Store(0)
			return nil
		case errors.Is(err, ErrUnprocessable):
			c.log.Warn("skipping unprocessable record",
				"topic", msg.Topic, "partition", msg.Partition, "offset", msg.Offset,
				"key", msg.Key, "error", err)
			return nil
		case attempt >= c.attempts:
			return c.exhausted(ctx, msg, err, attempt)
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

// exhausted decides what happens to a record that has run out of retries:
// stop the consumer, or set the record aside and carry on.
func (c *Consumer) exhausted(ctx context.Context, msg Message, cause error, attempts int) error {
	failed := fmt.Errorf("kafka: %s partition %d offset %d failed after %d attempts: %w",
		msg.Topic, msg.Partition, msg.Offset, attempts, cause)

	if c.deadLetter == nil {
		return failed
	}

	if err := c.deadLetter.Send(ctx, msg, cause, attempts); err != nil {
		// Nowhere safe to put it. Stopping keeps the record on the topic,
		// uncommitted, which is the only remaining way not to lose it.
		return fmt.Errorf("%w (and the dead-letter topic is unavailable: %w)", failed, err)
	}

	inARow := c.consecutiveDeadLetters.Add(1)
	c.log.Error("record set aside on the dead-letter topic",
		"topic", msg.Topic, "partition", msg.Partition, "offset", msg.Offset,
		"key", msg.Key, "dead_letter_topic", c.deadLetter.Topic(),
		"consecutive", inARow, "error", cause)

	if inARow >= c.maxConsecutiveDeadLetters {
		return fmt.Errorf("kafka: %d records in a row could not be processed; stopping rather than draining %s into %s: %w",
			inARow, c.topic, c.deadLetter.Topic(), cause)
	}
	return nil
}

// messageFrom converts a client record into the type service adapters see.
func messageFrom(rec *kgo.Record) Message {
	headers := make(map[string]string, len(rec.Headers))
	for _, h := range rec.Headers {
		headers[h.Key] = string(h.Value)
	}
	return Message{
		Topic:     rec.Topic,
		Key:       string(rec.Key),
		Value:     rec.Value,
		Partition: rec.Partition,
		Offset:    rec.Offset,
		Timestamp: rec.Timestamp,
		EventType: headers[HeaderEventType],
		Headers:   headers,
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
