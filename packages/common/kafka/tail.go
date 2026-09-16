package kafka

import (
	"context"
	"errors"
	"fmt"

	"github.com/twmb/franz-go/pkg/kgo"
)

// TailOptions controls a tail.
type TailOptions struct {
	// FromStart reads the topic from the beginning rather than following
	// only what arrives next.
	FromStart bool
	// Limit stops after this many records. Zero follows until the context is
	// cancelled.
	Limit int
}

// Tail reads a topic without joining a consumer group, calling fn for each
// record. It commits nothing and is invisible to the groups that do — so
// looking at a topic never costs a running consumer its place.
//
// This is a debugging tool, not a way to process events: values on the topic
// are binary protobuf, and the caller is expected to decode them (Message.Into)
// and print them.
func Tail(ctx context.Context, cfg Config, topic string, opts TailOptions, fn func(Message) error) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if topic == "" {
		return fmt.Errorf("kafka: tail needs a topic")
	}

	reset := kgo.NewOffset().AtEnd()
	if opts.FromStart {
		reset = kgo.NewOffset().AtStart()
	}

	options := append(cfg.baseOptions(),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(reset),
		kgo.FetchMaxPartitionBytes(MaxRecordBytes),
	)
	cl, err := kgo.NewClient(options...)
	if err != nil {
		return fmt.Errorf("kafka: tail client: %w", err)
	}
	defer cl.Close()

	seen := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		fetches := cl.PollRecords(ctx, 100)
		if fetches.IsClientClosed() {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, fe := range fetches.Errors() {
			if !errors.Is(fe.Err, context.Canceled) {
				return fmt.Errorf("kafka: tail %s: %w", topic, fe.Err)
			}
		}

		var fnErr error
		fetches.EachRecord(func(rec *kgo.Record) {
			if fnErr != nil || (opts.Limit > 0 && seen >= opts.Limit) {
				return
			}
			fnErr = fn(Message{
				Topic:     rec.Topic,
				Key:       string(rec.Key),
				Value:     rec.Value,
				Partition: rec.Partition,
				Offset:    rec.Offset,
				Timestamp: rec.Timestamp,
				EventType: Header(rec, HeaderEventType),
			})
			seen++
		})
		if fnErr != nil {
			return fnErr
		}
		if opts.Limit > 0 && seen >= opts.Limit {
			return nil
		}
	}
}
