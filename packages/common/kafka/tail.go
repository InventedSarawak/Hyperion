package kafka

import (
	"context"
	"errors"
	"fmt"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

// TailOptions controls a tail.
type TailOptions struct {
	// FromStart reads the topic from the beginning rather than following
	// only what arrives next.
	FromStart bool
	// StopAtEnd returns once everything on the topic at the moment of the
	// call has been read, instead of waiting for more. It is what makes
	// reading a topic a command that finishes — without it, "show me the
	// dead-letter topic" hangs forever on a healthy, empty one.
	StopAtEnd bool
	// Limit stops after this many records. Zero reads until StopAtEnd is
	// satisfied, or until the context is cancelled.
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

	// The end offsets as they are now. Reading "to the end" has to mean a
	// fixed point, or a topic still being written to is never finished.
	var ends map[int32]int64
	if opts.StopAtEnd {
		ends, err = endOffsets(ctx, cl, topic)
		if err != nil {
			return err
		}
		if remaining(ends) == 0 {
			return nil
		}
	}

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
			fnErr = fn(messageFrom(rec))
			seen++
		})
		if fnErr != nil {
			return fnErr
		}
		if opts.Limit > 0 && seen >= opts.Limit {
			return nil
		}
		if opts.StopAtEnd {
			fetches.EachPartition(func(p kgo.FetchTopicPartition) {
				for _, rec := range p.Records {
					if end, ok := ends[rec.Partition]; ok && rec.Offset >= end-1 {
						delete(ends, rec.Partition)
					}
				}
			})
			if remaining(ends) == 0 {
				return nil
			}
		}
	}
}

// endOffsets is the high-water mark of each partition that holds anything.
// Partitions that are empty are left out, so they never keep a tail waiting.
func endOffsets(ctx context.Context, cl *kgo.Client, topic string) (map[int32]int64, error) {
	listed, err := kadm.NewClient(cl).ListEndOffsets(ctx, topic)
	if err != nil {
		return nil, fmt.Errorf("kafka: end offsets for %s: %w", topic, err)
	}

	ends := make(map[int32]int64)
	listed.Each(func(o kadm.ListedOffset) {
		if o.Err == nil && o.Offset > 0 {
			ends[o.Partition] = o.Offset
		}
	})
	return ends, nil
}

// remaining counts the partitions still short of their end offset.
func remaining(ends map[int32]int64) int { return len(ends) }
