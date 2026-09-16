// Command tail prints what is on the signal topic, decoded.
//
// Records are binary protobuf, so a generic Kafka console consumer shows only
// bytes. This reads the same contract cortex reads and prints each event as
// protojson, which is the readable form of exactly what was published.
//
//	task topic:tail -- -limit 5 -from-start
//
// It also reads the dead-letter topic, and can put those records back:
//
//	task topic:dlq                  # what failed, and why
//	task topic:dlq -- -replay       # send them back to the signal topic
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/inventedsarawak/hyperion/packages/common/kafka"
	eventsv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/events/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/platform/config"
)

func main() {
	fromStart := flag.Bool("from-start", false,
		"read the topic from the beginning instead of following what arrives next")
	limit := flag.Int("limit", 0, "stop after this many records (0 follows until interrupted)")
	keysOnly := flag.Bool("keys", false, "print one line per record — key, partition, offset — instead of the full event")
	topic := flag.String("topic", "", "topic to read (default: the signal topic; \"dlq\" reads its dead-letter topic)")
	replayTo := flag.String("replay-to", "", "republish every record read to this topic, unchanged")
	replay := flag.Bool("replay", false, "shorthand for -topic dlq -replay-to <the signal topic>")
	follow := flag.Bool("follow", false, "with -from-start, keep waiting for new records instead of stopping once caught up")
	flag.Parse()

	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	deadLetterTopic := cfg.Kafka.DeadLetterTopic
	if deadLetterTopic == "" {
		deadLetterTopic = cfg.Kafka.Topic + kafka.DeadLetterSuffix
	}

	read := cfg.Kafka.Topic
	switch {
	case *replay:
		read, *replayTo = deadLetterTopic, cfg.Kafka.Topic
	case *topic == "dlq":
		read = deadLetterTopic
	case *topic != "":
		read = *topic
	}

	clientCfg := kafka.Config{Brokers: cfg.Kafka.Brokers, ClientID: "cortex-tail"}

	// Replaying reads from the start: the point is to drain what is there,
	// not to follow what arrives next.
	fromAll := *fromStart || *replayTo != ""

	// Reading a topic from the beginning is a question with an answer, so it
	// finishes by default — otherwise `task topic:dlq` on a healthy, empty
	// dead-letter topic would hang waiting for a failure to happen.
	stopAtEnd := fromAll && !*follow

	var producer *kafka.Producer
	if *replayTo != "" {
		var err error
		producer, err = kafka.NewProducer(clientCfg, *replayTo)
		if err != nil {
			fmt.Fprintln(os.Stderr, "tail:", err)
			os.Exit(1)
		}
		defer func() {
			// Flush before exit, or the last records replayed are still in a
			// buffer when the process goes away.
			if err := producer.Close(); err != nil {
				fmt.Fprintln(os.Stderr, "tail: replay did not flush cleanly:", err)
				os.Exit(1)
			}
		}()
		fmt.Fprintf(os.Stderr, "replaying %s -> %s\n", read, *replayTo)
	}

	marshaler := protojson.MarshalOptions{Multiline: !*keysOnly, Indent: "  "}
	replayed := 0

	err := kafka.Tail(ctx, clientCfg, read,
		kafka.TailOptions{FromStart: fromAll, StopAtEnd: stopAtEnd, Limit: *limit},
		func(msg kafka.Message) error {
			if producer != nil {
				// Republished exactly as it arrived, so whatever failed gets
				// another attempt against the same bytes.
				if err := producer.Publish(ctx, msg.Key, asMessage(msg)); err != nil {
					return err
				}
				replayed++
				fmt.Printf("replayed %s (was %s partition %d offset %d)\n",
					msg.Key, msg.Headers[kafka.HeaderDLQTopic], msg.Partition, msg.Offset)
				return nil
			}

			// Why a record was set aside is in its headers, and is the first
			// thing worth seeing when reading a dead-letter topic.
			if reason := msg.Headers[kafka.HeaderDLQError]; reason != "" {
				fmt.Printf("// FAILED %s after %s attempts at %s: %s\n",
					msg.Key, msg.Headers[kafka.HeaderDLQAttempts], msg.Headers[kafka.HeaderDLQAt], reason)
			}

			if *keysOnly {
				fmt.Printf("%s\tpartition=%d\toffset=%d\t%d bytes\n",
					msg.Key, msg.Partition, msg.Offset, len(msg.Value))
				return nil
			}

			var evt eventsv1.SignalDiscovered
			if err := msg.Into(&evt); err != nil {
				fmt.Fprintf(os.Stderr, "partition=%d offset=%d: %v\n", msg.Partition, msg.Offset, err)
				return nil // a record we cannot read is worth reporting, not worth stopping for
			}
			b, err := marshaler.Marshal(&evt)
			if err != nil {
				return err
			}
			fmt.Printf("// partition=%d offset=%d key=%s\n%s\n", msg.Partition, msg.Offset, msg.Key, b)
			return nil
		})

	if producer != nil {
		fmt.Fprintf(os.Stderr, "replayed %d records\n", replayed)
	}

	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "tail:", err)
		os.Exit(1)
	}
}

// asMessage decodes a record so it can be republished through the typed
// producer. The bytes are protobuf either way; going through the contract type
// keeps the headers the producer writes consistent with every other publisher.
func asMessage(msg kafka.Message) *eventsv1.SignalDiscovered {
	var evt eventsv1.SignalDiscovered
	if err := msg.Into(&evt); err != nil {
		// A record that will not decode cannot be replayed usefully, but it
		// still round-trips: an empty event carries the failure forward rather
		// than silently dropping it.
		fmt.Fprintf(os.Stderr, "replay: %s does not decode: %v\n", msg.Key, err)
	}
	return &evt
}
