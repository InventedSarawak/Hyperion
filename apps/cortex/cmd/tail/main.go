// Command tail prints what is on the signal topic, decoded.
//
// Records are binary protobuf, so a generic Kafka console consumer shows only
// bytes. This reads the same contract cortex reads and prints each event as
// protojson, which is the readable form of exactly what was published.
//
//	task topic:tail -- -limit 5 -from-start
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
	flag.Parse()

	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	marshaler := protojson.MarshalOptions{Multiline: !*keysOnly, Indent: "  "}
	err := kafka.Tail(ctx,
		kafka.Config{Brokers: cfg.Kafka.Brokers, ClientID: "cortex-tail"},
		cfg.Kafka.Topic,
		kafka.TailOptions{FromStart: *fromStart, Limit: *limit},
		func(msg kafka.Message) error {
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

	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "tail:", err)
		os.Exit(1)
	}
}
