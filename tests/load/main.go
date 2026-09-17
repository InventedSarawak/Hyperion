// Command load measures what the event backbone can carry.
//
// By default it creates a throwaway topic, publishes synthetic findings to it
// at a target rate, consumes them back in a consumer group, and reports what it
// measured — then deletes the topic. Nothing it does by default touches the
// signal topic, the databases, or anything cortex is reading.
//
//	task loadtest                       # 10k findings at 1000/s, transport only
//	task loadtest -- -count 50000 -rate 5000
//	task loadtest -- -topic hyperion.signals.v1 -no-consume   # drive the real pipeline
//
// What the default number proves and does not: it measures the broker and the
// client — produce, fetch, decode, commit — and not cortex's ingest, which is
// bounded by Postgres, Elasticsearch and Neo4j writes. To measure that, point
// it at the signal topic with -no-consume and watch `task topic:lag` drain.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	eventsv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/events/v1"

	"github.com/inventedsarawak/hyperion/packages/common/kafka"
)

func main() {
	brokers := flag.String("brokers", kafka.DefaultBroker, "comma-separated broker list")
	count := flag.Int("count", 10_000, "how many findings to publish")
	rate := flag.Int("rate", 1000, "target findings per second (0 for as fast as possible)")
	topic := flag.String("topic", "", "publish to this topic instead of a throwaway one")
	noConsume := flag.Bool("no-consume", false, "publish only, and leave the records for whoever is already consuming")
	partitions := flag.Int("partitions", kafka.DefaultPartitions, "partitions for the throwaway topic")
	flag.Parse()

	cfg := kafka.Config{Brokers: kafka.ParseBrokers(*brokers), ClientID: "hyperion-load"}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// A throwaway topic unless told otherwise: a load test that quietly filled
	// the real one with fabricated CVEs would be a data problem, not a
	// measurement.
	scratch := *topic == ""
	target := *topic
	if scratch {
		target = fmt.Sprintf("hyperion.loadtest.%d", time.Now().UnixNano())
	}

	if err := kafka.EnsureTopic(ctx, cfg, target, int32(*partitions)); err != nil {
		fail(err)
	}
	if scratch {
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := kafka.DeleteTopic(cleanup, cfg, target); err != nil {
				fmt.Fprintln(os.Stderr, "load: could not remove the throwaway topic:", err)
			}
		}()
	}

	fmt.Printf("topic      %s (%d partitions)\n", target, *partitions)
	fmt.Printf("target     %d findings at %s\n", *count, rateLabel(*rate))
	if !scratch {
		fmt.Printf("WARNING    publishing to an existing topic; whoever consumes it will ingest these\n")
	}
	fmt.Println()

	// Start consuming before producing, so the measurement covers the whole
	// path rather than a drain of records already at rest.
	var (
		consumed   atomic.Int64
		latencySum atomic.Int64
		latencyMax atomic.Int64
		firstAt    atomic.Int64 // unix nanos of the first record consumed
		lastAt     atomic.Int64 // and of the most recent
		warm       = make(chan struct{})
		done       = make(chan struct{})
		wg         sync.WaitGroup
	)

	consumeCtx, stopConsume := context.WithCancel(ctx)
	defer stopConsume()

	if !*noConsume {
		group := fmt.Sprintf("load-%d", time.Now().UnixNano())
		c, err := kafka.NewConsumer(cfg, target, group, kafka.WithMaxPollRecords(1000))
		if err != nil {
			fail(err)
		}
		defer c.Close()

		var warmOnce, doneOnce sync.Once
		wg.Add(1)
		go func() {
			defer wg.Done()
			handler := kafka.HandlerFunc(func(_ context.Context, msg kafka.Message) error {
				var evt eventsv1.SignalDiscovered
				if err := msg.Into(&evt); err != nil {
					return err
				}

				// The warm-up record. Everything before this is the consumer
				// group forming, which is startup cost rather than throughput
				// — counting it would make a run look worse the faster it is.
				if evt.GetSignalId() == warmupID {
					warmOnce.Do(func() { close(warm) })
					return nil
				}

				now := time.Now()
				lastAt.Store(now.UnixNano())
				firstAt.CompareAndSwap(0, now.UnixNano())

				// The publish time travels in the event, so this is the real
				// end-to-end latency: produced, acknowledged, fetched, decoded.
				if ts := evt.GetDiscoveredAt(); ts != nil {
					took := now.Sub(ts.AsTime()).Microseconds()
					latencySum.Add(took)
					for {
						current := latencyMax.Load()
						if took <= current || latencyMax.CompareAndSwap(current, took) {
							break
						}
					}
				}
				if consumed.Add(1) >= int64(*count) {
					doneOnce.Do(func() { close(done) })
				}
				return nil
			})
			_ = c.Run(consumeCtx, handler)
		}()

		// Wait for the group to be reading before the clock starts.
		fmt.Print("waiting for the consumer group to form... ")
		if err := warmUp(ctx, cfg, target, warm); err != nil {
			fail(err)
		}
		fmt.Println("ready")
	}

	producer, err := kafka.NewProducer(cfg, target)
	if err != nil {
		fail(err)
	}
	defer producer.Close()

	published, produceTook, err := publish(ctx, producer, *count, *rate)
	if err != nil {
		fail(err)
	}

	paced := ""
	if *rate > 0 {
		paced = fmt.Sprintf("  (paced at %d/s; use -rate 0 to find the ceiling)", *rate)
	}
	report("produced", published, produceTook, paced)

	if *noConsume {
		fmt.Println("\nnot consuming: watch `task topic:lag` to see what drains it")
		return
	}

	select {
	case <-done:
	case <-ctx.Done():
	case <-time.After(2 * time.Minute):
		fmt.Fprintln(os.Stderr, "\nload: gave up waiting for the consumer")
	}

	stopConsume()
	wg.Wait()

	n := consumed.Load()
	// Measured between the first and last record actually consumed. Timing
	// from the end of publishing would measure only the tail: the consumer
	// keeps pace while producing, so most records are through before then.
	consumeTook := time.Duration(lastAt.Load() - firstAt.Load())
	report("consumed", int(n), consumeTook, "")
	if n > 0 {
		fmt.Printf("latency    mean %s, max %s (publish to decode)\n",
			(time.Duration(latencySum.Load()/n) * time.Microsecond).Round(time.Millisecond),
			(time.Duration(latencyMax.Load()) * time.Microsecond).Round(time.Millisecond))
	}
}

// warmupID names the record that proves the consumer group is reading.
const warmupID = "load:warmup"

// warmUp publishes one record and waits until the consumer sees it, so the
// group's join does not count as throughput.
func warmUp(ctx context.Context, cfg kafka.Config, topic string, ready <-chan struct{}) error {
	p, err := kafka.NewProducer(cfg, topic)
	if err != nil {
		return err
	}
	defer p.Close()

	deadline := time.After(90 * time.Second)
	for {
		evt := synthetic(0)
		evt.SignalId = warmupID
		if err := p.Publish(ctx, "warmup", evt); err != nil {
			return err
		}
		if err := p.Flush(ctx); err != nil {
			return err
		}

		select {
		case <-ready:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("load: the consumer group did not start reading")
		case <-time.After(time.Second):
			// Publish another: a group that joined after the first was written
			// may be starting from a point past it.
		}
	}
}

// publish sends count findings, paced to rate, and reports how long it took
// for the broker to acknowledge all of them.
func publish(ctx context.Context, p *kafka.Producer, count, rate int) (int, time.Duration, error) {
	started := time.Now()

	var pacer <-chan time.Time
	if rate > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(rate))
		defer ticker.Stop()
		pacer = ticker.C
	}

	for i := range count {
		if pacer != nil {
			select {
			case <-pacer:
			case <-ctx.Done():
				return i, time.Since(started), nil
			}
		}
		if err := p.Publish(ctx, findingID(i), synthetic(i)); err != nil {
			return i, time.Since(started), err
		}
	}

	// Not done until the broker has them: Publish only buffers.
	if err := p.Flush(ctx); err != nil {
		return count, time.Since(started), err
	}
	return count, time.Since(started), nil
}

// findingID keys the record. Spreading ids across the keyspace is deliberate:
// one key would put every record on one partition and measure a single lane.
func findingID(i int) string { return fmt.Sprintf("CVE-9000-%06d", i) }

// synthetic builds a finding about the size of a real one: a paragraph of
// description, a handful of references, a score and an affected package.
func synthetic(i int) *eventsv1.SignalDiscovered {
	id := findingID(i)
	return &eventsv1.SignalDiscovered{
		SignalId: "load:" + id,
		Source:   eventsv1.SourceKind_SOURCE_KIND_NVD,
		Vulnerability: &commonv1.Vulnerability{
			CveId:       id,
			Title:       "Synthetic finding for load measurement " + id,
			Description: strings.Repeat("A representative advisory description. ", 12),
			Kind:        commonv1.FindingKind_FINDING_KIND_VULNERABILITY,
			Scores: []*commonv1.Cvss{{
				Version:   "3.1",
				BaseScore: 7.5,
				Vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Severity:  commonv1.Severity_SEVERITY_HIGH,
			}},
			References: []string{
				"https://example.test/advisory/" + id,
				"https://example.test/commit/" + id,
				"https://example.test/issue/" + id,
			},
			AffectedPackages: []*commonv1.PackageRef{{
				Ecosystem: commonv1.Ecosystem_ECOSYSTEM_NPM,
				Name:      "synthetic-package",
				Version:   "< 2.0.0",
			}},
		},
		// Read back on the consuming side to measure end-to-end latency.
		DiscoveredAt: timestamppb.Now(),
	}
}

func report(what string, n int, took time.Duration, note string) {
	if took <= 0 || n == 0 {
		fmt.Printf("%-10s %d%s\n", what, n, note)
		return
	}
	fmt.Printf("%-10s %d in %s — %.0f/s%s\n",
		what, n, took.Round(time.Millisecond), float64(n)/took.Seconds(), note)
}

func rateLabel(rate int) string {
	if rate <= 0 {
		return "no limit"
	}
	return fmt.Sprintf("%d/s", rate)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "load:", err)
	os.Exit(1)
}
