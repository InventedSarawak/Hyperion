package kafka_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/inventedsarawak/hyperion/packages/common/kafka"
)

// These specs need a real broker: `task infra:up`, then run with
// HYPERION_TEST_KAFKA_BROKERS=localhost:9092 (task test:go:integration sets
// it). Without it they skip, so an ordinary `task test:go` stays hermetic.
var _ = Describe("against a real broker", Ordered, func() {
	var (
		cfg   kafka.Config
		topic string
	)

	BeforeAll(func() {
		brokers := os.Getenv("HYPERION_TEST_KAFKA_BROKERS")
		if brokers == "" {
			Skip("set HYPERION_TEST_KAFKA_BROKERS to run the Kafka integration specs")
		}
		cfg = kafka.Config{Brokers: kafka.ParseBrokers(brokers), ClientID: "hyperion-test"}
	})

	// A topic per spec, not per run. These specs assert on offsets, lag and
	// what a group re-reads, and a consumer that starts at the beginning sees
	// every record another spec left behind — which reads exactly like the
	// bug they are meant to catch.
	BeforeEach(func() {
		topic = fmt.Sprintf("hyperion.test.%d", time.Now().UnixNano())

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		Expect(kafka.EnsureTopic(ctx, cfg, topic, 3)).To(Succeed())

		// Take it away again afterwards. Without this every test run leaves
		// another topic on the broker for good, and they pile up next to the
		// real ones in the console.
		DeferCleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			Expect(kafka.DeleteTopic(cleanupCtx, cfg, topic)).To(Succeed())
		})
	})

	// ctx is a short-lived context for setup calls inside a spec.
	ctx := func() context.Context {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		DeferCleanup(cancel)
		return c
	}

	// publish writes n records under each of the given keys, values numbered
	// "<key>-<i>", and blocks until the broker has them all.
	publish := func(keys []string, n int) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		p, err := kafka.NewProducer(cfg, topic)
		Expect(err).NotTo(HaveOccurred())
		defer func() { Expect(p.Close()).To(Succeed()) }()

		Expect(p.Ping(ctx)).To(Succeed())
		for i := range n {
			for _, k := range keys {
				Expect(p.Publish(ctx, k, wrapperspb.String(fmt.Sprintf("%s-%d", k, i)))).To(Succeed())
			}
		}
		// Until this returns, a nil from Publish only means "buffered".
		Expect(p.Flush(ctx)).To(Succeed())
	}

	// running is a consumer started in the background. The spec decides when
	// it stops: a consumer cancelled the moment its last record is handled is
	// cancelled *before* the batch is committed, which is a property of this
	// harness and not of the consumer under test.
	type running struct {
		consumer *kafka.Consumer
		finished chan struct{}
		stop     func() error // cancels, waits, and reports what Run returned
	}

	start := func(group string, h kafka.Handler, opts ...kafka.ConsumerOption) *running {
		c, err := kafka.NewConsumer(cfg, topic, group, opts...)
		Expect(err).NotTo(HaveOccurred())

		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		r := &running{consumer: c, finished: make(chan struct{})}

		var (
			mu     sync.Mutex
			runErr error
		)
		go func() {
			defer close(r.finished)
			err := c.Run(ctx, h)
			mu.Lock()
			runErr = err
			mu.Unlock()
		}()

		r.stop = func() error {
			cancel()
			<-r.finished
			c.Close()
			mu.Lock()
			defer mu.Unlock()
			return runErr
		}
		return r
	}

	// totalLag is what the group has left to read across every partition.
	// A group that has not formed yet reports no partitions at all, which is
	// not the same as being caught up: -1 keeps the wait going rather than
	// letting an unformed group read as zero lag.
	totalLag := func(c *kafka.Consumer) func() int64 {
		return func() int64 {
			lag, err := c.Lag(context.Background())
			if err != nil || len(lag) == 0 {
				return -1
			}
			var total int64
			for _, l := range lag {
				total += l
			}
			return total
		}
	}

	It("delivers every record, and keeps the records of one key in order", func() {
		const perKey = 20
		keys := []string{"CVE-2021-44228", "CVE-2014-0160", "GHSA-fw8c-xr5c-95f9"}
		publish(keys, perKey)

		var (
			mu   sync.Mutex
			seen = map[string][]string{}
		)
		handler := kafka.HandlerFunc(func(_ context.Context, msg kafka.Message) error {
			var v wrapperspb.StringValue
			if err := msg.Into(&v); err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			seen[msg.Key] = append(seen[msg.Key], v.GetValue())
			return nil
		})

		delivered := func() int {
			mu.Lock()
			defer mu.Unlock()
			n := 0
			for _, v := range seen {
				n += len(v)
			}
			return n
		}

		r := start("hyperion-test-order", handler)
		Eventually(delivered, "45s", "250ms").Should(Equal(perKey * len(keys)))
		Eventually(totalLag(r.consumer), "45s", "250ms").Should(BeZero())
		Expect(r.stop()).To(MatchError(context.Canceled))

		mu.Lock()
		defer mu.Unlock()
		for _, k := range keys {
			want := make([]string, perKey)
			for i := range perKey {
				want[i] = fmt.Sprintf("%s-%d", k, i)
			}
			// Per-key order is the whole point of keying records: cortex
			// merges each finding read-modify-write, so two reports of one
			// CVE arriving out of order lose a contribution.
			Expect(seen[k]).To(Equal(want), "key %s arrived out of order", k)
		}
	})

	It("commits what it handled, so a restart of the group does not re-read it", func() {
		publish([]string{"resume-a", "resume-b"}, 3)

		var handled atomic.Int64
		count := kafka.HandlerFunc(func(_ context.Context, _ kafka.Message) error {
			handled.Add(1)
			return nil
		})

		first := start("hyperion-test-resume", count)
		Eventually(handled.Load, "45s", "250ms").Should(Equal(int64(6)))
		// Lag reaching zero is the proof the offsets were committed, rather
		// than a sleep hoping they were.
		Eventually(totalLag(first.consumer), "45s", "250ms").Should(BeZero())
		Expect(first.stop()).To(MatchError(context.Canceled))

		// A second member of the same group starts from the committed offset.
		// Nothing new was produced, so it should stay idle.
		var again atomic.Int64
		second := start("hyperion-test-resume", kafka.HandlerFunc(func(_ context.Context, _ kafka.Message) error {
			again.Add(1)
			return nil
		}))
		defer second.stop()

		Consistently(again.Load, "10s", "500ms").Should(BeZero(),
			"the group re-read records it had already committed")
	})

	It("skips an unprocessable record and keeps going, rather than wedging the partition behind it", func() {
		publish([]string{"poison"}, 4)

		var (
			mu      sync.Mutex
			handled []string
		)
		handler := kafka.HandlerFunc(func(_ context.Context, msg kafka.Message) error {
			var v wrapperspb.StringValue
			if err := msg.Into(&v); err != nil {
				return err
			}
			// The second record can never succeed; the third and fourth must
			// still be delivered.
			if v.GetValue() == "poison-1" {
				return fmt.Errorf("%w: malformed", kafka.ErrUnprocessable)
			}
			mu.Lock()
			defer mu.Unlock()
			handled = append(handled, v.GetValue())
			return nil
		})

		delivered := func() int {
			mu.Lock()
			defer mu.Unlock()
			return len(handled)
		}

		r := start("hyperion-test-poison", handler)
		Eventually(delivered, "45s", "250ms").Should(Equal(3))
		Eventually(totalLag(r.consumer), "45s", "250ms").Should(BeZero())
		Expect(r.stop()).To(MatchError(context.Canceled))

		mu.Lock()
		defer mu.Unlock()
		Expect(handled).To(Equal([]string{"poison-0", "poison-2", "poison-3"}))
	})

	It("sets an unprocessable record aside and carries on, when there is somewhere to put it", func() {
		publish([]string{"dlq"}, 4)

		dlqTopic := topic + kafka.DeadLetterSuffix
		dl, err := kafka.NewDeadLetter(ctx(), cfg, topic, dlqTopic, nil)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() {
			Expect(dl.Close()).To(Succeed())
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			Expect(kafka.DeleteTopic(cleanupCtx, cfg, dlqTopic)).To(Succeed())
		})

		var (
			mu      sync.Mutex
			handled []string
		)
		handler := kafka.HandlerFunc(func(_ context.Context, msg kafka.Message) error {
			var v wrapperspb.StringValue
			if err := msg.Into(&v); err != nil {
				return err
			}
			// One record that never succeeds. Everything behind it on the
			// partition must still be delivered.
			if v.GetValue() == "dlq-1" {
				return errors.New("this record can never be stored")
			}
			mu.Lock()
			defer mu.Unlock()
			handled = append(handled, v.GetValue())
			return nil
		})

		r := start("hyperion-test-dlq", handler,
			kafka.WithRetries(2, 10*time.Millisecond),
			kafka.WithDeadLetter(dl, 10))
		Eventually(func() int {
			mu.Lock()
			defer mu.Unlock()
			return len(handled)
		}, "45s", "250ms").Should(Equal(3))
		Eventually(totalLag(r.consumer), "45s", "250ms").Should(BeZero())
		Expect(r.stop()).To(MatchError(context.Canceled))

		mu.Lock()
		defer mu.Unlock()
		Expect(handled).To(Equal([]string{"dlq-0", "dlq-2", "dlq-3"}))

		// The record itself is on the dead-letter topic, byte for byte, with
		// the reason attached — so it can be looked at, fixed and replayed.
		var dead []kafka.Message
		tailCtx, cancelTail := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancelTail()
		Expect(kafka.Tail(tailCtx, cfg, dlqTopic, kafka.TailOptions{FromStart: true, Limit: 1},
			func(m kafka.Message) error {
				dead = append(dead, m)
				return nil
			})).To(Succeed())

		Expect(dead).To(HaveLen(1))
		var v wrapperspb.StringValue
		Expect(dead[0].Into(&v)).To(Succeed())
		Expect(v.GetValue()).To(Equal("dlq-1"))
		Expect(dead[0].Headers[kafka.HeaderDLQError]).To(ContainSubstring("can never be stored"))
		Expect(dead[0].Headers[kafka.HeaderDLQTopic]).To(Equal(topic))
		Expect(dead[0].Headers[kafka.HeaderDLQAttempts]).To(Equal("2"))
	})

	It("stops rather than draining the whole topic into the dead-letter queue when everything is failing", func() {
		publish([]string{"outage"}, 8)

		dlqTopic := topic + kafka.DeadLetterSuffix
		dl, err := kafka.NewDeadLetter(ctx(), cfg, topic, dlqTopic, nil)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() {
			Expect(dl.Close()).To(Succeed())
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			Expect(kafka.DeleteTopic(cleanupCtx, cfg, dlqTopic)).To(Succeed())
		})

		// Everything fails, as it would with the database down. Setting every
		// record aside would be a silent migration of the topic; the consumer
		// is supposed to give up instead.
		everything := kafka.HandlerFunc(func(_ context.Context, _ kafka.Message) error {
			return errors.New("database is down")
		})

		r := start("hyperion-test-outage", everything,
			kafka.WithRetries(1, 10*time.Millisecond),
			kafka.WithDeadLetter(dl, 3))

		Eventually(r.finished, "45s").Should(BeClosed())
		Expect(r.stop()).To(MatchError(ContainSubstring("in a row could not be processed")))
	})

	It("stops without committing when a record fails past its retries, so the work is replayed", func() {
		publish([]string{"replay"}, 3)

		var attempts atomic.Int64
		failing := kafka.HandlerFunc(func(_ context.Context, msg kafka.Message) error {
			var v wrapperspb.StringValue
			if err := msg.Into(&v); err != nil {
				return err
			}
			if v.GetValue() == "replay-1" {
				attempts.Add(1)
				return errors.New("database is down")
			}
			return nil
		})

		r := start("hyperion-test-replay", failing, kafka.WithRetries(3, 10*time.Millisecond))

		// Run returns on its own here — the spec does not cancel it. The
		// consumer stops loudly, because silently skipping an infrastructure
		// failure is how data disappears without anyone noticing.
		Eventually(r.finished, "45s").Should(BeClosed())
		Expect(r.stop()).To(MatchError(ContainSubstring("failed after 3 attempts")))
		Expect(attempts.Load()).To(Equal(int64(3)))

		// Nothing was committed, so a healthy consumer replays the batch.
		var (
			mu   sync.Mutex
			seen []string
		)
		second := start("hyperion-test-replay", kafka.HandlerFunc(func(_ context.Context, msg kafka.Message) error {
			var v wrapperspb.StringValue
			if err := msg.Into(&v); err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, v.GetValue())
			return nil
		}))
		Eventually(func() int {
			mu.Lock()
			defer mu.Unlock()
			return len(seen)
		}, "45s", "250ms").Should(Equal(3))
		Eventually(totalLag(second.consumer), "45s", "250ms").Should(BeZero())
		Expect(second.stop()).To(MatchError(context.Canceled))

		mu.Lock()
		defer mu.Unlock()
		Expect(seen).To(ContainElement("replay-1"))
	})
})
