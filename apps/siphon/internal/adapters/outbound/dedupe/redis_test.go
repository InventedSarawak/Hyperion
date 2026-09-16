package dedupe_test

import (
	"context"
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/redis/go-redis/v9"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/dedupe"
)

// These specs need a real Redis: `task infra:up`, then run with
// SIPHON_TEST_REDIS_ADDR=localhost:6379 (task test:go:integration sets it).
var _ = Describe("Redis dedupe store", Ordered, func() {
	var (
		store *dedupe.Redis
		addr  string
		key   string
		ctx   = context.Background()
	)

	BeforeAll(func() {
		addr = os.Getenv("SIPHON_TEST_REDIS_ADDR")
		if addr == "" {
			Skip("set SIPHON_TEST_REDIS_ADDR to run the dedupe integration specs")
		}
		var err error
		store, err = dedupe.Connect(ctx, addr)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(store.Close()).To(Succeed()) })
	})

	BeforeEach(func() {
		key = fmt.Sprintf("test-%d", time.Now().UnixNano())
		DeferCleanup(func() {
			client := redis.NewClient(&redis.Options{Addr: addr})
			defer func() { _ = client.Close() }()
			Expect(client.Del(ctx, "hyperion:siphon:seen:"+key).Err()).To(Succeed())
		})
	})

	It("reports a key as new once, and as seen afterwards", func() {
		first, err := store.FirstSeen(ctx, key, time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(first).To(BeTrue())

		again, err := store.FirstSeen(ctx, key, time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(again).To(BeFalse())
	})

	It("keeps different keys independent", func() {
		other := key + "-other"
		DeferCleanup(func() {
			client := redis.NewClient(&redis.Options{Addr: addr})
			defer func() { _ = client.Close() }()
			Expect(client.Del(ctx, "hyperion:siphon:seen:"+other).Err()).To(Succeed())
		})

		_, err := store.FirstSeen(ctx, key, time.Hour)
		Expect(err).NotTo(HaveOccurred())

		// A changed observation hashes to a different fingerprint, and must
		// not be suppressed by the unchanged one already stored.
		first, err := store.FirstSeen(ctx, other, time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(first).To(BeTrue())
	})

	It("expires a key after its window, so a long-lived signal is eventually republished", func() {
		first, err := store.FirstSeen(ctx, key, time.Second)
		Expect(err).NotTo(HaveOccurred())
		Expect(first).To(BeTrue())

		Eventually(func() bool {
			again, err := store.FirstSeen(ctx, key, time.Second)
			Expect(err).NotTo(HaveOccurred())
			return again
		}, "5s", "250ms").Should(BeTrue())
	})

	It("does not extend the window when a key is seen again", func() {
		_, err := store.FirstSeen(ctx, key, 30*time.Second)
		Expect(err).NotTo(HaveOccurred())
		_, err = store.FirstSeen(ctx, key, time.Hour)
		Expect(err).NotTo(HaveOccurred())

		client := redis.NewClient(&redis.Options{Addr: addr})
		defer func() { _ = client.Close() }()

		// SET NX does not touch an existing key, so suppression cannot be
		// renewed indefinitely by the same signal being re-observed.
		ttl, err := client.TTL(ctx, "hyperion:siphon:seen:"+key).Result()
		Expect(err).NotTo(HaveOccurred())
		Expect(ttl).To(BeNumerically("<=", 30*time.Second))
	})
})
