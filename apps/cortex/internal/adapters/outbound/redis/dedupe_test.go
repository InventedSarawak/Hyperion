package redis_test

import (
	"context"
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	redisadapter "github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/redis"
)

// This suite needs a real Redis. It is skipped unless CORTEX_TEST_REDIS_ADDR
// is set, e.g.:
//
//	docker compose -f deploy/docker-compose.yml up -d redis
//	CORTEX_TEST_REDIS_ADDR=localhost:6379 go test ./internal/adapters/outbound/redis/...
//
// Keys are prefixed per run, so specs never collide with real suppression state.
var _ = Describe("Redis DedupeStore (integration)", func() {
	var (
		ctx    = context.Background()
		store  *redisadapter.Store
		prefix string
	)

	BeforeEach(func() {
		addr := os.Getenv("CORTEX_TEST_REDIS_ADDR")
		if addr == "" {
			Skip("set CORTEX_TEST_REDIS_ADDR to run Redis integration tests")
		}

		var err error
		store, err = redisadapter.Connect(ctx, addr)
		Expect(err).ToNot(HaveOccurred())
		prefix = fmt.Sprintf("test:%d:", time.Now().UnixNano())

		DeferCleanup(func() { Expect(store.Close()).To(Succeed()) })
	})

	It("is ready", func() {
		Expect(store.Ready(ctx)).To(Succeed())
	})

	It("reports the first sighting, then suppresses within the window", func() {
		key := prefix + "alert:sub-1:CVE-2021-44228"

		first, err := store.FirstSeen(ctx, key, time.Minute)
		Expect(err).ToNot(HaveOccurred())
		Expect(first).To(BeTrue())

		again, err := store.FirstSeen(ctx, key, time.Minute)
		Expect(err).ToNot(HaveOccurred())
		Expect(again).To(BeFalse())
	})

	It("keeps different keys independent", func() {
		one, err := store.FirstSeen(ctx, prefix+"alert:sub-1:CVE-1", time.Minute)
		Expect(err).ToNot(HaveOccurred())
		Expect(one).To(BeTrue())

		two, err := store.FirstSeen(ctx, prefix+"alert:sub-1:CVE-2", time.Minute)
		Expect(err).ToNot(HaveOccurred())
		Expect(two).To(BeTrue(), "suppression is per CVE, not per subscription")

		three, err := store.FirstSeen(ctx, prefix+"alert:sub-2:CVE-1", time.Minute)
		Expect(err).ToNot(HaveOccurred())
		Expect(three).To(BeTrue(), "suppression is per subscription, not per CVE")
	})

	It("lets the key expire, so the window really is a window", func() {
		key := prefix + "alert:expiring"

		first, err := store.FirstSeen(ctx, key, 800*time.Millisecond)
		Expect(err).ToNot(HaveOccurred())
		Expect(first).To(BeTrue())

		Eventually(func() bool {
			seen, err := store.FirstSeen(ctx, key, time.Second)
			Expect(err).ToNot(HaveOccurred())
			return seen
		}, 3*time.Second, 200*time.Millisecond).Should(BeTrue(),
			"after the window elapses the same alert may fire again")
	})

	It("reports an unreachable server rather than silently suppressing", func() {
		// Failing closed here would mean alerts vanish when Redis is down.
		_, err := redisadapter.Connect(ctx, "127.0.0.1:1")
		Expect(err).To(HaveOccurred())
	})
})
