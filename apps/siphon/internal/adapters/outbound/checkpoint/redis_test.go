package checkpoint_test

import (
	"context"
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/redis/go-redis/v9"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/checkpoint"
)

// These specs need a real Redis: `task infra:up`, then run with
// SIPHON_TEST_REDIS_ADDR=localhost:6379 (task test:go:integration sets it).
var _ = Describe("Redis checkpoint store", Ordered, func() {
	var (
		store *checkpoint.Redis
		addr  string
		name  string
		ctx   = context.Background()
	)

	BeforeAll(func() {
		addr = os.Getenv("SIPHON_TEST_REDIS_ADDR")
		if addr == "" {
			Skip("set SIPHON_TEST_REDIS_ADDR to run the checkpoint integration specs")
		}
		var err error
		store, err = checkpoint.Connect(ctx, addr)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(store.Close()).To(Succeed()) })
	})

	// A name per spec, so one spec's watermark is never another's starting state.
	BeforeEach(func() {
		name = fmt.Sprintf("test-%d", time.Now().UnixNano())
		DeferCleanup(func() {
			client := redis.NewClient(&redis.Options{Addr: addr})
			defer func() { _ = client.Close() }()
			Expect(client.Del(ctx, "hyperion:siphon:watermark:"+name).Err()).To(Succeed())
		})
	})

	It("reports nothing stored for a name it has never seen", func() {
		_, found, err := store.Load(ctx, name)
		Expect(err).NotTo(HaveOccurred())
		// Not an error and not the zero time: the caller has to be able to
		// tell "never recorded" from "recorded", and only fall back for one.
		Expect(found).To(BeFalse())
	})

	It("round-trips a watermark", func() {
		at := time.Now().Add(-90 * time.Minute).UTC().Truncate(time.Millisecond)
		Expect(store.Save(ctx, name, at)).To(Succeed())

		got, found, err := store.Load(ctx, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(got).To(BeTemporally("==", at))
	})

	It("keeps only the latest watermark", func() {
		older := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Millisecond)
		newer := time.Now().Add(-10 * time.Minute).UTC().Truncate(time.Millisecond)
		Expect(store.Save(ctx, name, older)).To(Succeed())
		Expect(store.Save(ctx, name, newer)).To(Succeed())

		got, _, err := store.Load(ctx, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeTemporally("==", newer))
	})

	It("stores the watermark without an expiry", func() {
		Expect(store.Save(ctx, name, time.Now())).To(Succeed())

		client := redis.NewClient(&redis.Options{Addr: addr})
		defer func() { _ = client.Close() }()

		// A watermark that quietly expired would send the next start back to
		// the lookback window — the exact failure this store exists to stop.
		ttl, err := client.TTL(ctx, "hyperion:siphon:watermark:"+name).Result()
		Expect(err).NotTo(HaveOccurred())
		Expect(ttl).To(Equal(time.Duration(-1)), "the key should never expire")
	})

	It("treats an unreadable value as nothing stored, so a corrupt bookmark cannot block ingestion", func() {
		client := redis.NewClient(&redis.Options{Addr: addr})
		defer func() { _ = client.Close() }()
		Expect(client.Set(ctx, "hyperion:siphon:watermark:"+name, "not a timestamp", 0).Err()).To(Succeed())

		_, found, err := store.Load(ctx, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeFalse())
	})
})
