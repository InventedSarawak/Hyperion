package postgres_test

import (
	"context"
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/postgres"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

var _ = Describe("Postgres watchlist (integration)", func() {
	var (
		ctx  = context.Background()
		list *postgres.Watchlist
	)

	BeforeEach(func() {
		dsn := os.Getenv("CORTEX_TEST_DATABASE_URL")
		if dsn == "" {
			Skip("set CORTEX_TEST_DATABASE_URL to run Postgres integration tests")
		}
		schema := fmt.Sprintf("hyperion_watchlist_test_%d", time.Now().UnixNano())

		admin, err := postgres.Connect(ctx, dsn)
		Expect(err).ToNot(HaveOccurred())
		_, err = admin.Exec(ctx, "CREATE SCHEMA "+schema)
		Expect(err).ToNot(HaveOccurred())
		admin.Close()

		pool, err := postgres.Connect(ctx, withSearchPath(dsn, schema))
		Expect(err).ToNot(HaveOccurred())
		Expect(postgres.Migrate(ctx, pool)).To(Succeed())

		DeferCleanup(func() {
			pool.Close()
			cleanup, err := postgres.Connect(ctx, dsn)
			if err == nil {
				_, _ = cleanup.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
				cleanup.Close()
			}
		})
		list = postgres.NewWatchlist(pool)
	})

	repo := func(owner, name string) model.TrackedRepository {
		return model.TrackedRepository{Owner: owner, Name: name, Status: model.ScanPending}
	}

	It("tracks repositories as pending and lists them by name", func() {
		_, err := list.Track(ctx, []model.TrackedRepository{repo("vercel", "swr"), repo("eslint", "eslint")})
		Expect(err).ToNot(HaveOccurred())

		got, err := list.List(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(2))
		Expect(got[0].FullName()).To(Equal("eslint/eslint"))
		Expect(got[0].Status).To(Equal(model.ScanPending))
		Expect(got[0].AddedAt).ToNot(BeZero())
		Expect(got[0].LastScanAt).To(BeZero())
	})

	It("records outcomes, keeping the last good count when a scan fails", func() {
		_, err := list.Track(ctx, []model.TrackedRepository{repo("vercel", "swr")})
		Expect(err).ToNot(HaveOccurred())

		Expect(list.RecordScan(ctx, model.ScanOutcome{FullName: "vercel/swr", Succeeded: true, DependencyCount: 40})).To(Succeed())
		Expect(list.RecordScan(ctx, model.ScanOutcome{FullName: "vercel/swr", Error: "rate limited"})).To(Succeed())

		got, _ := list.List(ctx)
		Expect(got[0].Status).To(Equal(model.ScanFailed))
		Expect(got[0].LastError).To(Equal("rate limited"))
		Expect(got[0].DependencyCount).To(Equal(40))
	})

	It("re-queues a repository tracked again under different casing, keeping when it was added", func() {
		first, err := list.Track(ctx, []model.TrackedRepository{repo("vercel", "next.js")})
		Expect(err).ToNot(HaveOccurred())
		Expect(list.RecordScan(ctx, model.ScanOutcome{FullName: "vercel/next.js", Succeeded: true, DependencyCount: 9})).To(Succeed())

		again, err := list.Track(ctx, []model.TrackedRepository{repo("Vercel", "Next.js")})
		Expect(err).ToNot(HaveOccurred())

		got, _ := list.List(ctx)
		Expect(got).To(HaveLen(1))
		Expect(again[0].Status).To(Equal(model.ScanPending))
		Expect(again[0].AddedAt).To(BeTemporally("~", first[0].AddedAt, time.Millisecond))
	})

	It("removes an entry, case-insensitively, and reports whether it existed", func() {
		_, _ = list.Track(ctx, []model.TrackedRepository{repo("vercel", "swr")})

		removed, err := list.Remove(ctx, "VERCEL/SWR")
		Expect(err).ToNot(HaveOccurred())
		Expect(removed).To(BeTrue())

		removed, err = list.Remove(ctx, "vercel/swr")
		Expect(err).ToNot(HaveOccurred())
		Expect(removed).To(BeFalse())
	})

	It("reports a scan for an untracked repository as not tracked", func() {
		err := list.RecordScan(ctx, model.ScanOutcome{FullName: "nobody/here", Succeeded: true})
		Expect(err).To(MatchError(ports.ErrNotTracked))
	})
})
