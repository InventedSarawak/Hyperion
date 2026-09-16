package postgres_test

import (
	"context"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/postgres"
)

// These specs need a real Postgres: task test:go:integration sets
// CORTEX_TEST_DATABASE_URL.
var _ = Describe("migration runner", Ordered, func() {
	var pool *pgxpool.Pool

	BeforeAll(func() {
		dsn := os.Getenv("CORTEX_TEST_DATABASE_URL")
		if dsn == "" {
			Skip("set CORTEX_TEST_DATABASE_URL to run the migration specs")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var err error
		pool, err = postgres.Connect(ctx, dsn)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(pool.Close)
	})

	It("records every migration it applies", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		Expect(postgres.Migrate(ctx, pool)).To(Succeed())

		var count int
		Expect(pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count)).To(Succeed())
		Expect(count).To(BeNumerically(">=", 6))
	})

	It("applies nothing the second time", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		var before time.Time
		Expect(pool.QueryRow(ctx, `SELECT max(applied_at) FROM schema_migrations`).Scan(&before)).To(Succeed())

		Expect(postgres.Migrate(ctx, pool)).To(Succeed())

		// Nothing re-applied means nothing re-recorded. This is what makes a
		// one-time migration — a backfill, a data correction — possible at
		// all: under the old runner every file ran on every boot.
		var after time.Time
		Expect(pool.QueryRow(ctx, `SELECT max(applied_at) FROM schema_migrations`).Scan(&after)).To(Succeed())
		Expect(after).To(BeTemporally("==", before))
	})

	It("refuses to run when a migration that already ran has been edited", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Pretend 0001 was applied from different text than the tree holds.
		_, err := pool.Exec(ctx,
			`UPDATE schema_migrations SET checksum = 'tampered' WHERE version = '0001_init.sql'`)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			// Put it back by re-deriving it: deleting the row would make the
			// next run re-apply 0001, which is harmless but noisy.
			_, err := pool.Exec(cleanupCtx,
				`DELETE FROM schema_migrations WHERE version = '0001_init.sql'`)
			Expect(err).NotTo(HaveOccurred())
			Expect(postgres.Migrate(cleanupCtx, pool)).To(Succeed())
		})

		err = postgres.Migrate(ctx, pool)

		// Editing an applied migration is a silent way for two databases built
		// from the same source tree to end up with different schemas.
		Expect(err).To(MatchError(ContainSubstring("has changed since it was applied")))
	})
})
