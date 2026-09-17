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

// Retiring a key must never lose it. When two records turn out to be one
// finding, the loser's row is deleted and its id has to survive as an alias —
// otherwise a lookup by that id finds nothing, and whatever was stored under it
// is gone with no trace of where it went.
//
// These specs exist because 9,239 rows disappeared from a running store over
// eleven hours, present afterwards neither as records nor as aliases. They pin
// the invariant the retire path is supposed to hold.
var _ = Describe("retiring a key (integration)", func() {
	var (
		ctx  = context.Background()
		repo *postgres.Repo
	)

	BeforeEach(func() {
		dsn := os.Getenv("CORTEX_TEST_DATABASE_URL")
		if dsn == "" {
			Skip("set CORTEX_TEST_DATABASE_URL to run Postgres integration tests")
		}
		schema := fmt.Sprintf("hyperion_retire_%d", time.Now().UnixNano())

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
		repo = postgres.NewRepo(pool)
	})

	It("keeps a retired id reachable, when the surviving record carries it", func() {
		ghsa, cve := "GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"

		// Stored first under its GHSA, as GitHub reports it.
		Expect(repo.Upsert(ctx, model.Vulnerability{
			CVEID: ghsa, Sources: []string{"github_advisory"},
		}.Normalized())).To(Succeed())

		// Then a feed links the two ids: the finding moves to its CVE and the
		// GHSA row is retired.
		merged := model.Vulnerability{
			CVEID: cve, Aliases: []string{ghsa}, Sources: []string{"nvd"},
		}.Normalized()
		Expect(repo.Upsert(ctx, merged, ghsa)).To(Succeed())

		// The row is gone, which is right — but the id must still find it.
		found, err := repo.GetByID(ctx, ghsa)
		Expect(err).ToNot(HaveOccurred(), "the retired id resolves to nothing: it was lost, not merged")
		Expect(found.CVEID).To(Equal(cve))
	})

	It("refuses to retire an id the surviving record does not carry", func() {
		first, second := "CVE-2019-4798", "CVE-2021-44228"

		Expect(repo.Upsert(ctx, model.Vulnerability{
			CVEID: first, Sources: []string{"nvd"},
		}.Normalized())).To(Succeed())

		// The id has nowhere to live on, so the row would be deleted and
		// nothing would resolve that id afterwards. There is no caller for
		// whom that is the intent, so the store refuses instead of obeying.
		err := repo.Upsert(ctx, model.Vulnerability{
			CVEID: second, Sources: []string{"nvd"},
		}.Normalized(), first)

		Expect(err).To(MatchError(ports.ErrOrphanedRetire))

		// And the record it would have deleted is still there.
		found, err := repo.GetByID(ctx, first)
		Expect(err).ToNot(HaveOccurred())
		Expect(found.CVEID).To(Equal(first))
	})

})
