package postgres_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/postgres"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// This suite needs a real Postgres. It is skipped unless CORTEX_TEST_DATABASE_URL
// is set, e.g.:
//
//	docker compose -f deploy/docker-compose.yml up -d
//	CORTEX_TEST_DATABASE_URL=postgres://hyperion:hyperion@localhost:5432/hyperion?sslmode=disable \
//	  go test ./internal/adapters/outbound/postgres/...
var _ = Describe("Postgres Repo (integration)", func() {
	var (
		ctx  = context.Background()
		repo *postgres.Repo
	)

	BeforeEach(func() {
		dsn := os.Getenv("CORTEX_TEST_DATABASE_URL")
		if dsn == "" {
			Skip("set CORTEX_TEST_DATABASE_URL to run Postgres integration tests")
		}

		// Run inside a throwaway schema so these tests can never touch real
		// data in the target database (mirrors the ES suite's throwaway index).
		schema := fmt.Sprintf("hyperion_test_%d", time.Now().UnixNano())

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

	It("upserts and reads back a vulnerability", func() {
		in := model.Vulnerability{
			CVEID:       "CVE-2021-44228",
			Description: "log4shell",
			Scores:      []model.CVSS{{Version: "3.1", BaseScore: 10, Severity: model.SeverityCritical}},
			References:  []string{"https://example.test/a"},
			Sources:     []string{"nvd"},
			PublishedAt: time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
		}
		Expect(repo.Upsert(ctx, in)).To(Succeed())

		got, err := repo.GetByCVE(ctx, "CVE-2021-44228")
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Description).To(Equal("log4shell"))
		Expect(got.Scores).To(HaveLen(1))
		Expect(got.Scores[0].Severity).To(Equal(model.SeverityCritical))
		Expect(got.Sources).To(Equal([]string{"nvd"}))
		Expect(got.PublishedAt.Year()).To(Equal(2021))
	})

	It("returns ErrNotFound for an unknown CVE", func() {
		_, err := repo.GetByCVE(ctx, "CVE-0000-0000")
		Expect(err).To(MatchError(ports.ErrNotFound))
	})

	It("upsert on the same CVE overwrites rather than duplicating", func() {
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: "CVE-1", Description: "old"})).To(Succeed())
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: "CVE-1", Description: "new"})).To(Succeed())

		n, err := repo.Count(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(1))

		got, _ := repo.GetByCVE(ctx, "CVE-1")
		Expect(got.Description).To(Equal("new"))
	})
})

// withSearchPath returns dsn with the connection's search_path pinned to schema.
func withSearchPath(dsn, schema string) string {
	u, err := url.Parse(dsn)
	Expect(err).ToNot(HaveOccurred())
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}
