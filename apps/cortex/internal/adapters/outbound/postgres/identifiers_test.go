package postgres_test

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/postgres"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

var _ = Describe("Postgres finding identifiers (integration)", func() {
	const (
		cve  = "CVE-2021-44228"
		ghsa = "GHSA-jfh8-c2jp-5v3q"
	)
	var (
		ctx  = context.Background()
		repo *postgres.Repo
		pool *pgxpool.Pool
	)

	BeforeEach(func() {
		dsn := os.Getenv("CORTEX_TEST_DATABASE_URL")
		if dsn == "" {
			Skip("set CORTEX_TEST_DATABASE_URL to run Postgres integration tests")
		}
		schema := fmt.Sprintf("hyperion_test_%d", time.Now().UnixNano())
		admin, err := postgres.Connect(ctx, dsn)
		Expect(err).ToNot(HaveOccurred())
		_, err = admin.Exec(ctx, "CREATE SCHEMA "+schema)
		Expect(err).ToNot(HaveOccurred())
		admin.Close()

		pool, err = postgres.Connect(ctx, withSearchPath(dsn, schema))
		Expect(err).ToNot(HaveOccurred())
		Expect(postgres.Migrate(ctx, pool)).To(Succeed())
		DeferCleanup(func() {
			pool.Close()
			if cleanup, err := postgres.Connect(ctx, dsn); err == nil {
				_, _ = cleanup.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
				cleanup.Close()
			}
		})
		repo = postgres.NewRepo(pool)
	})

	It("finds a finding by any of its ids", func() {
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: cve, Aliases: []string{ghsa, "GO-2022-0001"}})).To(Succeed())

		for _, id := range []string{cve, ghsa, "GO-2022-0001"} {
			got, err := repo.GetByID(ctx, id)
			Expect(err).ToNot(HaveOccurred(), id)
			Expect(got.CVEID).To(Equal(cve))
			Expect(got.Aliases).To(Equal([]string{ghsa, "GO-2022-0001"}), "in scheme order")
		}
		_, err := repo.GetByID(ctx, "GHSA-xxxx-xxxx-xxxx")
		Expect(err).To(MatchError(ports.ErrNotFound))
	})

	It("stores the kind, reading a record written without one as a vulnerability", func() {
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: "MAL-2026-2307", Kind: model.KindMalware})).To(Succeed())
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: cve})).To(Succeed())

		malware, _ := repo.GetByID(ctx, "MAL-2026-2307")
		Expect(malware.Kind).To(Equal(model.KindMalware))
		plain, _ := repo.GetByID(ctx, cve)
		Expect(plain.Kind).To(Equal(model.KindVulnerability))
	})

	It("re-keys a finding in one step, keeping when it was first seen and its alerts", func() {
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: ghsa, Title: "log4shell"})).To(Succeed())
		_, err := pool.Exec(ctx, `UPDATE vulnerabilities SET first_seen_at = '2020-01-01' WHERE cve_id = $1`, ghsa)
		Expect(err).ToNot(HaveOccurred())
		_, err = pool.Exec(ctx, `INSERT INTO subscriptions (id, tenant, name) VALUES ('s1', 't', 'n');
			INSERT INTO alerts (id, subscription_id, tenant, cve_id) VALUES ('a1', 's1', 't', '`+ghsa+`')`)
		Expect(err).ToNot(HaveOccurred())

		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: cve, Aliases: []string{ghsa}, Title: "log4shell"}, ghsa)).To(Succeed())

		n, _ := repo.Count(ctx)
		Expect(n).To(Equal(1), "the old key is gone, not left beside the new one")
		got, err := repo.GetByID(ctx, ghsa)
		Expect(err).ToNot(HaveOccurred())
		Expect(got.CVEID).To(Equal(cve))

		var firstSeen time.Time
		Expect(pool.QueryRow(ctx, `SELECT first_seen_at FROM vulnerabilities WHERE cve_id = $1`, cve).Scan(&firstSeen)).To(Succeed())
		Expect(firstSeen.Year()).To(Equal(2020))

		var alerted string
		Expect(pool.QueryRow(ctx, `SELECT cve_id FROM alerts WHERE id = 'a1'`).Scan(&alerted)).To(Succeed())
		Expect(alerted).To(Equal(cve))
	})

	It("refuses to give one id to two findings", func() {
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: cve, Aliases: []string{ghsa}})).To(Succeed())

		err := repo.Upsert(ctx, model.Vulnerability{CVEID: "CVE-2021-45046", Aliases: []string{ghsa}})
		Expect(err).To(MatchError(ports.ErrConflict), "already an alias of another finding")

		err = repo.Upsert(ctx, model.Vulnerability{CVEID: "GHSA-7rjr-3q55-vv33", Aliases: []string{cve}})
		Expect(err).To(MatchError(ports.ErrConflict), "already another finding's key")

		n, _ := repo.Count(ctx)
		Expect(n).To(Equal(1), "a refused write leaves nothing behind")
	})

	It("drops an alias the record no longer carries", func() {
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: cve, Aliases: []string{ghsa, "GO-2022-0001"}})).To(Succeed())
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: cve, Aliases: []string{ghsa}})).To(Succeed())

		_, err := repo.GetByID(ctx, "GO-2022-0001")
		Expect(err).To(MatchError(ports.ErrNotFound))
	})

	It("returns every finding a set of ids reaches, once each", func() {
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: cve, Aliases: []string{ghsa}})).To(Succeed())
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: "MAL-2026-2307"})).To(Succeed())
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: "CVE-2000-0001"})).To(Succeed())

		found, err := repo.FindByIDs(ctx, []string{ghsa, cve, "MAL-2026-2307", "CVE-1999-0001"})
		Expect(err).ToNot(HaveOccurred())
		ids := []string{}
		for _, v := range found {
			ids = append(ids, v.CVEID)
		}
		Expect(ids).To(Equal([]string{cve, "MAL-2026-2307"}))
	})

	It("walks the table with aliases and kind intact", func() {
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: ghsa, Aliases: []string{"MAL-2026-2307"}, Kind: model.KindMalware})).To(Succeed())
		page, err := repo.Scan(ctx, "", 10)
		Expect(err).ToNot(HaveOccurred())
		Expect(page).To(HaveLen(1))
		Expect(page[0].Aliases).To(Equal([]string{"MAL-2026-2307"}))
		Expect(page[0].Kind).To(Equal(model.KindMalware))
	})
})
