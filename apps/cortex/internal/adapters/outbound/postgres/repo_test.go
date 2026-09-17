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
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
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

		got, err := repo.GetByID(ctx, "CVE-2021-44228")
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Description).To(Equal("log4shell"))
		Expect(got.Scores).To(HaveLen(1))
		Expect(got.Scores[0].Severity).To(Equal(model.SeverityCritical))
		Expect(got.Sources).To(Equal([]string{"nvd"}))
		Expect(got.PublishedAt.Year()).To(Equal(2021))
	})

	It("keeps a stated severity that no score carries", func() {
		// The Linux kernel CNA publishes thousands of CVEs and scores none of
		// them; a rating that survives ingestion but not the round trip is
		// lost at the next reindex, which is what used to happen here.
		in := model.Vulnerability{
			CVEID:       "CVE-2026-93148",
			Description: "In the Linux kernel, the following vulnerability has been resolved",
			Severity:    model.SeverityHigh,
		}
		Expect(repo.Upsert(ctx, in)).To(Succeed())

		got, err := repo.GetByID(ctx, "CVE-2026-93148")
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Severity).To(Equal(model.SeverityHigh))
		Expect(got.TopSeverity()).To(Equal(model.SeverityHigh))
	})

	It("leaves severity unset when no source stated one", func() {
		// Absent is not the same as "unknown": a finding with no stated
		// rating is rated from its scores, and must not read back as though
		// a source had said it did not know.
		Expect(repo.Upsert(ctx, model.Vulnerability{
			CVEID:  "CVE-2-SCORED",
			Scores: []model.CVSS{{BaseScore: 9.8, Severity: model.SeverityCritical}},
		})).To(Succeed())

		got, err := repo.GetByID(ctx, "CVE-2-SCORED")
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Severity).To(BeEmpty())
		Expect(got.TopSeverity()).To(Equal(model.SeverityCritical))
	})

	It("returns ErrNotFound for an unknown CVE", func() {
		_, err := repo.GetByID(ctx, "CVE-0000-0000")
		Expect(err).To(MatchError(ports.ErrNotFound))
	})

	It("upsert on the same CVE overwrites rather than duplicating", func() {
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: "CVE-1", Description: "old"})).To(Succeed())
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: "CVE-1", Description: "new"})).To(Succeed())

		n, err := repo.Count(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(1))

		got, _ := repo.GetByID(ctx, "CVE-1")
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

var _ = Describe("Postgres affected packages (integration)", func() {
	var (
		ctx  = context.Background()
		repo *postgres.Repo
	)

	BeforeEach(func() {
		dsn := os.Getenv("CORTEX_TEST_DATABASE_URL")
		if dsn == "" {
			Skip("set CORTEX_TEST_DATABASE_URL to run Postgres integration tests")
		}
		schema := fmt.Sprintf("hyperion_pkg_test_%d", time.Now().UnixNano())

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

	It("round-trips the packages a CVE affects", func() {
		Expect(repo.Upsert(ctx, model.Vulnerability{
			CVEID: "CVE-2021-44228",
			AffectedPackages: []valueobject.PackageRef{
				valueobject.NewPackageRef("maven", "org.apache.logging.log4j:log4j-core", ">= 2.0.1, < 2.15.0"),
				valueobject.NewPackageRef("npm", "lodash", "< 4.17.21"),
			},
		})).To(Succeed())

		got, err := repo.GetByID(ctx, "CVE-2021-44228")
		Expect(err).ToNot(HaveOccurred())
		Expect(got.AffectedPackages).To(HaveLen(2))
		Expect(got.AffectedPackages[0].Key()).To(Equal("maven:org.apache.logging.log4j:log4j-core"))
		Expect(got.AffectedPackages[0].Version).To(Equal(">= 2.0.1, < 2.15.0"))
		Expect(got.AffectedPackages[1].Ecosystem).To(Equal(valueobject.EcosystemNPM))
	})

	It("keeps the linkage when a later source reports the CVE without packages", func() {
		// This is why the column exists: the merge can only preserve a
		// package linkage it can read back out of storage.
		Expect(repo.Upsert(ctx, model.Vulnerability{
			CVEID:            "CVE-2021-23337",
			AffectedPackages: []valueobject.PackageRef{valueobject.NewPackageRef("npm", "lodash", "< 4.17.21")},
		})).To(Succeed())

		stored, err := repo.GetByID(ctx, "CVE-2021-23337")
		Expect(err).ToNot(HaveOccurred())

		merged := stored.Merge(model.Vulnerability{CVEID: "CVE-2021-23337", Description: "from nvd"})
		Expect(repo.Upsert(ctx, merged)).To(Succeed())

		got, err := repo.GetByID(ctx, "CVE-2021-23337")
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Description).To(Equal("from nvd"))
		Expect(got.AffectedPackages).To(HaveLen(1))
	})

	It("stores an empty list rather than null for a CVE with no packages", func() {
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: "CVE-2000-0001"})).To(Succeed())
		got, err := repo.GetByID(ctx, "CVE-2000-0001")
		Expect(err).ToNot(HaveOccurred())
		Expect(got.AffectedPackages).To(BeNil())
	})
})

var _ = Describe("Postgres Repo scan (integration)", func() {
	var (
		ctx  = context.Background()
		repo *postgres.Repo
	)

	BeforeEach(func() {
		dsn := os.Getenv("CORTEX_TEST_DATABASE_URL")
		if dsn == "" {
			Skip("set CORTEX_TEST_DATABASE_URL to run Postgres integration tests")
		}
		schema := fmt.Sprintf("hyperion_scan_test_%d", time.Now().UnixNano())
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
			if cleanup, err := postgres.Connect(ctx, dsn); err == nil {
				_, _ = cleanup.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
				cleanup.Close()
			}
		})
		repo = postgres.NewRepo(pool)
	})

	It("walks every row once, in id order, across pages", func() {
		for i := 0; i < 7; i++ {
			Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: fmt.Sprintf("CVE-2026-%04d", i)})).To(Succeed())
		}

		var seen []string
		after := ""
		for {
			page, err := repo.Scan(ctx, after, 3)
			Expect(err).ToNot(HaveOccurred())
			if len(page) == 0 {
				break
			}
			for _, v := range page {
				seen = append(seen, v.CVEID)
			}
			after = page[len(page)-1].CVEID
		}
		Expect(seen).To(Equal([]string{"CVE-2026-0000", "CVE-2026-0001", "CVE-2026-0002",
			"CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006"}))
	})

	It("returns the full record, affected packages included", func() {
		Expect(repo.Upsert(ctx, model.Vulnerability{CVEID: "CVE-1", Title: "flaw",
			AffectedPackages: []valueobject.PackageRef{valueobject.NewPackageRef("npm", "next", "")}})).To(Succeed())

		page, err := repo.Scan(ctx, "", 10)
		Expect(err).ToNot(HaveOccurred())
		Expect(page).To(HaveLen(1))
		Expect(page[0].Title).To(Equal("flaw"))
		Expect(page[0].AffectedPackages[0].Key()).To(Equal("npm:next"))
	})
})
