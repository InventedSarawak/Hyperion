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
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

var _ = Describe("Postgres alerting (integration)", func() {
	var (
		ctx    = context.Background()
		subs   *postgres.SubscriptionRepo
		alerts *postgres.AlertRepo
	)

	BeforeEach(func() {
		dsn := os.Getenv("CORTEX_TEST_DATABASE_URL")
		if dsn == "" {
			Skip("set CORTEX_TEST_DATABASE_URL to run Postgres integration tests")
		}
		schema := fmt.Sprintf("hyperion_alert_test_%d", time.Now().UnixNano())

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

		subs = postgres.NewSubscriptionRepo(pool)
		alerts = postgres.NewAlertRepo(pool)
	})

	rule := model.AlertRule{
		Term:        "log4j",
		MinSeverity: model.SeverityHigh,
		Packages:    []valueobject.PackageRef{valueobject.NewPackageRef("maven", "org.apache.logging.log4j:log4j-core", "")},
		Ecosystems:  []valueobject.Ecosystem{valueobject.EcosystemMaven},
	}
	watch := model.Subscription{
		ID: "sub-1", Tenant: "acme", Name: "Log4j watch", Rule: rule,
		CreatedAt: time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC),
	}

	Describe("subscriptions", func() {
		It("round-trips a rule with every condition set", func() {
			Expect(subs.Save(ctx, watch)).To(Succeed())

			got, err := subs.Get(ctx, "sub-1")
			Expect(err).ToNot(HaveOccurred())
			Expect(got.Name).To(Equal("Log4j watch"))
			Expect(got.Tenant).To(Equal("acme"))
			Expect(got.Rule.Term).To(Equal("log4j"))
			Expect(got.Rule.MinSeverity).To(Equal(model.SeverityHigh))
			Expect(got.Rule.Packages).To(HaveLen(1))
			Expect(got.Rule.Packages[0].Key()).To(Equal("maven:org.apache.logging.log4j:log4j-core"))
			Expect(got.Rule.Ecosystems).To(ConsistOf(valueobject.EcosystemMaven))
		})

		It("reports a missing subscription distinctly", func() {
			_, err := subs.Get(ctx, "nope")
			Expect(err).To(MatchError(ports.ErrSubscriptionNotFound))
		})

		It("updates in place rather than duplicating", func() {
			Expect(subs.Save(ctx, watch)).To(Succeed())
			renamed := watch
			renamed.Name = "Log4j watch (revised)"
			Expect(subs.Save(ctx, renamed)).To(Succeed())

			all, err := subs.List(ctx, "acme")
			Expect(err).ToNot(HaveOccurred())
			Expect(all).To(HaveLen(1))
			Expect(all[0].Name).To(Equal("Log4j watch (revised)"))
		})

		It("lists per tenant, and everything when no tenant is given", func() {
			other := watch
			other.ID, other.Tenant, other.Name = "sub-2", "globex", "Globex watch"
			Expect(subs.Save(ctx, watch)).To(Succeed())
			Expect(subs.Save(ctx, other)).To(Succeed())

			acme, err := subs.List(ctx, "acme")
			Expect(err).ToNot(HaveOccurred())
			Expect(acme).To(HaveLen(1))

			all, err := subs.List(ctx, "")
			Expect(err).ToNot(HaveOccurred())
			Expect(all).To(HaveLen(2))
		})

		It("refuses to store a rule that matches everything", func() {
			Expect(subs.Save(ctx, model.Subscription{ID: "s", Name: "all"})).
				To(MatchError(model.ErrEmptyAlertRule))
		})
	})

	Describe("alerts", func() {
		BeforeEach(func() {
			Expect(subs.Save(ctx, watch)).To(Succeed())
		})

		vuln := model.Vulnerability{CVEID: "CVE-2021-44228", Title: "Log4Shell"}

		It("records an alert and lists it back", func() {
			alert := model.NewAlert(watch, vuln, time.Now())
			Expect(alerts.Append(ctx, alert)).To(Succeed())

			got, err := alerts.List(ctx, "acme", "", 10)
			Expect(err).ToNot(HaveOccurred())
			Expect(got).To(HaveLen(1))
			Expect(got[0].CVEID).To(Equal("CVE-2021-44228"))
			Expect(got[0].SubscriptionID).To(Equal("sub-1"))
			Expect(got[0].Reason).ToNot(BeEmpty())
		})

		It("refreshes rather than stacking when the same CVE is re-observed", func() {
			Expect(alerts.Append(ctx, model.NewAlert(watch, vuln, time.Now()))).To(Succeed())
			Expect(alerts.Append(ctx, model.NewAlert(watch, vuln, time.Now().Add(time.Hour)))).To(Succeed())

			got, err := alerts.List(ctx, "acme", "", 10)
			Expect(err).ToNot(HaveOccurred())
			Expect(got).To(HaveLen(1))
		})

		It("returns the newest first and honours the limit", func() {
			base := time.Now().Add(-time.Hour)
			for i, cve := range []string{"CVE-1", "CVE-2", "CVE-3"} {
				alert := model.NewAlert(watch, model.Vulnerability{CVEID: cve}, base.Add(time.Duration(i)*time.Minute))
				Expect(alerts.Append(ctx, alert)).To(Succeed())
			}

			got, err := alerts.List(ctx, "acme", "", 2)
			Expect(err).ToNot(HaveOccurred())
			Expect(got).To(HaveLen(2))
			Expect(got[0].CVEID).To(Equal("CVE-3"))
		})

		It("filters to one subscription", func() {
			second := watch
			second.ID, second.Name = "sub-2", "Second"
			Expect(subs.Save(ctx, second)).To(Succeed())
			Expect(alerts.Append(ctx, model.NewAlert(watch, vuln, time.Now()))).To(Succeed())
			Expect(alerts.Append(ctx, model.NewAlert(second, vuln, time.Now()))).To(Succeed())

			got, err := alerts.List(ctx, "acme", "sub-2", 10)
			Expect(err).ToNot(HaveOccurred())
			Expect(got).To(HaveLen(1))
			Expect(got[0].SubscriptionID).To(Equal("sub-2"))
		})

		It("removes a subscription's alerts along with the rule", func() {
			// An alert only means something next to the rule that raised it.
			Expect(alerts.Append(ctx, model.NewAlert(watch, vuln, time.Now()))).To(Succeed())
			Expect(subs.Delete(ctx, "sub-1")).To(Succeed())

			got, err := alerts.List(ctx, "acme", "", 10)
			Expect(err).ToNot(HaveOccurred())
			Expect(got).To(BeEmpty())
		})

		It("rejects an alert that cannot say what matched", func() {
			Expect(alerts.Append(ctx, model.Alert{})).To(MatchError(model.ErrIncompleteAlert))
		})
	})
})
