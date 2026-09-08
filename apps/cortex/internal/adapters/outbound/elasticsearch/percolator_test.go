package elasticsearch_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/elasticsearch"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// This suite needs a real Elasticsearch. It is skipped unless
// CORTEX_TEST_ELASTICSEARCH_URL is set, e.g.:
//
//	docker compose -f deploy/docker-compose.yml up -d elasticsearch
//	CORTEX_TEST_ELASTICSEARCH_URL=http://localhost:9200 \
//	  go test ./internal/adapters/outbound/elasticsearch/...
//
// Each spec gets a throwaway index, so it can never touch real subscriptions.
var _ = Describe("Elasticsearch Percolator (integration)", func() {
	var (
		ctx        = context.Background()
		percolator *elasticsearch.Percolator
		baseURL    string
		index      string
	)

	BeforeEach(func() {
		baseURL = os.Getenv("CORTEX_TEST_ELASTICSEARCH_URL")
		if baseURL == "" {
			Skip("set CORTEX_TEST_ELASTICSEARCH_URL to run Elasticsearch integration tests")
		}
		index = fmt.Sprintf("hyperion-subs-test-%d", time.Now().UnixNano())

		percolator = elasticsearch.NewPercolator(nil, baseURL, index)
		Expect(percolator.Ready(ctx)).To(Succeed())

		DeferCleanup(func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL+"/"+index, nil)
			Expect(err).ToNot(HaveOccurred())
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		})
	})

	lodash := valueobject.NewPackageRef("npm", "lodash", "")
	next := valueobject.NewPackageRef("npm", "next", "")

	sub := func(id, name string, rule model.AlertRule) model.Subscription {
		return model.Subscription{ID: id, Tenant: "acme", Name: name, Rule: rule}
	}
	vuln := func(cve, title string, severity model.Severity, pkgs ...valueobject.PackageRef) model.Vulnerability {
		v := model.Vulnerability{CVEID: cve, Title: title, AffectedPackages: pkgs}
		if severity != model.SeverityUnknown {
			v.Scores = []model.CVSS{{Severity: severity}}
		}
		return v
	}

	It("is ready and creates its index idempotently", func() {
		Expect(percolator.Ready(ctx)).To(Succeed())
	})

	It("matches a free-text rule", func() {
		Expect(percolator.Register(ctx, sub("s1", "Log4j watch",
			model.AlertRule{Term: "log4j"}))).To(Succeed())

		hits, err := percolator.Match(ctx, vuln("CVE-2021-44228", "Log4Shell in log4j", model.SeverityCritical))
		Expect(err).ToNot(HaveOccurred())
		Expect(hits).To(ConsistOf("s1"))
	})

	It("does not match a rule whose term is absent", func() {
		Expect(percolator.Register(ctx, sub("s1", "Log4j watch",
			model.AlertRule{Term: "log4j"}))).To(Succeed())

		hits, err := percolator.Match(ctx, vuln("CVE-1", "an unrelated flaw", model.SeverityCritical))
		Expect(err).ToNot(HaveOccurred())
		Expect(hits).To(BeEmpty())
	})

	It("matches a minimum severity, inclusive, and excludes what is below", func() {
		Expect(percolator.Register(ctx, sub("s1", "High and above",
			model.AlertRule{MinSeverity: model.SeverityHigh}))).To(Succeed())

		high, err := percolator.Match(ctx, vuln("CVE-1", "x", model.SeverityHigh))
		Expect(err).ToNot(HaveOccurred())
		Expect(high).To(ConsistOf("s1"))

		medium, err := percolator.Match(ctx, vuln("CVE-2", "x", model.SeverityMedium))
		Expect(err).ToNot(HaveOccurred())
		Expect(medium).To(BeEmpty())
	})

	It("never matches an unscored finding against a severity threshold", func() {
		// "We don't know how bad this is" must not clear a bar.
		Expect(percolator.Register(ctx, sub("s1", "High and above",
			model.AlertRule{MinSeverity: model.SeverityHigh}))).To(Succeed())

		hits, err := percolator.Match(ctx, vuln("CVE-1", "x", model.SeverityUnknown))
		Expect(err).ToNot(HaveOccurred())
		Expect(hits).To(BeEmpty())
	})

	It("matches a watched library regardless of the affected version range", func() {
		Expect(percolator.Register(ctx, sub("s1", "lodash",
			model.AlertRule{Packages: []valueobject.PackageRef{lodash}}))).To(Succeed())

		pinned := valueobject.NewPackageRef("npm", "lodash", "< 4.17.21")
		hits, err := percolator.Match(ctx, vuln("CVE-1", "x", model.SeverityHigh, pinned))
		Expect(err).ToNot(HaveOccurred())
		Expect(hits).To(ConsistOf("s1"))
	})

	It("keeps the same package name in different ecosystems apart", func() {
		Expect(percolator.Register(ctx, sub("s1", "pypi requests",
			model.AlertRule{Packages: []valueobject.PackageRef{
				valueobject.NewPackageRef("pypi", "requests", "")}}))).To(Succeed())

		gem := valueobject.NewPackageRef("rubygems", "requests", "")
		hits, err := percolator.Match(ctx, vuln("CVE-1", "x", model.SeverityHigh, gem))
		Expect(err).ToNot(HaveOccurred())
		Expect(hits).To(BeEmpty())
	})

	It("ANDs conditions, so each one narrows the match", func() {
		Expect(percolator.Register(ctx, sub("s1", "critical lodash",
			model.AlertRule{MinSeverity: model.SeverityCritical,
				Packages: []valueobject.PackageRef{lodash}}))).To(Succeed())

		both, err := percolator.Match(ctx, vuln("CVE-1", "x", model.SeverityCritical, lodash))
		Expect(err).ToNot(HaveOccurred())
		Expect(both).To(ConsistOf("s1"))

		wrongPackage, err := percolator.Match(ctx, vuln("CVE-2", "x", model.SeverityCritical, next))
		Expect(err).ToNot(HaveOccurred())
		Expect(wrongPackage).To(BeEmpty())

		wrongSeverity, err := percolator.Match(ctx, vuln("CVE-3", "x", model.SeverityLow, lodash))
		Expect(err).ToNot(HaveOccurred())
		Expect(wrongSeverity).To(BeEmpty())
	})

	It("returns every subscription a vulnerability satisfies", func() {
		Expect(percolator.Register(ctx, sub("s1", "log4j", model.AlertRule{Term: "log4j"}))).To(Succeed())
		Expect(percolator.Register(ctx, sub("s2", "critical",
			model.AlertRule{MinSeverity: model.SeverityCritical}))).To(Succeed())
		Expect(percolator.Register(ctx, sub("s3", "next",
			model.AlertRule{Packages: []valueobject.PackageRef{next}}))).To(Succeed())

		hits, err := percolator.Match(ctx, vuln("CVE-2021-44228", "Log4Shell in log4j", model.SeverityCritical))
		Expect(err).ToNot(HaveOccurred())
		Expect(hits).To(ConsistOf("s1", "s2"))
	})

	It("makes a rule matchable immediately after registering it", func() {
		// Without an explicit refresh a subscription could miss the very
		// advisory that prompted someone to create it.
		Expect(percolator.Register(ctx, sub("s1", "log4j", model.AlertRule{Term: "log4j"}))).To(Succeed())

		hits, err := percolator.Match(ctx, vuln("CVE-1", "log4j flaw", model.SeverityHigh))
		Expect(err).ToNot(HaveOccurred())
		Expect(hits).To(ConsistOf("s1"))
	})

	It("stops matching a deregistered rule", func() {
		Expect(percolator.Register(ctx, sub("s1", "log4j", model.AlertRule{Term: "log4j"}))).To(Succeed())
		Expect(percolator.Deregister(ctx, "s1")).To(Succeed())

		hits, err := percolator.Match(ctx, vuln("CVE-1", "log4j flaw", model.SeverityHigh))
		Expect(err).ToNot(HaveOccurred())
		Expect(hits).To(BeEmpty())
	})

	It("treats deregistering an absent rule as success", func() {
		Expect(percolator.Deregister(ctx, "never-existed")).To(Succeed())
	})

	It("rejects an empty rule rather than indexing a match-all", func() {
		err := percolator.Register(ctx, sub("s1", "everything", model.AlertRule{}))
		Expect(err).To(MatchError(model.ErrEmptyAlertRule))
	})

	It("reports no subscribers when nothing has ever been registered", func() {
		absent := elasticsearch.NewPercolator(nil, baseURL,
			fmt.Sprintf("hyperion-subs-missing-%d", time.Now().UnixNano()))

		hits, err := absent.Match(ctx, vuln("CVE-1", "x", model.SeverityHigh))
		Expect(err).ToNot(HaveOccurred(), "an index nobody has written to means nobody is subscribed")
		Expect(hits).To(BeEmpty())
	})
})
