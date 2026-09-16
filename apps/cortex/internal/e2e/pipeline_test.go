// Package e2e drives cortex end to end: an event in the shape siphon
// publishes, through the real consumer, use cases and databases, out again as
// search results, a blast radius and a repository's exposure.
//
// Every layer here is the real one — Postgres, Elasticsearch and Neo4j — so
// the suite is skipped unless all three are configured, the same way the
// adapter suites are:
//
//	task infra:up
//	task test:go:integration
package e2e_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	eventsv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/events/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/inbound/consumer"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/elasticsearch"
	graphadapter "github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/neo4j"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/postgres"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var _ = Describe("The pipeline, end to end", func() {
	var (
		ctx      = context.Background()
		esURL    string
		esIndex  string
		prefix   string
		repo     *postgres.Repo
		index    *elasticsearch.Index
		graph    *graphadapter.Graph
		ingest   *commands.IngestSignal
		deps     *commands.IngestDependency
		search   *queries.Search
		blast    *queries.CalculateBlastRadius
		exposure *queries.RepositoryExposure
	)

	// refresh makes recent writes visible to search at once; Elasticsearch is
	// near-real-time, and a test cannot wait a second for every assertion.
	refresh := func() {
		GinkgoHelper()
		resp, err := http.Post(esURL+"/"+esIndex+"/_refresh", "application/json", nil)
		Expect(err).ToNot(HaveOccurred())
		resp.Body.Close()
	}

	BeforeEach(func() {
		dsn := os.Getenv("CORTEX_TEST_DATABASE_URL")
		esURL = os.Getenv("CORTEX_TEST_ELASTICSEARCH_URL")
		neo4jURI := os.Getenv("CORTEX_TEST_NEO4J_URI")
		if dsn == "" || esURL == "" || neo4jURI == "" {
			Skip("set CORTEX_TEST_DATABASE_URL, CORTEX_TEST_ELASTICSEARCH_URL and CORTEX_TEST_NEO4J_URI")
		}
		stamp := time.Now().UnixNano()
		prefix = fmt.Sprintf("hyptest%d", stamp)
		esIndex = fmt.Sprintf("hyperion-e2e-%d", stamp)

		// Postgres: a throwaway schema, so the suite can never touch real rows.
		schema := fmt.Sprintf("hyperion_e2e_%d", stamp)
		admin, err := postgres.Connect(ctx, dsn)
		Expect(err).ToNot(HaveOccurred())
		_, err = admin.Exec(ctx, "CREATE SCHEMA "+schema)
		Expect(err).ToNot(HaveOccurred())
		admin.Close()

		scoped, err := url.Parse(dsn)
		Expect(err).ToNot(HaveOccurred())
		q := scoped.Query()
		q.Set("search_path", schema)
		scoped.RawQuery = q.Encode()

		pool, err := postgres.Connect(ctx, scoped.String())
		Expect(err).ToNot(HaveOccurred())
		Expect(postgres.Migrate(ctx, pool)).To(Succeed())
		repo = postgres.NewRepo(pool)

		index = elasticsearch.New(nil, esURL, esIndex)
		Expect(index.Ready(ctx)).To(Succeed())

		graph, err = graphadapter.Connect(ctx, graphadapter.Config{
			URI:      neo4jURI,
			Username: envOr("CORTEX_TEST_NEO4J_USERNAME", "neo4j"),
			Password: envOr("CORTEX_TEST_NEO4J_PASSWORD", "hyperion"),
			Database: envOr("CORTEX_TEST_NEO4J_DATABASE", "neo4j"),
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(graph.EnsureSchema(ctx)).To(Succeed())

		ingest = commands.NewIngestSignal(repo, index, graph, nil)
		deps = commands.NewIngestDependency(graph)
		search = queries.NewSearch(index)
		blast = queries.NewCalculateBlastRadius(graph, 3).WithResolver(repo)
		exposure = queries.NewRepositoryExposure(graph, repo, 3)

		DeferCleanup(func() {
			Expect(graph.RemoveRepository(ctx, prefix+"/app")).To(Succeed())
			Expect(graph.RemoveVulnerabilities(ctx, []string{prefix + "-MAL", prefix + "-CVE"})).To(Succeed())
			pool.Close()
			if cleanup, err := postgres.Connect(ctx, dsn); err == nil {
				_, _ = cleanup.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
				cleanup.Close()
			}
			req, _ := http.NewRequest(http.MethodDelete, esURL+"/"+esIndex, nil)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				resp.Body.Close()
			}
		})
	})

	// event builds the protojson line siphon publishes for one finding.
	event := func(v *commonv1.Vulnerability) string {
		GinkgoHelper()
		line, err := protojson.Marshal(&eventsv1.SignalDiscovered{
			SignalId:      "package_feed:" + v.GetCveId(),
			Source:        eventsv1.SourceKind_SOURCE_KIND_PACKAGE_FEED,
			DiscoveredAt:  timestamppb.New(time.Now()),
			Vulnerability: v,
		})
		Expect(err).ToNot(HaveOccurred())
		return string(line)
	}

	It("carries a finding from the wire into storage, search and the graph", func() {
		malwareID := prefix + "-MAL"
		line := event(&commonv1.Vulnerability{
			CveId:       malwareID,
			Aliases:     []string{prefix + "-GHSA"},
			Kind:        commonv1.FindingKind_FINDING_KIND_MALWARE,
			Title:       "Malicious code in " + prefix + "-axios",
			Description: "Any machine that installed it should be considered compromised.",
			Scores:      []*commonv1.Cvss{{Severity: commonv1.Severity_SEVERITY_CRITICAL}},
			AffectedPackages: []*commonv1.PackageRef{
				{Ecosystem: commonv1.Ecosystem_ECOSYSTEM_NPM, Name: prefix + "-axios", Version: "= 1.14.1"},
			},
			PublishedAt: timestamppb.New(time.Now()),
		})

		read, err := consumer.NewConsumer(ingest).Run(ctx, stringReader(line))
		Expect(err).ToNot(HaveOccurred())
		Expect(read).To(Equal(1))

		By("storing it under its canonical id, findable by every id it carries")
		stored, err := repo.GetByID(ctx, prefix+"-GHSA")
		Expect(err).ToNot(HaveOccurred())
		Expect(stored.CVEID).To(Equal(malwareID))
		Expect(stored.IsMalware()).To(BeTrue())

		By("making it searchable, but not among ordinary vulnerabilities")
		refresh()
		hits, err := search.Handle(ctx, prefix+"-axios", model.SortRelevance, nil, 10, "")
		Expect(err).ToNot(HaveOccurred())
		Expect(hits.Hits).ToNot(BeEmpty())
		Expect(hits.Hits[0].Vulnerability.CVEID).To(Equal(malwareID))

		onlyVulns, err := search.Handle(ctx, prefix+"-axios", model.SortRelevance,
			[]model.FindingKind{model.KindVulnerability}, 10, "")
		Expect(err).ToNot(HaveOccurred())
		Expect(onlyVulns.Hits).To(BeEmpty(), "malware is not an ordinary vulnerability")

		By("linking it to the library it affects")
		radius, err := blast.Handle(ctx, prefix+"-GHSA", 3, 10)
		Expect(err).ToNot(HaveOccurred())
		Expect(radius.CVEID).To(Equal(malwareID), "asked by alias, answered by canonical id")
		Expect(radius.Linked()).To(BeTrue())
	})

	It("judges a repository by the versions its lockfile pins", func() {
		malwareID, flawID := prefix+"-MAL", prefix+"-CVE"
		lines := event(&commonv1.Vulnerability{
			CveId: malwareID,
			Kind:  commonv1.FindingKind_FINDING_KIND_MALWARE,
			Title: "Malicious code in " + prefix + "-axios",
			AffectedPackages: []*commonv1.PackageRef{
				{Ecosystem: commonv1.Ecosystem_ECOSYSTEM_NPM, Name: prefix + "-axios", Version: "= 1.14.1"},
			},
		}) + "\n" + event(&commonv1.Vulnerability{
			CveId:  flawID,
			Title:  "Prototype pollution in " + prefix + "-lodash",
			Scores: []*commonv1.Cvss{{Severity: commonv1.Severity_SEVERITY_CRITICAL, BaseScore: 9.8}},
			AffectedPackages: []*commonv1.PackageRef{
				{Ecosystem: commonv1.Ecosystem_ECOSYSTEM_NPM, Name: prefix + "-lodash", Version: "< 4.17.12"},
			},
		})
		_, err := consumer.NewConsumer(ingest).Run(ctx, stringReader(lines))
		Expect(err).ToNot(HaveOccurred())

		By("reading the repository's manifests and lockfile")
		written, err := deps.Handle(ctx, model.RepositorySnapshot{
			Repository: model.Repository{Owner: prefix, Name: "app", DefaultBranch: "main"},
			Dependencies: []model.Dependency{
				// The manifest allows the compromised release; the lockfile
				// rules it out, and the lockfile is what is installed.
				{Package: valueobject.NewPackageRef("npm", prefix+"-axios", "^1.13.2"), Direct: true, ManifestPath: "package.json"},
				{Package: valueobject.NewPackageRef("npm", prefix+"-axios", "1.13.2"), Locked: true, ManifestPath: "pnpm-lock.yaml"},
				{Package: valueobject.NewPackageRef("npm", prefix+"-lodash", "4.17.4"), Locked: true, ManifestPath: "pnpm-lock.yaml"},
			},
			ObservedAt: time.Now().UTC(),
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(written).To(Equal(2), "one edge per library, the locked version winning")

		By("ruling out what the installed version is not exposed to")
		got, err := exposure.Handle(ctx, prefix+"/app", 3, true)
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Scanned).To(BeTrue())

		verdicts := map[string]valueobject.ExposureVerdict{}
		versions := map[string]string{}
		for _, f := range got.Findings {
			verdicts[f.Finding.CVEID] = f.Verdict
			versions[f.Finding.CVEID] = f.Package.Version
		}
		Expect(versions[malwareID]).To(Equal("1.13.2"), "the locked version, not the declared range")
		Expect(verdicts[malwareID]).To(Equal(valueobject.ExposureNotAffected))
		Expect(verdicts[flawID]).To(Equal(valueobject.ExposureAffected))

		By("flagging the repository by what it is actually exposed to")
		Expect(got.Summary.CriticalAffected).To(Equal(1), "the lodash flaw")
		Expect(got.Summary.Total).To(Equal(1), "the malware is ruled out by version")

		By("answering the same question from the finding's side")
		radius, err := blast.Handle(ctx, flawID, 3, 10)
		Expect(err).ToNot(HaveOccurred())
		Expect(radius.Repositories).To(HaveLen(1))
		Expect(radius.Repositories[0].Repository.FullName()).To(Equal(prefix + "/app"))
		Expect(radius.Repositories[0].Verdict).To(Equal(valueobject.ExposureAffected))
	})
})
