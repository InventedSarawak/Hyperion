package neo4j_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sdk "github.com/neo4j/neo4j-go-driver/v5/neo4j"

	graphadapter "github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/neo4j"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

var _ = Describe("Neo4j repository exposure (integration)", func() {
	var (
		ctx    = context.Background()
		graph  *graphadapter.Graph
		prefix string
		cveID  string
	)

	BeforeEach(func() {
		uri := os.Getenv("CORTEX_TEST_NEO4J_URI")
		if uri == "" {
			Skip("set CORTEX_TEST_NEO4J_URI to run Neo4j integration tests")
		}
		cfg := graphadapter.Config{
			URI:      uri,
			Username: envOr("CORTEX_TEST_NEO4J_USERNAME", "neo4j"),
			Password: envOr("CORTEX_TEST_NEO4J_PASSWORD", "hyperion"),
			Database: databaseName(),
		}
		var err error
		graph, err = graphadapter.Connect(ctx, cfg)
		Expect(err).ToNot(HaveOccurred())
		Expect(graph.EnsureSchema(ctx)).To(Succeed())

		stamp := time.Now().UnixNano()
		prefix = fmt.Sprintf("hyptest%d", stamp)
		cveID = fmt.Sprintf("CVE-2997-%d", stamp%100000)

		DeferCleanup(func() {
			driver, err := sdk.NewDriverWithContext(cfg.URI, sdk.BasicAuth(cfg.Username, cfg.Password, ""))
			if err == nil {
				session := driver.NewSession(ctx, sdk.SessionConfig{DatabaseName: databaseName()})
				_, _ = session.Run(ctx, `MATCH (n) WHERE coalesce(n.full_name, '') STARTS WITH $prefix
					OR coalesce(n.name, '') STARTS WITH $prefix OR coalesce(n.login, '') STARTS WITH $prefix
					OR coalesce(n.cve_id, '') = $cve DETACH DELETE n`, map[string]any{"prefix": prefix, "cve": cveID})
				_ = session.Close(ctx)
				_ = driver.Close(ctx)
			}
			Expect(graph.Close(ctx)).To(Succeed())
		})

		_, err = graph.UpsertRepositorySnapshot(ctx, model.RepositorySnapshot{
			Repository: model.Repository{Owner: prefix, Name: "app", URL: "https://example.test/" + prefix + "/app", DefaultBranch: "main"},
			Author:     model.Author{Login: prefix},
			Dependencies: []model.Dependency{{
				Package:      valueobject.NewPackageRef("npm", prefix+"-lib", "^1.2.0"),
				Direct:       true,
				ManifestPath: "package.json",
			}},
			ObservedAt: time.Now().UTC(),
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(graph.LinkVulnerability(ctx, cveID,
			[]valueobject.PackageRef{valueobject.NewPackageRef("npm", prefix+"-lib", "< 1.3.0")})).To(Succeed())
	})

	It("walks from a repository to the findings its dependencies reach, with both versions", func() {
		got, err := graph.FindRepositoryExposures(ctx, []string{strings.ToUpper(prefix + "/app")}, 3)

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].Repository).To(Equal(prefix + "/app"))
		Expect(got[0].Finding.CVEID).To(Equal(cveID))
		Expect(got[0].Package.Name).To(Equal(prefix + "-lib"))
		Expect(got[0].Package.Version).To(Equal("^1.2.0"), "what the manifest declares")
		Expect(got[0].AffectedVersions).To(Equal("< 1.3.0"), "what the advisory says")
		Expect(got[0].Depth).To(Equal(1))
		Expect(got[0].Direct).To(BeTrue())
	})

	It("carries both versions on blast radius too", func() {
		radius, err := graph.FindBlastRadius(ctx, cveID, 3, 10)

		Expect(err).ToNot(HaveOccurred())
		Expect(radius.Repositories).To(HaveLen(1))
		Expect(radius.Repositories[0].DeclaredVersion).To(Equal("^1.2.0"))
		Expect(radius.Repositories[0].AffectedVersions).To(Equal("< 1.3.0"))
	})

	It("knows which repositories it has", func() {
		Expect(graph.HasRepository(ctx, prefix+"/app")).To(BeTrue())
		Expect(graph.HasRepository(ctx, prefix+"/missing")).To(BeFalse())
	})
})
