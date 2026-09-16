package neo4j_test

import (
	"context"
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sdk "github.com/neo4j/neo4j-go-driver/v5/neo4j"

	graphadapter "github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/neo4j"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

var _ = Describe("Neo4j vulnerability removal (integration)", func() {
	var (
		ctx    = context.Background()
		graph  *graphadapter.Graph
		driver sdk.DriverWithContext
		prefix string
		oldID  string
		newID  string
	)

	count := func(cypher string, params map[string]any) int64 {
		session := driver.NewSession(ctx, sdk.SessionConfig{DatabaseName: databaseName()})
		defer session.Close(ctx)
		result, err := session.Run(ctx, cypher, params)
		Expect(err).ToNot(HaveOccurred())
		record, err := result.Single(ctx)
		Expect(err).ToNot(HaveOccurred())
		n, _ := record.Get("n")
		return n.(int64)
	}

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
		driver, err = sdk.NewDriverWithContext(cfg.URI, sdk.BasicAuth(cfg.Username, cfg.Password, ""))
		Expect(err).ToNot(HaveOccurred())

		stamp := time.Now().UnixNano()
		prefix = fmt.Sprintf("hyptest%d", stamp)
		oldID = fmt.Sprintf("GHSA-test-%d", stamp)
		newID = fmt.Sprintf("CVE-2998-%d", stamp%100000)

		DeferCleanup(func() {
			session := driver.NewSession(ctx, sdk.SessionConfig{DatabaseName: databaseName()})
			_, _ = session.Run(ctx, `MATCH (n) WHERE coalesce(n.name, '') STARTS WITH $prefix
				OR coalesce(n.cve_id, '') IN [$old, $new] DETACH DELETE n`,
				map[string]any{"prefix": prefix, "old": oldID, "new": newID})
			_ = session.Close(ctx)
			Expect(driver.Close(ctx)).To(Succeed())
			Expect(graph.Close(ctx)).To(Succeed())
		})
	})

	It("removes a re-keyed finding's node and edges, leaving its libraries and the new node", func() {
		pkg := []valueobject.PackageRef{valueobject.NewPackageRef("npm", prefix+"-lib", "< 1.0.0")}
		Expect(graph.LinkVulnerability(ctx, oldID, pkg)).To(Succeed())
		Expect(graph.LinkVulnerability(ctx, newID, pkg)).To(Succeed())

		Expect(graph.RemoveVulnerabilities(ctx, []string{oldID})).To(Succeed())

		Expect(count(`MATCH (v:Vulnerability {cve_id: $id}) RETURN count(v) AS n`, map[string]any{"id": oldID})).To(BeZero())
		Expect(count(`MATCH (:Library)-[:AFFECTED_BY]->(v:Vulnerability {cve_id: $id}) RETURN count(v) AS n`,
			map[string]any{"id": newID})).To(Equal(int64(1)))
		Expect(count(`MATCH (l:Library) WHERE l.name STARTS WITH $prefix RETURN count(l) AS n`,
			map[string]any{"prefix": prefix})).To(Equal(int64(1)))
	})

	It("treats removing an absent node, or nothing, as success", func() {
		Expect(graph.RemoveVulnerabilities(ctx, []string{oldID})).To(Succeed())
		Expect(graph.RemoveVulnerabilities(ctx, nil)).To(Succeed())
	})
})
