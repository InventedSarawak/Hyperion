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
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// A lockfile records which package pulled in which. Keeping that is what lets
// the graph answer "how does this reach me?" with a path instead of "it just
// does" — the repository has an edge to every installed package either way.
var _ = Describe("Neo4j transitive dependencies (integration)", func() {
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
		cveID = fmt.Sprintf("CVE-2996-%d", stamp%100000)

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
	})

	// app depends on express; express pulls in body-parser; body-parser pulls
	// in bytes, which is the vulnerable one. The lockfile lists all three
	// against the repository, as lockfiles do.
	lockfileSnapshot := func() model.RepositorySnapshot {
		ref := func(name string) valueobject.PackageRef {
			return valueobject.PackageRef{Ecosystem: valueobject.EcosystemNPM, Name: prefix + name}
		}
		dep := func(name, version string, direct bool, needs ...string) model.Dependency {
			d := model.Dependency{
				Package:      valueobject.PackageRef{Ecosystem: valueobject.EcosystemNPM, Name: prefix + name, Version: version},
				Direct:       direct,
				Locked:       true,
				ManifestPath: "package-lock.json",
			}
			for _, n := range needs {
				d.DependsOn = append(d.DependsOn, ref(n))
			}
			return d
		}
		return model.RepositorySnapshot{
			Repository: model.Repository{Owner: prefix, Name: "app"},
			Dependencies: []model.Dependency{
				dep("express", "4.18.2", true, "bodyparser"),
				dep("bodyparser", "1.20.1", false, "bytes"),
				dep("bytes", "3.1.2", false),
			},
			ObservedAt: time.Now().UTC(),
		}
	}

	It("reports the chain a package arrived through, not the flat edge", func() {
		snapshot := lockfileSnapshot()
		_, err := graph.UpsertRepositorySnapshot(ctx, snapshot)
		Expect(err).ToNot(HaveOccurred())
		Expect(graph.LinkVulnerability(ctx, cveID, []valueobject.PackageRef{
			{Ecosystem: valueobject.EcosystemNPM, Name: prefix + "bytes"},
		})).To(Succeed())

		radius, err := graph.FindBlastRadius(ctx, cveID, 5, 100)
		Expect(err).ToNot(HaveOccurred())
		Expect(radius.Repositories).To(HaveLen(1))

		reached := radius.Repositories[0]
		Expect(reached.Path).To(Equal([]string{
			prefix + "/app",
			"npm:" + prefix + "express",
			"npm:" + prefix + "bodyparser",
			"npm:" + prefix + "bytes",
		}), "the lockfile knows which dependency pulled it in")
		Expect(reached.Depth).To(Equal(3))
		Expect(reached.Direct).To(BeFalse())
	})

	It("still reports a declared dependency at depth 1", func() {
		// For a package the repository actually asked for, the first hop is
		// the whole answer — a longer route to it would be noise.
		snapshot := lockfileSnapshot()
		_, err := graph.UpsertRepositorySnapshot(ctx, snapshot)
		Expect(err).ToNot(HaveOccurred())
		Expect(graph.LinkVulnerability(ctx, cveID, []valueobject.PackageRef{
			{Ecosystem: valueobject.EcosystemNPM, Name: prefix + "express"},
		})).To(Succeed())

		radius, err := graph.FindBlastRadius(ctx, cveID, 5, 100)
		Expect(err).ToNot(HaveOccurred())
		Expect(radius.Repositories).To(HaveLen(1))
		Expect(radius.Repositories[0].Depth).To(Equal(1))
		Expect(radius.Repositories[0].Direct).To(BeTrue())
	})

	It("writes no edge to a package the lockfile named but did not install", func() {
		// A requirement can name an optional peer or a platform-specific
		// build that nothing resolved. An edge to it would invent a
		// dependency that is not there.
		snapshot := lockfileSnapshot()
		snapshot.Dependencies[0].DependsOn = append(snapshot.Dependencies[0].DependsOn,
			valueobject.PackageRef{Ecosystem: valueobject.EcosystemNPM, Name: prefix + "neverinstalled"})
		_, err := graph.UpsertRepositorySnapshot(ctx, snapshot)
		Expect(err).ToNot(HaveOccurred())

		Expect(snapshot.LibraryEdges()).To(HaveLen(2))
	})
})
