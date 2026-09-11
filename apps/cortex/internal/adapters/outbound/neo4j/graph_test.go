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

// This suite needs a real Neo4j. It is skipped unless CORTEX_TEST_NEO4J_URI is
// set, e.g.:
//
//	docker compose -f deploy/docker-compose.yml up -d neo4j
//	CORTEX_TEST_NEO4J_URI=bolt://localhost:7687 \
//	  go test ./internal/adapters/outbound/neo4j/...
//
// Neo4j Community serves a single database, so unlike the Postgres suite these
// specs cannot hide in a throwaway namespace. Instead every node they create
// carries a per-run prefix, and cleanup deletes exactly those.
var _ = Describe("Neo4j DependencyGraph (integration)", func() {
	var (
		ctx    = context.Background()
		graph  *graphadapter.Graph
		driver sdk.DriverWithContext
		prefix string
		cveID  string
	)

	// run executes raw Cypher, for building fixtures the adapter cannot write
	// and for cleaning up afterwards.
	run := func(cypher string, params map[string]any) {
		session := driver.NewSession(ctx, sdk.SessionConfig{DatabaseName: databaseName()})
		defer session.Close(ctx)
		_, err := session.Run(ctx, cypher, params)
		Expect(err).ToNot(HaveOccurred())
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

		prefix = fmt.Sprintf("hyptest%d", time.Now().UnixNano())
		cveID = fmt.Sprintf("CVE-2999-%d", time.Now().UnixNano()%100000)

		DeferCleanup(func() {
			run(`MATCH (n)
			     WHERE coalesce(n.full_name, '') STARTS WITH $prefix
			        OR coalesce(n.name, '')      STARTS WITH $prefix
			        OR coalesce(n.login, '')     STARTS WITH $prefix
			        OR coalesce(n.cve_id, '')    = $cve
			     DETACH DELETE n`,
				map[string]any{"prefix": prefix, "cve": cveID})
			Expect(driver.Close(ctx)).To(Succeed())
			Expect(graph.Close(ctx)).To(Succeed())
		})
	})

	// snapshot builds a repository requiring the named libraries. Every
	// identifier is prefixed so cleanup can find it again.
	snapshot := func(repoName string, deps ...model.Dependency) model.RepositorySnapshot {
		return model.RepositorySnapshot{
			Repository: model.Repository{
				Owner:         prefix,
				Name:          repoName,
				URL:           "https://example.test/" + prefix + "/" + repoName,
				DefaultBranch: "main",
			},
			Author:       model.Author{Login: prefix, Name: "Test Org"},
			Dependencies: deps,
			ObservedAt:   time.Now().UTC(),
		}
	}
	lib := func(name, version string, direct bool) model.Dependency {
		return model.Dependency{
			Package:      valueobject.NewPackageRef("go", prefix+"/"+name, version),
			Direct:       direct,
			ManifestPath: "go.mod",
		}
	}
	libRef := func(name string) valueobject.PackageRef {
		return valueobject.NewPackageRef("go", prefix+"/"+name, "")
	}

	// publishing builds a snapshot for a repository that ships a library, so
	// its direct requirements become that library's requirements too.
	publishing := func(repoName, moduleName string, deps ...model.Dependency) model.RepositorySnapshot {
		s := snapshot(repoName, deps...)
		s.Publishes = valueobject.NewPackageRef("go", prefix+"/"+moduleName, "")
		return s
	}

	It("is ready and creates its schema idempotently", func() {
		Expect(graph.Ready(ctx)).To(Succeed())
		Expect(graph.EnsureSchema(ctx)).To(Succeed())
	})

	It("writes a manifest as repository, author and dependency edges", func() {
		n, err := graph.UpsertRepositorySnapshot(ctx,
			snapshot("api", lib("net", "v0.17.0", true), lib("sys", "v0.13.0", false)))

		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(2))

		session := driver.NewSession(ctx, sdk.SessionConfig{DatabaseName: databaseName()})
		defer session.Close(ctx)
		result, err := session.Run(ctx,
			`MATCH (a:Author {login: $login})-[:MAINTAINS]->(r:Repository)-[e:DEPENDS_ON]->(l:Library)
			 RETURN count(e) AS edges, collect(l.key) AS libs`,
			map[string]any{"login": prefix})
		Expect(err).ToNot(HaveOccurred())
		record, err := result.Single(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(record.Values[0]).To(Equal(int64(2)))
	})

	It("re-reading an unchanged manifest does not duplicate the graph", func() {
		s := snapshot("api", lib("net", "v0.17.0", true))
		_, err := graph.UpsertRepositorySnapshot(ctx, s)
		Expect(err).ToNot(HaveOccurred())
		_, err = graph.UpsertRepositorySnapshot(ctx, s)
		Expect(err).ToNot(HaveOccurred())

		session := driver.NewSession(ctx, sdk.SessionConfig{DatabaseName: databaseName()})
		defer session.Close(ctx)
		result, err := session.Run(ctx,
			`MATCH (r:Repository {full_name: $full})-[e:DEPENDS_ON]->() RETURN count(e) AS edges`,
			map[string]any{"full": prefix + "/api"})
		Expect(err).ToNot(HaveOccurred())
		record, err := result.Single(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(record.Values[0]).To(Equal(int64(1)), "MERGE must not create a second edge")
	})

	It("records a repository that has no dependencies at all", func() {
		n, err := graph.UpsertRepositorySnapshot(ctx, snapshot("empty"))
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(0))

		session := driver.NewSession(ctx, sdk.SessionConfig{DatabaseName: databaseName()})
		defer session.Close(ctx)
		result, err := session.Run(ctx,
			`MATCH (r:Repository {full_name: $full}) RETURN count(r) AS n`,
			map[string]any{"full": prefix + "/empty"})
		Expect(err).ToNot(HaveOccurred())
		record, err := result.Single(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(record.Values[0]).To(Equal(int64(1)))
	})

	Describe("blast radius", func() {
		It("reports an unlinked CVE as unanswered, not as 'nothing affected'", func() {
			_, err := graph.UpsertRepositorySnapshot(ctx, snapshot("api", lib("net", "v0.17.0", true)))
			Expect(err).ToNot(HaveOccurred())

			radius, err := graph.FindBlastRadius(ctx, cveID, 3, 100)
			Expect(err).ToNot(HaveOccurred())
			Expect(radius.Linked()).To(BeFalse())
			Expect(radius.Repositories).To(BeEmpty())
		})

		It("finds every repository that directly requires the vulnerable library", func() {
			_, err := graph.UpsertRepositorySnapshot(ctx, snapshot("api", lib("net", "v0.17.0", true)))
			Expect(err).ToNot(HaveOccurred())
			_, err = graph.UpsertRepositorySnapshot(ctx, snapshot("worker", lib("net", "v0.16.0", true)))
			Expect(err).ToNot(HaveOccurred())

			Expect(graph.LinkVulnerability(ctx, cveID, []valueobject.PackageRef{libRef("net")})).To(Succeed())

			radius, err := graph.FindBlastRadius(ctx, cveID, 3, 100)
			Expect(err).ToNot(HaveOccurred())
			Expect(radius.CVEID).To(Equal(cveID))
			Expect(radius.Linked()).To(BeTrue())
			Expect(radius.TotalRepositories()).To(Equal(2))

			names := []string{}
			for _, r := range radius.Repositories {
				names = append(names, r.Repository.FullName())
				Expect(r.Depth).To(Equal(1))
				Expect(r.Direct).To(BeTrue())
				Expect(r.Author.Login).To(Equal(prefix))
				Expect(r.ViaPackage.Name).To(Equal(prefix + "/net"))
			}
			Expect(names).To(ConsistOf(prefix+"/api", prefix+"/worker"))
		})

		It("marks an indirect requirement as not direct", func() {
			_, err := graph.UpsertRepositorySnapshot(ctx, snapshot("api", lib("net", "v0.17.0", false)))
			Expect(err).ToNot(HaveOccurred())
			Expect(graph.LinkVulnerability(ctx, cveID, []valueobject.PackageRef{libRef("net")})).To(Succeed())

			radius, err := graph.FindBlastRadius(ctx, cveID, 3, 100)
			Expect(err).ToNot(HaveOccurred())
			Expect(radius.Repositories).To(HaveLen(1))
			Expect(radius.Repositories[0].Direct).To(BeFalse())
		})

		It("traverses library-to-library edges recursively and reports the path", func() {
			// The manifest reader only writes repo->lib edges today, so the
			// lib->lib hop is built here directly. It exercises the recursion
			// the DEPENDS_ON*1..n traversal exists for.
			_, err := graph.UpsertRepositorySnapshot(ctx, snapshot("api", lib("framework", "v1.0.0", true)))
			Expect(err).ToNot(HaveOccurred())

			run(`MATCH (framework:Library {key: $framework})
			     MERGE (transitive:Library {key: $transitive})
			     ON CREATE SET transitive.ecosystem = 'go', transitive.name = $transitiveName
			     MERGE (framework)-[:DEPENDS_ON {direct: true}]->(transitive)`,
				map[string]any{
					"framework":      libRef("framework").Key(),
					"transitive":     libRef("crypto").Key(),
					"transitiveName": prefix + "/crypto",
				})

			Expect(graph.LinkVulnerability(ctx, cveID, []valueobject.PackageRef{libRef("crypto")})).To(Succeed())

			radius, err := graph.FindBlastRadius(ctx, cveID, 3, 100)
			Expect(err).ToNot(HaveOccurred())
			Expect(radius.Repositories).To(HaveLen(1))

			hit := radius.Repositories[0]
			Expect(hit.Repository.FullName()).To(Equal(prefix + "/api"))
			Expect(hit.Depth).To(Equal(2))
			Expect(hit.Direct).To(BeFalse(), "reached through another library, not the repo's own manifest")
			Expect(hit.Path).To(Equal([]string{
				prefix + "/api",
				libRef("framework").Key(),
				libRef("crypto").Key(),
			}))
		})

		It("reaches through a library published by another scanned repository", func() {
			// Two ordinary manifest reads, no hand-built edges: the framework
			// repo publishes go:<prefix>/framework and requires crypto, so the
			// app that requires framework is two hops from the vulnerability.
			_, err := graph.UpsertRepositorySnapshot(ctx,
				publishing("framework-repo", "framework", lib("crypto", "v0.1.0", true)))
			Expect(err).ToNot(HaveOccurred())
			_, err = graph.UpsertRepositorySnapshot(ctx,
				snapshot("app", lib("framework", "v1.0.0", true)))
			Expect(err).ToNot(HaveOccurred())

			Expect(graph.LinkVulnerability(ctx, cveID, []valueobject.PackageRef{libRef("crypto")})).To(Succeed())

			radius, err := graph.FindBlastRadius(ctx, cveID, 3, 100)
			Expect(err).ToNot(HaveOccurred())
			Expect(radius.TotalRepositories()).To(Equal(2))

			byName := map[string]model.ImpactedRepository{}
			for _, r := range radius.Repositories {
				byName[r.Repository.FullName()] = r
			}

			// The framework's own repository requires it directly.
			Expect(byName).To(HaveKey(prefix + "/framework-repo"))
			Expect(byName[prefix+"/framework-repo"].Depth).To(Equal(1))
			Expect(byName[prefix+"/framework-repo"].Direct).To(BeTrue())

			// The app never mentions crypto; it is exposed through framework.
			Expect(byName).To(HaveKey(prefix + "/app"))
			Expect(byName[prefix+"/app"].Depth).To(Equal(2))
			Expect(byName[prefix+"/app"].Direct).To(BeFalse())
			Expect(byName[prefix+"/app"].Path).To(Equal([]string{
				prefix + "/app",
				libRef("framework").Key(),
				libRef("crypto").Key(),
			}))
		})

		It("does not make a published module depend on itself", func() {
			// A manifest that lists its own module is malformed but real; the
			// self-edge would make every traversal loop back on itself.
			_, err := graph.UpsertRepositorySnapshot(ctx,
				publishing("framework-repo", "framework",
					lib("framework", "v1.0.0", true),
					lib("crypto", "v0.1.0", true)))
			Expect(err).ToNot(HaveOccurred())

			session := driver.NewSession(ctx, sdk.SessionConfig{DatabaseName: databaseName()})
			defer session.Close(ctx)
			result, err := session.Run(ctx,
				`MATCH (l:Library {key: $key})-[e:DEPENDS_ON]->(l) RETURN count(e) AS loops`,
				map[string]any{"key": libRef("framework").Key()})
			Expect(err).ToNot(HaveOccurred())
			record, err := result.Single(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(record.Values[0]).To(Equal(int64(0)))
		})

		It("does not give a published library its transitive requirements", func() {
			// An indirect entry in go.mod belongs to whichever library pulled
			// it in, not to the module being published.
			_, err := graph.UpsertRepositorySnapshot(ctx,
				publishing("framework-repo", "framework", lib("crypto", "v0.1.0", false)))
			Expect(err).ToNot(HaveOccurred())

			session := driver.NewSession(ctx, sdk.SessionConfig{DatabaseName: databaseName()})
			defer session.Close(ctx)
			result, err := session.Run(ctx,
				`MATCH (:Library {key: $from})-[e:DEPENDS_ON]->(:Library {key: $to}) RETURN count(e) AS edges`,
				map[string]any{"from": libRef("framework").Key(), "to": libRef("crypto").Key()})
			Expect(err).ToNot(HaveOccurred())
			record, err := result.Single(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(record.Values[0]).To(Equal(int64(0)))
		})

		It("records what a dependency-free repository publishes", func() {
			_, err := graph.UpsertRepositorySnapshot(ctx, publishing("framework-repo", "framework"))
			Expect(err).ToNot(HaveOccurred())

			session := driver.NewSession(ctx, sdk.SessionConfig{DatabaseName: databaseName()})
			defer session.Close(ctx)
			result, err := session.Run(ctx,
				`MATCH (:Repository {full_name: $full})-[p:PUBLISHES]->(:Library {key: $key}) RETURN count(p) AS n`,
				map[string]any{"full": prefix + "/framework-repo", "key": libRef("framework").Key()})
			Expect(err).ToNot(HaveOccurred())
			record, err := result.Single(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(record.Values[0]).To(Equal(int64(1)))
		})

		It("does not report repositories beyond the requested depth", func() {
			_, err := graph.UpsertRepositorySnapshot(ctx, snapshot("api", lib("framework", "v1.0.0", true)))
			Expect(err).ToNot(HaveOccurred())
			run(`MATCH (framework:Library {key: $framework})
			     MERGE (transitive:Library {key: $transitive})
			     ON CREATE SET transitive.ecosystem = 'go', transitive.name = $transitiveName
			     MERGE (framework)-[:DEPENDS_ON {direct: true}]->(transitive)`,
				map[string]any{
					"framework":      libRef("framework").Key(),
					"transitive":     libRef("crypto").Key(),
					"transitiveName": prefix + "/crypto",
				})
			Expect(graph.LinkVulnerability(ctx, cveID, []valueobject.PackageRef{libRef("crypto")})).To(Succeed())

			radius, err := graph.FindBlastRadius(ctx, cveID, 1, 100)
			Expect(err).ToNot(HaveOccurred())
			Expect(radius.Linked()).To(BeTrue())
			Expect(radius.Repositories).To(BeEmpty(), "the only path is 2 hops away")
		})

		It("honours the result limit", func() {
			for _, name := range []string{"api", "worker", "cli"} {
				_, err := graph.UpsertRepositorySnapshot(ctx, snapshot(name, lib("net", "v0.17.0", true)))
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(graph.LinkVulnerability(ctx, cveID, []valueobject.PackageRef{libRef("net")})).To(Succeed())

			radius, err := graph.FindBlastRadius(ctx, cveID, 3, 2)
			Expect(err).ToNot(HaveOccurred())
			Expect(radius.Repositories).To(HaveLen(2))
		})

		It("normalizes a lowercase CVE id on both write and read", func() {
			_, err := graph.UpsertRepositorySnapshot(ctx, snapshot("api", lib("net", "v0.17.0", true)))
			Expect(err).ToNot(HaveOccurred())

			lower := strings.ToLower(cveID)
			Expect(graph.LinkVulnerability(ctx, lower, []valueobject.PackageRef{libRef("net")})).To(Succeed())

			radius, err := graph.FindBlastRadius(ctx, lower, 3, 100)
			Expect(err).ToNot(HaveOccurred())
			Expect(radius.CVEID).To(Equal(cveID))
			Expect(radius.Repositories).To(HaveLen(1))
		})

		It("ignores a link request with no usable packages", func() {
			Expect(graph.LinkVulnerability(ctx, cveID, nil)).To(Succeed())
			Expect(graph.LinkVulnerability(ctx, cveID, []valueobject.PackageRef{{}})).To(Succeed())

			radius, err := graph.FindBlastRadius(ctx, cveID, 3, 100)
			Expect(err).ToNot(HaveOccurred())
			Expect(radius.Linked()).To(BeFalse())
		})
	})

	Describe("removing a repository", func() {
		It("removes it and its edges, keeps shared libraries, and drops an orphaned author", func() {
			_, err := graph.UpsertRepositorySnapshot(ctx, snapshot("api", lib("net", "v0.17.0", true)))
			Expect(err).ToNot(HaveOccurred())
			_, err = graph.UpsertRepositorySnapshot(ctx, snapshot("web", lib("net", "v0.17.0", true)))
			Expect(err).ToNot(HaveOccurred())
			Expect(graph.LinkVulnerability(ctx, cveID, []valueobject.PackageRef{libRef("net")})).To(Succeed())

			// Case-insensitive, like GitHub.
			Expect(graph.RemoveRepository(ctx, strings.ToUpper(prefix)+"/API")).To(Succeed())

			radius, err := graph.FindBlastRadius(ctx, cveID, 3, 100)
			Expect(err).ToNot(HaveOccurred())
			Expect(radius.Linked()).To(BeTrue(), "the library and its advisory link survive")
			Expect(radius.Repositories).To(HaveLen(1))
			Expect(radius.Repositories[0].Repository.Name).To(Equal("web"))

			// The author still maintains web, so stays; once web goes too, so does the author.
			Expect(graph.RemoveRepository(ctx, prefix+"/web")).To(Succeed())
			session := driver.NewSession(ctx, sdk.SessionConfig{DatabaseName: databaseName()})
			defer session.Close(ctx)
			result, err := session.Run(ctx, "MATCH (a:Author {login: $login}) RETURN count(a) AS n", map[string]any{"login": prefix})
			Expect(err).ToNot(HaveOccurred())
			record, err := result.Single(ctx)
			Expect(err).ToNot(HaveOccurred())
			n, _ := record.Get("n")
			Expect(n).To(BeEquivalentTo(0))
		})

		It("treats removing a repository that was never written as done", func() {
			Expect(graph.RemoveRepository(ctx, prefix+"/never-scanned")).To(Succeed())
		})
	})
})

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func databaseName() string { return envOr("CORTEX_TEST_NEO4J_DATABASE", "neo4j") }
