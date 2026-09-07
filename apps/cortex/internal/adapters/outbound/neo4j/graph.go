// Package neo4j is an OUTBOUND adapter implementing ports.DependencyGraph on
// Neo4j. Every Cypher statement lives here; the rest of cortex sees only
// domain types.
//
// The graph it maintains:
//
//	(:Author {login})-[:MAINTAINS]->(:Repository {full_name})
//	(:Repository)-[:DEPENDS_ON {version, direct, manifest_path}]->(:Library {key})
//	(:Library)-[:AFFECTED_BY {affected_version}]->(:Vulnerability {cve_id})
//
// Libraries are keyed on ecosystem+name without a version, so every dependant
// of a package converges on one node and a single traversal finds them all.
// The version a repository pins lives on the DEPENDS_ON edge.
package neo4j

import (
	"context"
	"fmt"
	"time"

	driver "github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// Config holds everything needed to reach the graph.
type Config struct {
	URI      string
	Username string
	Password string
	Database string
}

// Graph is the Neo4j-backed dependency graph.
type Graph struct {
	driver   driver.DriverWithContext
	database string
}

// Connect opens a driver and verifies it can reach the server.
func Connect(ctx context.Context, cfg Config) (*Graph, error) {
	d, err := driver.NewDriverWithContext(cfg.URI, driver.BasicAuth(cfg.Username, cfg.Password, ""))
	if err != nil {
		return nil, fmt.Errorf("neo4j: driver for %s: %w", cfg.URI, err)
	}
	if err := d.VerifyConnectivity(ctx); err != nil {
		_ = d.Close(ctx)
		return nil, fmt.Errorf("neo4j: connect %s: %w", cfg.URI, err)
	}
	return &Graph{driver: d, database: cfg.Database}, nil
}

// Close releases the driver's connection pool.
func (g *Graph) Close(ctx context.Context) error { return g.driver.Close(ctx) }

// Ready reports whether the server is reachable.
func (g *Graph) Ready(ctx context.Context) error {
	if err := g.driver.VerifyConnectivity(ctx); err != nil {
		return fmt.Errorf("neo4j: not ready: %w", err)
	}
	return nil
}

// constraints are idempotent and double as indexes: Neo4j backs every
// uniqueness constraint with one, which is what keeps MERGE from degrading
// into a full label scan as the graph grows.
var constraints = []string{
	`CREATE CONSTRAINT repository_full_name IF NOT EXISTS
	 FOR (r:Repository) REQUIRE r.full_name IS UNIQUE`,
	`CREATE CONSTRAINT library_key IF NOT EXISTS
	 FOR (l:Library) REQUIRE l.key IS UNIQUE`,
	`CREATE CONSTRAINT author_login IF NOT EXISTS
	 FOR (a:Author) REQUIRE a.login IS UNIQUE`,
	`CREATE CONSTRAINT vulnerability_cve_id IF NOT EXISTS
	 FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE`,
}

// EnsureSchema creates the uniqueness constraints the MERGEs rely on. Without
// them a concurrent MERGE can create a duplicate node under the same key.
func (g *Graph) EnsureSchema(ctx context.Context) error {
	session := g.session(ctx, driver.AccessModeWrite)
	defer session.Close(ctx)

	for _, stmt := range constraints {
		if _, err := session.Run(ctx, stmt, nil); err != nil {
			return fmt.Errorf("neo4j: ensure schema: %w", err)
		}
	}
	return nil
}

func (g *Graph) session(ctx context.Context, mode driver.AccessMode) driver.SessionWithContext {
	return g.driver.NewSession(ctx, driver.SessionConfig{
		DatabaseName: g.database,
		AccessMode:   mode,
	})
}

const mergeRepositoryCypher = `
MERGE (r:Repository {full_name: $full_name})
SET r.owner = $owner,
    r.name = $name,
    r.url = $url,
    r.default_branch = $default_branch,
    r.last_seen_at = $observed_at`

const mergeAuthorCypher = `
MERGE (a:Author {login: $login})
SET a.name = $name, a.url = $url
WITH a
MATCH (r:Repository {full_name: $full_name})
MERGE (a)-[:MAINTAINS]->(r)`

const mergeDependenciesCypher = `
MATCH (r:Repository {full_name: $full_name})
UNWIND $deps AS dep
MERGE (l:Library {key: dep.key})
ON CREATE SET l.ecosystem = dep.ecosystem, l.name = dep.name
MERGE (r)-[e:DEPENDS_ON]->(l)
SET e.version = dep.version,
    e.direct = dep.direct,
    e.manifest_path = dep.manifest_path,
    e.observed_at = $observed_at
RETURN count(e) AS written`

// UpsertRepositorySnapshot writes one manifest read as graph edges, in a
// single transaction so the repository, its owner and its dependencies never
// land half-applied.
func (g *Graph) UpsertRepositorySnapshot(ctx context.Context, snapshot model.RepositorySnapshot) (int, error) {
	if err := snapshot.Validate(); err != nil {
		return 0, err
	}

	observedAt := snapshot.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	repo := snapshot.Repository
	deps := snapshot.ValidDependencies()

	session := g.session(ctx, driver.AccessModeWrite)
	defer session.Close(ctx)

	written, err := session.ExecuteWrite(ctx, func(tx driver.ManagedTransaction) (any, error) {
		if _, err := tx.Run(ctx, mergeRepositoryCypher, map[string]any{
			"full_name":      repo.FullName(),
			"owner":          repo.Owner,
			"name":           repo.Name,
			"url":            repo.URL,
			"default_branch": repo.DefaultBranch,
			"observed_at":    observedAt,
		}); err != nil {
			return 0, err
		}

		if !snapshot.Author.IsZero() {
			if _, err := tx.Run(ctx, mergeAuthorCypher, map[string]any{
				"login":     snapshot.Author.Login,
				"name":      snapshot.Author.Name,
				"url":       snapshot.Author.URL,
				"full_name": repo.FullName(),
			}); err != nil {
				return 0, err
			}
		}

		// A repository with no third-party requirements is a real fact: the
		// node above is recorded, and there is simply nothing to UNWIND.
		if len(deps) == 0 {
			return 0, nil
		}

		rows := make([]any, 0, len(deps))
		for _, d := range deps {
			rows = append(rows, map[string]any{
				"key":           d.Package.Key(),
				"ecosystem":     d.Package.Ecosystem.String(),
				"name":          d.Package.Name,
				"version":       d.Package.Version,
				"direct":        d.Direct,
				"manifest_path": d.ManifestPath,
			})
		}

		result, err := tx.Run(ctx, mergeDependenciesCypher, map[string]any{
			"full_name":   repo.FullName(),
			"deps":        rows,
			"observed_at": observedAt,
		})
		if err != nil {
			return 0, err
		}
		record, err := result.Single(ctx)
		if err != nil {
			return 0, err
		}
		return int(asInt(record, "written")), nil
	})
	if err != nil {
		return 0, fmt.Errorf("neo4j: upsert snapshot %s: %w", repo.FullName(), err)
	}
	return written.(int), nil
}

const linkVulnerabilityCypher = `
MERGE (v:Vulnerability {cve_id: $cve_id})
ON CREATE SET v.first_linked_at = $linked_at
SET v.last_linked_at = $linked_at
WITH v
UNWIND $packages AS pkg
MERGE (l:Library {key: pkg.key})
ON CREATE SET l.ecosystem = pkg.ecosystem, l.name = pkg.name
MERGE (l)-[a:AFFECTED_BY]->(v)
SET a.affected_version = pkg.version`

// LinkVulnerability records that a CVE affects the given libraries. An empty
// package list is a no-op rather than an orphan Vulnerability node: most CVEs
// never name a package, and materializing them all would bloat the graph with
// nodes no traversal can ever reach.
func (g *Graph) LinkVulnerability(ctx context.Context, cveID string, packages []valueobject.PackageRef) error {
	cveID = valueobject.NormalizeCVEID(cveID)
	if cveID == "" {
		return fmt.Errorf("neo4j: link vulnerability: cve id is required")
	}

	rows := make([]any, 0, len(packages))
	for _, p := range packages {
		if p.Validate() != nil {
			continue
		}
		rows = append(rows, map[string]any{
			"key":       p.Key(),
			"ecosystem": p.Ecosystem.String(),
			"name":      p.Name,
			"version":   p.Version,
		})
	}
	if len(rows) == 0 {
		return nil
	}

	session := g.session(ctx, driver.AccessModeWrite)
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx driver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, linkVulnerabilityCypher, map[string]any{
			"cve_id":    cveID,
			"packages":  rows,
			"linked_at": time.Now().UTC(),
		})
		if err != nil {
			return nil, err
		}
		_, err = result.Consume(ctx)
		return nil, err
	})
	if err != nil {
		return fmt.Errorf("neo4j: link vulnerability %s: %w", cveID, err)
	}
	return nil
}
