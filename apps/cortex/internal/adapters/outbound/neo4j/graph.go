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

// migration is one versioned change to the graph's schema.
//
// Versioned for the same reason the Postgres migrations are: a statement that
// creates something can be written idempotently and re-run forever, but one
// that *changes* something cannot, and there was previously no way to tell
// which had already happened. Appending here is how the graph schema evolves.
type migration struct {
	version string
	stmt    string
}

// migrations run in order, once each. The constraints double as indexes: Neo4j
// backs every uniqueness constraint with one, which is what keeps MERGE from
// degrading into a full label scan as the graph grows.
var migrations = []migration{
	{"0001_repository_full_name", `CREATE CONSTRAINT repository_full_name IF NOT EXISTS
	 FOR (r:Repository) REQUIRE r.full_name IS UNIQUE`},
	{"0002_library_key", `CREATE CONSTRAINT library_key IF NOT EXISTS
	 FOR (l:Library) REQUIRE l.key IS UNIQUE`},
	{"0003_author_login", `CREATE CONSTRAINT author_login IF NOT EXISTS
	 FOR (a:Author) REQUIRE a.login IS UNIQUE`},
	{"0004_vulnerability_cve_id", `CREATE CONSTRAINT vulnerability_cve_id IF NOT EXISTS
	 FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE`},
}

// schemaVersionConstraint keeps the migration register honest: two cortex
// instances starting at once must not both record the same version.
const schemaVersionConstraint = `CREATE CONSTRAINT schema_migration_version IF NOT EXISTS
	 FOR (m:SchemaMigration) REQUIRE m.version IS UNIQUE`

// EnsureSchema applies any graph migration that has not run yet.
//
// The constraints the MERGEs rely on are created here; without them a
// concurrent MERGE can create a duplicate node under the same key.
func (g *Graph) EnsureSchema(ctx context.Context) error {
	session := g.session(ctx, driver.AccessModeWrite)
	defer session.Close(ctx)

	// The register itself first — it is what decides whether anything else
	// runs, so it cannot be one of the things it decides about.
	if _, err := session.Run(ctx, schemaVersionConstraint, nil); err != nil {
		return fmt.Errorf("neo4j: ensure schema register: %w", err)
	}

	applied, err := g.appliedVersions(ctx, session)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if applied[m.version] {
			continue
		}
		if _, err := session.Run(ctx, m.stmt, nil); err != nil {
			return fmt.Errorf("neo4j: apply %s: %w", m.version, err)
		}
		if _, err := session.Run(ctx,
			`MERGE (m:SchemaMigration {version: $version})
			 ON CREATE SET m.applied_at = datetime()`,
			map[string]any{"version": m.version}); err != nil {
			return fmt.Errorf("neo4j: record %s: %w", m.version, err)
		}
	}
	return nil
}

// appliedVersions reads which graph migrations have already run.
func (g *Graph) appliedVersions(ctx context.Context, session driver.SessionWithContext) (map[string]bool, error) {
	result, err := session.Run(ctx, `MATCH (m:SchemaMigration) RETURN m.version AS version`, nil)
	if err != nil {
		return nil, fmt.Errorf("neo4j: read schema migrations: %w", err)
	}

	applied := map[string]bool{}
	for result.Next(ctx) {
		if v, ok := result.Record().Get("version"); ok {
			if name, ok := v.(string); ok {
				applied[name] = true
			}
		}
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("neo4j: read schema migrations: %w", err)
	}
	return applied, nil
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
		// node above is recorded, and there is simply nothing to UNWIND. It
		// may still publish a library, so that is recorded either way.
		if len(deps) == 0 {
			if published, ok := snapshot.PublishedLibrary(); ok {
				if _, err := tx.Run(ctx, mergePublishedLibraryCypher, map[string]any{
					"full_name":   repo.FullName(),
					"key":         published.Key(),
					"ecosystem":   published.Ecosystem.String(),
					"name":        published.Name,
					"deps":        []any{},
					"observed_at": observedAt,
				}); err != nil {
					return 0, err
				}
			}
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
		written := int(asInt(record, "written"))

		if published, ok := snapshot.PublishedLibrary(); ok {
			direct := snapshot.DirectDependencies()
			directRows := make([]any, 0, len(direct))
			for _, d := range direct {
				directRows = append(directRows, map[string]any{
					"key":           d.Package.Key(),
					"version":       d.Package.Version,
					"manifest_path": d.ManifestPath,
				})
			}
			if _, err := tx.Run(ctx, mergePublishedLibraryCypher, map[string]any{
				"full_name":   repo.FullName(),
				"key":         published.Key(),
				"ecosystem":   published.Ecosystem.String(),
				"name":        published.Name,
				"deps":        directRows,
				"observed_at": observedAt,
			}); err != nil {
				return 0, err
			}
		}
		return written, nil
	})
	if err != nil {
		return 0, fmt.Errorf("neo4j: upsert snapshot %s: %w", repo.FullName(), err)
	}
	return written.(int), nil
}

// mergePublishedLibraryCypher records the library this repository ships and
// gives it the repository's own direct requirements. These library-to-library
// edges are what make the DEPENDS_ON traversal recursive: without them the
// graph is one hop deep no matter how many manifests we read.
//
// A module is never made to depend on itself, and the dependency libraries are
// MATCHed rather than MERGEd because the statement before this one has already
// created them.
const mergePublishedLibraryCypher = `
MATCH (r:Repository {full_name: $full_name})
MERGE (pub:Library {key: $key})
ON CREATE SET pub.ecosystem = $ecosystem, pub.name = $name
SET pub.published_by = $full_name
MERGE (r)-[:PUBLISHES]->(pub)
WITH pub
UNWIND $deps AS dep
WITH pub, dep WHERE dep.key <> $key
MATCH (l:Library {key: dep.key})
MERGE (pub)-[e:DEPENDS_ON]->(l)
SET e.version = dep.version,
    e.direct = true,
    e.manifest_path = dep.manifest_path,
    e.observed_at = $observed_at`

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

const removeVulnerabilitiesCypher = `
MATCH (v:Vulnerability) WHERE v.cve_id IN $ids
DETACH DELETE v`

// RemoveVulnerabilities deletes findings' nodes and every AFFECTED_BY edge to
// them. Libraries stay: repositories still depend on them.
func (g *Graph) RemoveVulnerabilities(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	params := make([]any, 0, len(ids))
	for _, id := range ids {
		params = append(params, id)
	}

	session := g.session(ctx, driver.AccessModeWrite)
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx driver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, removeVulnerabilitiesCypher, map[string]any{"ids": params})
		if err != nil {
			return nil, err
		}
		_, err = result.Consume(ctx)
		return nil, err
	})
	if err != nil {
		return fmt.Errorf("neo4j: remove vulnerabilities %v: %w", ids, err)
	}
	return nil
}

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

// removeRepositoryCypher deletes a repository with every edge it owns — its
// DEPENDS_ON, PUBLISHES and MAINTAINS relationships — and then its author, if
// that author maintains nothing else. Libraries are left alone: advisories and
// other repositories point at them. So are library-to-library edges learned
// from this repository's manifest; "ajv depends on fast-uri" stays true
// whether or not anyone tracks ajv, and dropping it would shorten every other
// repository's transitive blast radius.
//
// Matching ignores case because GitHub does: "Vercel/Next.js" and
// "vercel/next.js" are one repository.
const removeRepositoryCypher = `
MATCH (r:Repository)
WHERE toLower(r.full_name) = toLower($full_name)
OPTIONAL MATCH (a:Author)-[:MAINTAINS]->(r)
DETACH DELETE r
WITH DISTINCT a
WHERE a IS NOT NULL AND NOT (a)-[:MAINTAINS]->()
DELETE a`

// RemoveRepository deletes a repository from the graph. Removing one that is
// not there is not an error: a repository can be untracked before its first
// scan ever wrote it.
func (g *Graph) RemoveRepository(ctx context.Context, fullName string) error {
	session := g.session(ctx, driver.AccessModeWrite)
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx driver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, removeRepositoryCypher, map[string]any{"full_name": fullName})
		if err != nil {
			return nil, err
		}
		_, err = result.Consume(ctx)
		return nil, err
	})
	if err != nil {
		return fmt.Errorf("neo4j: remove repository %s: %w", fullName, err)
	}
	return nil
}
