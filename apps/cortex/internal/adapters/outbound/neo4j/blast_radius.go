package neo4j

import (
	"context"
	"fmt"

	driver "github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// maxTraversalDepth is a hard ceiling applied in the adapter as well as the
// use case. The depth is interpolated into the Cypher (a variable-length
// bound cannot be a parameter), so it must never come from an unchecked
// caller — this bound is what makes that interpolation safe.
const maxTraversalDepth = 10

const vulnerablePackagesCypher = `
MATCH (lib:Library)-[a:AFFECTED_BY]->(:Vulnerability {cve_id: $cve_id})
RETURN lib.ecosystem AS ecosystem,
       lib.name      AS name,
       a.affected_version AS version
ORDER BY ecosystem, name`

// impactedRepositoriesCypher walks DEPENDS_ON backwards from every affected
// library to the repositories that reach it. %d is the traversal depth.
//
// Where a repository reaches the same library by several paths, the shortest
// wins: ordering before collect() and taking the head is the Cypher idiom for
// "best per group".
const impactedRepositoriesCypher = `
MATCH (lib:Library)-[a:AFFECTED_BY]->(:Vulnerability {cve_id: $cve_id})
MATCH path = (repo:Repository)-[:DEPENDS_ON*1..%d]->(lib)
WITH repo, lib, a, path, length(path) AS depth
ORDER BY depth ASC
WITH repo, lib, a, head(collect({path: path, depth: depth})) AS best
OPTIONAL MATCH (author:Author)-[:MAINTAINS]->(repo)
RETURN repo.owner          AS owner,
       repo.name           AS name,
       repo.url            AS url,
       repo.default_branch AS default_branch,
       author.login        AS author_login,
       author.name         AS author_name,
       author.url          AS author_url,
       lib.ecosystem       AS ecosystem,
       lib.name            AS library,
       best.depth          AS depth,
       (best.depth = 1 AND coalesce(relationships(best.path)[0].direct, false)) AS direct,
       [n IN nodes(best.path) | coalesce(n.full_name, n.key)] AS path,
       last(relationships(best.path)).version AS declared,
       a.affected_version  AS affected
ORDER BY depth ASC, owner ASC, name ASC
LIMIT $limit`

// FindBlastRadius answers "who is exposed to this CVE?".
//
// The two result sets are gathered separately and deliberately: the libraries
// an advisory names are worth reporting even when nothing depends on them,
// because that is the difference between "nothing is affected" and "we cannot
// tell yet".
func (g *Graph) FindBlastRadius(ctx context.Context, cveID string, maxDepth, limit int) (model.BlastRadius, error) {
	cveID = valueobject.NormalizeCVEID(cveID)
	if cveID == "" {
		return model.BlastRadius{}, fmt.Errorf("neo4j: blast radius: cve id is required")
	}
	if maxDepth <= 0 {
		maxDepth = 1
	}
	if maxDepth > maxTraversalDepth {
		maxDepth = maxTraversalDepth
	}
	if limit <= 0 {
		limit = 100
	}

	session := g.session(ctx, driver.AccessModeRead)
	defer session.Close(ctx)

	out, err := session.ExecuteRead(ctx, func(tx driver.ManagedTransaction) (any, error) {
		radius := model.BlastRadius{CVEID: cveID}

		packages, err := tx.Run(ctx, vulnerablePackagesCypher, map[string]any{"cve_id": cveID})
		if err != nil {
			return nil, err
		}
		packageRows, err := packages.Collect(ctx)
		if err != nil {
			return nil, err
		}
		for _, row := range packageRows {
			radius.VulnerablePackages = append(radius.VulnerablePackages, valueobject.PackageRef{
				Ecosystem: valueobject.ParseEcosystem(asString(row, "ecosystem")),
				Name:      asString(row, "name"),
				Version:   asString(row, "version"),
			})
		}
		// Nothing links this CVE to a library, so no traversal can start.
		if len(radius.VulnerablePackages) == 0 {
			return radius, nil
		}

		repos, err := tx.Run(ctx,
			fmt.Sprintf(impactedRepositoriesCypher, maxDepth),
			map[string]any{"cve_id": cveID, "limit": int64(limit)})
		if err != nil {
			return nil, err
		}
		repoRows, err := repos.Collect(ctx)
		if err != nil {
			return nil, err
		}
		for _, row := range repoRows {
			radius.Repositories = append(radius.Repositories, model.ImpactedRepository{
				Repository: model.Repository{
					Owner:         asString(row, "owner"),
					Name:          asString(row, "name"),
					URL:           asString(row, "url"),
					DefaultBranch: asString(row, "default_branch"),
				},
				Author: model.Author{
					Login: asString(row, "author_login"),
					Name:  asString(row, "author_name"),
					URL:   asString(row, "author_url"),
				},
				ViaPackage: valueobject.PackageRef{
					Ecosystem: valueobject.ParseEcosystem(asString(row, "ecosystem")),
					Name:      asString(row, "library"),
				},
				Depth:            int(asInt(row, "depth")),
				Direct:           asBool(row, "direct"),
				Path:             asStrings(row, "path"),
				DeclaredVersion:  asString(row, "declared"),
				AffectedVersions: asString(row, "affected"),
			})
		}
		return radius, nil
	})
	if err != nil {
		return model.BlastRadius{}, fmt.Errorf("neo4j: blast radius %s: %w", cveID, err)
	}
	return out.(model.BlastRadius), nil
}
