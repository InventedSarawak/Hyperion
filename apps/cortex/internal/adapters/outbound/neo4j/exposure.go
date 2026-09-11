package neo4j

import (
	"context"
	"fmt"
	"strings"

	driver "github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// repositoryExposuresCypher walks from repositories to the findings their
// dependencies reach. %d is the traversal depth. As in blast radius, the
// shortest path to each library wins, and its last hop carries the version
// the nearest manifest declares.
const repositoryExposuresCypher = `
MATCH (repo:Repository)
WHERE size($names) = 0 OR toLower(repo.full_name) IN $names
MATCH path = (repo)-[:DEPENDS_ON*1..%d]->(lib:Library)
MATCH (lib)-[a:AFFECTED_BY]->(v:Vulnerability)
WITH repo, lib, a, v, path, length(path) AS depth
ORDER BY depth ASC
WITH repo, lib, a, v, head(collect({path: path, depth: depth})) AS best
RETURN repo.full_name     AS repo,
       v.cve_id           AS id,
       lib.ecosystem      AS ecosystem,
       lib.name           AS library,
       last(relationships(best.path)).version AS declared,
       a.affected_version AS affected,
       best.depth         AS depth,
       (best.depth = 1 AND coalesce(relationships(best.path)[0].direct, false)) AS direct,
       [n IN nodes(best.path) | coalesce(n.full_name, n.key)] AS path
ORDER BY repo, depth, library, id`

// FindRepositoryExposures answers "which findings do these repositories reach?".
func (g *Graph) FindRepositoryExposures(ctx context.Context, fullNames []string, maxDepth int) ([]model.Exposure, error) {
	if maxDepth <= 0 {
		maxDepth = 1
	}
	names := make([]any, 0, len(fullNames))
	for _, n := range fullNames {
		names = append(names, strings.ToLower(strings.TrimSpace(n)))
	}

	session := g.session(ctx, driver.AccessModeRead)
	defer session.Close(ctx)

	out, err := session.ExecuteRead(ctx, func(tx driver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, fmt.Sprintf(repositoryExposuresCypher, maxDepth), map[string]any{"names": names})
		if err != nil {
			return nil, err
		}
		rows, err := result.Collect(ctx)
		if err != nil {
			return nil, err
		}
		exposures := make([]model.Exposure, 0, len(rows))
		for _, row := range rows {
			exposures = append(exposures, model.Exposure{
				Repository: asString(row, "repo"),
				Finding:    model.Vulnerability{CVEID: asString(row, "id")},
				Package: valueobject.PackageRef{
					Ecosystem: valueobject.ParseEcosystem(asString(row, "ecosystem")),
					Name:      asString(row, "library"),
					Version:   asString(row, "declared"),
				},
				AffectedVersions: asString(row, "affected"),
				Depth:            int(asInt(row, "depth")),
				Direct:           asBool(row, "direct"),
				Path:             asStrings(row, "path"),
			})
		}
		return exposures, nil
	})
	if err != nil {
		return nil, fmt.Errorf("neo4j: repository exposures: %w", err)
	}
	return out.([]model.Exposure), nil
}

// HasRepository reports whether a repository is in the graph.
func (g *Graph) HasRepository(ctx context.Context, fullName string) (bool, error) {
	session := g.session(ctx, driver.AccessModeRead)
	defer session.Close(ctx)

	out, err := session.ExecuteRead(ctx, func(tx driver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx,
			`MATCH (r:Repository) WHERE toLower(r.full_name) = $name RETURN count(r) > 0 AS found`,
			map[string]any{"name": strings.ToLower(strings.TrimSpace(fullName))})
		if err != nil {
			return nil, err
		}
		row, err := result.Single(ctx)
		if err != nil {
			return nil, err
		}
		return asBool(row, "found"), nil
	})
	if err != nil {
		return false, fmt.Errorf("neo4j: has repository %s: %w", fullName, err)
	}
	return out.(bool), nil
}
