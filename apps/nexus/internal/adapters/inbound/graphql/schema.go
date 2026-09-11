// Package graphql is an INBOUND adapter exposing nexus's read API as GraphQL.
// It builds the schema programmatically and resolves fields by calling the
// application use case; it holds no business logic of its own.
package graphql

import (
	"context"
	"fmt"

	"github.com/graphql-go/graphql"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
)

// Searcher is the use case this adapter drives (consumer-side interface).
type Searcher interface {
	Handle(ctx context.Context, term string, sort model.SearchSort, pageSize int, pageToken string) (model.SearchResult, error)
}

// BlastRadiusResolver answers which repositories a vulnerability reaches.
type BlastRadiusResolver interface {
	Handle(ctx context.Context, cveID string, maxDepth, limit int) (model.BlastRadius, error)
}

// cvssType mirrors model.CVSS.
var cvssType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Cvss",
	Fields: graphql.Fields{
		"version":   &graphql.Field{Type: graphql.String},
		"baseScore": &graphql.Field{Type: graphql.Float},
		"vector":    &graphql.Field{Type: graphql.String},
		"severity":  &graphql.Field{Type: graphql.String},
	},
})

// vulnerabilityType mirrors model.Vulnerability.
var vulnerabilityType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Vulnerability",
	Fields: graphql.Fields{
		"cveId":       &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
		"title":       &graphql.Field{Type: graphql.String},
		"description": &graphql.Field{Type: graphql.String},
		"scores":      &graphql.Field{Type: graphql.NewList(cvssType)},
		"references":  &graphql.Field{Type: graphql.NewList(graphql.String)},
		"publishedAt": &graphql.Field{Type: graphql.String},
		"modifiedAt":  &graphql.Field{Type: graphql.String},
	},
})

var searchHitType = graphql.NewObject(graphql.ObjectConfig{
	Name: "SearchHit",
	Fields: graphql.Fields{
		"vulnerability": &graphql.Field{Type: vulnerabilityType},
		"score":         &graphql.Field{Type: graphql.Float},
	},
})

// searchSortEnum orders search results.
var searchSortEnum = graphql.NewEnum(graphql.EnumConfig{
	Name: "SearchSort",
	Values: graphql.EnumValueConfigMap{
		"RELEVANCE": &graphql.EnumValueConfig{
			Value:       string(model.SortRelevance),
			Description: "Best match first; ties broken by newest, then CVE id.",
		},
		"NEWEST": &graphql.EnumValueConfig{
			Value:       string(model.SortNewest),
			Description: "Most recently published first. The only sort that accepts an empty term.",
		},
	},
})

var searchResultType = graphql.NewObject(graphql.ObjectConfig{
	Name: "SearchResult",
	Fields: graphql.Fields{
		"hits":          &graphql.Field{Type: graphql.NewList(searchHitType)},
		"nextPageToken": &graphql.Field{Type: graphql.String},
		"totalResults": &graphql.Field{
			Type:        graphql.Float,
			Description: "How many records match. A floor when totalIsLowerBound is true.",
		},
		"totalIsLowerBound": &graphql.Field{Type: graphql.Boolean},
	},
})

// impactedRepositoryType mirrors model.ImpactedRepository.
var impactedRepositoryType = graphql.NewObject(graphql.ObjectConfig{
	Name: "ImpactedRepository",
	Fields: graphql.Fields{
		"fullName": &graphql.Field{
			Type:        graphql.NewNonNull(graphql.String),
			Description: "owner/name, e.g. \"vercel/commerce\"",
		},
		"owner":      &graphql.Field{Type: graphql.String},
		"name":       &graphql.Field{Type: graphql.String},
		"url":        &graphql.Field{Type: graphql.String},
		"authorName": &graphql.Field{Type: graphql.String},
		"viaPackage": &graphql.Field{
			Type:        graphql.String,
			Description: "the vulnerable library this repository reaches",
		},
		"depth": &graphql.Field{
			Type:        graphql.Int,
			Description: "dependency hops from the repository to the vulnerable library",
		},
		"direct": &graphql.Field{
			Type:        graphql.Boolean,
			Description: "true when the repository's own manifest names the library",
		},
		"path": &graphql.Field{Type: graphql.NewList(graphql.String)},
		"chain": &graphql.Field{
			Type:        graphql.String,
			Description: "the dependency path rendered for display",
		},
	},
})

// blastRadiusType mirrors model.BlastRadius.
var blastRadiusType = graphql.NewObject(graphql.ObjectConfig{
	Name: "BlastRadius",
	Fields: graphql.Fields{
		"cveId": &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
		"vulnerablePackages": &graphql.Field{
			Type:        graphql.NewList(graphql.String),
			Description: "libraries the advisory names as vulnerable",
		},
		"repositories":      &graphql.Field{Type: graphql.NewList(impactedRepositoryType)},
		"totalRepositories": &graphql.Field{Type: graphql.Int},
		"linked": &graphql.Field{
			Type: graphql.Boolean,
			Description: "false when the CVE has no package linkage at all — an empty " +
				"repository list then means 'unknown', not 'nothing is affected'",
		},
	},
})

// NewSchema builds the GraphQL schema, wiring each query to its use case.
func NewSchema(searcher Searcher, blast BlastRadiusResolver) (graphql.Schema, error) {
	query := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"search": &graphql.Field{
				Type:        searchResultType,
				Description: "Full-text search across ingested vulnerabilities.",
				Args: graphql.FieldConfigArgument{
					// Optional: an empty term with sort NEWEST is the live feed.
					// Relaxing non-null to nullable does not break existing
					// clients, which always sent a term.
					"term":      &graphql.ArgumentConfig{Type: graphql.String},
					"sort":      &graphql.ArgumentConfig{Type: searchSortEnum, DefaultValue: string(model.SortRelevance)},
					"pageSize":  &graphql.ArgumentConfig{Type: graphql.Int},
					"pageToken": &graphql.ArgumentConfig{Type: graphql.String},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					term, _ := p.Args["term"].(string)
					sort, _ := p.Args["sort"].(string)
					pageSize, _ := p.Args["pageSize"].(int)
					pageToken, _ := p.Args["pageToken"].(string)

					result, err := searcher.Handle(p.Context, term, model.SearchSort(sort), pageSize, pageToken)
					if err != nil {
						return nil, err
					}
					return toGraphQL(result), nil
				},
			},
			"blastRadius": &graphql.Field{
				Type:        blastRadiusType,
				Description: "Which repositories a vulnerability reaches through the dependency graph.",
				Args: graphql.FieldConfigArgument{
					"cveId":    &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"maxDepth": &graphql.ArgumentConfig{Type: graphql.Int},
					"limit":    &graphql.ArgumentConfig{Type: graphql.Int},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					cveID, _ := p.Args["cveId"].(string)
					maxDepth, _ := p.Args["maxDepth"].(int)
					limit, _ := p.Args["limit"].(int)

					radius, err := blast.Handle(p.Context, cveID, maxDepth, limit)
					if err != nil {
						return nil, err
					}
					return blastRadiusMap(radius), nil
				},
			},
		},
	})

	schema, err := graphql.NewSchema(graphql.SchemaConfig{Query: query})
	if err != nil {
		return graphql.Schema{}, fmt.Errorf("graphql: build schema: %w", err)
	}
	return schema, nil
}

// --- mapping: view model -> GraphQL response shape ---

func toGraphQL(r model.SearchResult) map[string]any {
	hits := make([]map[string]any, 0, len(r.Hits))
	for _, h := range r.Hits {
		hits = append(hits, map[string]any{
			"vulnerability": vulnerabilityMap(h.Vulnerability),
			"score":         h.Score,
		})
	}
	return map[string]any{
		"hits":              hits,
		"nextPageToken":     r.NextPageToken,
		"totalResults":      float64(r.TotalResults), // GraphQL Int is 32-bit
		"totalIsLowerBound": r.TotalIsLowerBound,
	}
}

func vulnerabilityMap(v model.Vulnerability) map[string]any {
	scores := make([]map[string]any, 0, len(v.Scores))
	for _, s := range v.Scores {
		scores = append(scores, map[string]any{
			"version":   s.Version,
			"baseScore": s.BaseScore,
			"vector":    s.Vector,
			"severity":  s.Severity,
		})
	}
	out := map[string]any{
		"cveId":       v.CVEID,
		"title":       v.Title,
		"description": v.Description,
		"scores":      scores,
		"references":  v.References,
	}
	if !v.PublishedAt.IsZero() {
		out["publishedAt"] = v.PublishedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	if !v.ModifiedAt.IsZero() {
		out["modifiedAt"] = v.ModifiedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	return out
}

func blastRadiusMap(r model.BlastRadius) map[string]any {
	repos := make([]map[string]any, 0, len(r.Repositories))
	for _, repo := range r.Repositories {
		repos = append(repos, map[string]any{
			"fullName":   repo.FullName(),
			"owner":      repo.Owner,
			"name":       repo.Name,
			"url":        repo.URL,
			"authorName": repo.AuthorName,
			"viaPackage": repo.ViaPackage,
			"depth":      repo.Depth,
			"direct":     repo.Direct,
			"path":       repo.Path,
			"chain":      repo.Chain(),
		})
	}
	return map[string]any{
		"cveId":              r.CVEID,
		"vulnerablePackages": r.VulnerablePackages,
		"repositories":       repos,
		"totalRepositories":  len(r.Repositories),
		"linked":             r.Linked(),
	}
}
