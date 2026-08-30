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
	Handle(ctx context.Context, term string, pageSize int, pageToken string) (model.SearchResult, error)
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

var searchResultType = graphql.NewObject(graphql.ObjectConfig{
	Name: "SearchResult",
	Fields: graphql.Fields{
		"hits":          &graphql.Field{Type: graphql.NewList(searchHitType)},
		"nextPageToken": &graphql.Field{Type: graphql.String},
	},
})

// NewSchema builds the GraphQL schema, wiring the `search` query to the use case.
func NewSchema(searcher Searcher) (graphql.Schema, error) {
	query := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"search": &graphql.Field{
				Type:        searchResultType,
				Description: "Full-text search across ingested vulnerabilities.",
				Args: graphql.FieldConfigArgument{
					"term":      &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"pageSize":  &graphql.ArgumentConfig{Type: graphql.Int},
					"pageToken": &graphql.ArgumentConfig{Type: graphql.String},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					term, _ := p.Args["term"].(string)
					pageSize, _ := p.Args["pageSize"].(int)
					pageToken, _ := p.Args["pageToken"].(string)

					result, err := searcher.Handle(p.Context, term, pageSize, pageToken)
					if err != nil {
						return nil, err
					}
					return toGraphQL(result), nil
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
	return map[string]any{"hits": hits, "nextPageToken": r.NextPageToken}
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
