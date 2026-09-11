// Package graphql is an INBOUND adapter exposing nexus's read API as GraphQL.
// It builds the schema programmatically and resolves fields by calling the
// application use case; it holds no business logic of its own.
package graphql

import (
	"context"
	"fmt"
	"time"

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

// VulnerabilityResolver returns one finding in full.
type VulnerabilityResolver interface {
	Handle(ctx context.Context, id string) (model.Vulnerability, error)
}

// WatchlistResolver reads and edits the repositories cortex tracks.
type WatchlistResolver interface {
	Tracked(ctx context.Context) ([]model.TrackedRepository, error)
	Discover(ctx context.Context, owner string, limit int) ([]model.DiscoveredRepository, error)
	Track(ctx context.Context, fullNames []string) ([]model.TrackedRepository, error)
	Untrack(ctx context.Context, fullName string) (bool, error)
}

// Option adds optional resolvers to the schema.
type Option func(*resolvers)

type resolvers struct {
	vulnerability VulnerabilityResolver
	watchlist     WatchlistResolver
}

// WithVulnerability serves the `vulnerability` query.
func WithVulnerability(r VulnerabilityResolver) Option {
	return func(rs *resolvers) { rs.vulnerability = r }
}

// WithWatchlist serves the watchlist queries and mutations.
func WithWatchlist(r WatchlistResolver) Option {
	return func(rs *resolvers) { rs.watchlist = r }
}

// errUnavailable is returned by a field whose resolver was not configured.
// The field stays in the schema either way, so clients see one stable shape.
var errUnavailable = fmt.Errorf("not available on this gateway")

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

// affectedPackageType mirrors model.AffectedPackage.
var affectedPackageType = graphql.NewObject(graphql.ObjectConfig{
	Name: "AffectedPackage",
	Fields: graphql.Fields{
		"package": &graphql.Field{
			Type:        graphql.NewNonNull(graphql.String),
			Description: "ecosystem:name, e.g. \"npm:next\"",
		},
		"versionRange": &graphql.Field{
			Type:        graphql.String,
			Description: "affected versions as the feed wrote them, e.g. \">= 13.0.0, < 14.2.25\"",
		},
	},
})

// vulnerabilityType mirrors model.Vulnerability.
var vulnerabilityType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Vulnerability",
	Fields: graphql.Fields{
		"cveId": &graphql.Field{
			Type:        graphql.NewNonNull(graphql.String),
			Description: "the CVE id, or the GHSA id for an advisory with no CVE",
		},
		"title":       &graphql.Field{Type: graphql.String},
		"description": &graphql.Field{Type: graphql.String},
		"scores":      &graphql.Field{Type: graphql.NewList(cvssType)},
		"references":  &graphql.Field{Type: graphql.NewList(graphql.String)},
		"publishedAt": &graphql.Field{Type: graphql.String},
		"modifiedAt":  &graphql.Field{Type: graphql.String},
		"sources": &graphql.Field{
			Type:        graphql.NewList(graphql.String),
			Description: "feeds that reported it, e.g. \"nvd\", \"github_advisory\"",
		},
		"affectedPackages": &graphql.Field{Type: graphql.NewList(affectedPackageType)},
	},
})

// trackedRepositoryType mirrors model.TrackedRepository.
var trackedRepositoryType = graphql.NewObject(graphql.ObjectConfig{
	Name: "TrackedRepository",
	Fields: graphql.Fields{
		"fullName": &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
		"url":      &graphql.Field{Type: graphql.String},
		"status": &graphql.Field{
			Type:        graphql.String,
			Description: "pending, scanned or failed",
		},
		"addedAt":         &graphql.Field{Type: graphql.String},
		"lastScanAt":      &graphql.Field{Type: graphql.String},
		"lastError":       &graphql.Field{Type: graphql.String},
		"dependencyCount": &graphql.Field{Type: graphql.Int},
	},
})

// discoveredRepositoryType mirrors model.DiscoveredRepository.
var discoveredRepositoryType = graphql.NewObject(graphql.ObjectConfig{
	Name: "DiscoveredRepository",
	Fields: graphql.Fields{
		"fullName":    &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
		"description": &graphql.Field{Type: graphql.String},
		"language":    &graphql.Field{Type: graphql.String},
		"stars":       &graphql.Field{Type: graphql.Int},
		"pushedAt":    &graphql.Field{Type: graphql.String},
		"fork":        &graphql.Field{Type: graphql.Boolean},
		"archived":    &graphql.Field{Type: graphql.Boolean},
		"tracked": &graphql.Field{
			Type:        graphql.Boolean,
			Description: "already on the watchlist",
		},
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
func NewSchema(searcher Searcher, blast BlastRadiusResolver, opts ...Option) (graphql.Schema, error) {
	var rs resolvers
	for _, opt := range opts {
		opt(&rs)
	}

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
			"vulnerability": &graphql.Field{
				Type: vulnerabilityType,
				Description: "One finding in full, from the store of record — including each " +
					"affected package's version range, which search results omit.",
				Args: graphql.FieldConfigArgument{
					"cveId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if rs.vulnerability == nil {
						return nil, errUnavailable
					}
					id, _ := p.Args["cveId"].(string)
					v, err := rs.vulnerability.Handle(p.Context, id)
					if err != nil {
						return nil, err
					}
					return vulnerabilityMap(v), nil
				},
			},
			"trackedRepositories": &graphql.Field{
				Type:        graphql.NewList(trackedRepositoryType),
				Description: "Every repository on the watchlist, with how its last scan went.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if rs.watchlist == nil {
						return nil, errUnavailable
					}
					repos, err := rs.watchlist.Tracked(p.Context)
					if err != nil {
						return nil, err
					}
					return trackedMaps(repos), nil
				},
			},
			"discoverRepositories": &graphql.Field{
				Type:        graphql.NewList(discoveredRepositoryType),
				Description: "A GitHub user's or organization's repositories, most recently pushed first.",
				Args: graphql.FieldConfigArgument{
					"owner": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"limit": &graphql.ArgumentConfig{Type: graphql.Int},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if rs.watchlist == nil {
						return nil, errUnavailable
					}
					owner, _ := p.Args["owner"].(string)
					limit, _ := p.Args["limit"].(int)
					found, err := rs.watchlist.Discover(p.Context, owner, limit)
					if err != nil {
						return nil, err
					}
					out := make([]map[string]any, 0, len(found))
					for _, r := range found {
						out = append(out, map[string]any{
							"fullName":    r.FullName,
							"description": r.Description,
							"language":    r.Language,
							"stars":       r.Stars,
							"pushedAt":    formatTime(r.PushedAt),
							"fork":        r.Fork,
							"archived":    r.Archived,
							"tracked":     r.Tracked,
						})
					}
					return out, nil
				},
			},
		},
	})

	mutation := graphql.NewObject(graphql.ObjectConfig{
		Name: "Mutation",
		Fields: graphql.Fields{
			"trackRepositories": &graphql.Field{
				Type: graphql.NewList(trackedRepositoryType),
				Description: "Add repositories to the watchlist; the scanner reads them on its next pass. " +
					"Tracking one already tracked re-queues it for a scan.",
				Args: graphql.FieldConfigArgument{
					"fullNames": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(graphql.String))),
					},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if rs.watchlist == nil {
						return nil, errUnavailable
					}
					raw, _ := p.Args["fullNames"].([]any)
					names := make([]string, 0, len(raw))
					for _, n := range raw {
						if s, ok := n.(string); ok {
							names = append(names, s)
						}
					}
					repos, err := rs.watchlist.Track(p.Context, names)
					if err != nil {
						return nil, err
					}
					return trackedMaps(repos), nil
				},
			},
			"untrackRepository": &graphql.Field{
				Type:        graphql.Boolean,
				Description: "Stop tracking a repository and remove it from the dependency graph.",
				Args: graphql.FieldConfigArgument{
					"fullName": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if rs.watchlist == nil {
						return nil, errUnavailable
					}
					fullName, _ := p.Args["fullName"].(string)
					return rs.watchlist.Untrack(p.Context, fullName)
				},
			},
		},
	})

	schema, err := graphql.NewSchema(graphql.SchemaConfig{Query: query, Mutation: mutation})
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
	packages := make([]map[string]any, 0, len(v.AffectedPackages))
	for _, p := range v.AffectedPackages {
		packages = append(packages, map[string]any{"package": p.Package, "versionRange": p.VersionRange})
	}
	out := map[string]any{
		"cveId":            v.CVEID,
		"title":            v.Title,
		"description":      v.Description,
		"scores":           scores,
		"references":       v.References,
		"sources":          v.Sources,
		"affectedPackages": packages,
	}
	if !v.PublishedAt.IsZero() {
		out["publishedAt"] = formatTime(v.PublishedAt)
	}
	if !v.ModifiedAt.IsZero() {
		out["modifiedAt"] = formatTime(v.ModifiedAt)
	}
	return out
}

// formatTime renders a timestamp as RFC 3339 UTC, and a zero one as null.
func formatTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func trackedMaps(repos []model.TrackedRepository) []map[string]any {
	out := make([]map[string]any, 0, len(repos))
	for _, r := range repos {
		out = append(out, map[string]any{
			"fullName":        r.FullName,
			"url":             r.URL,
			"status":          r.Status,
			"addedAt":         formatTime(r.AddedAt),
			"lastScanAt":      formatTime(r.LastScanAt),
			"lastError":       r.LastError,
			"dependencyCount": r.DependencyCount,
		})
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
