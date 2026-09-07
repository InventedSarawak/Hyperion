// Package config loads cortex's settings through Hyperion's centralized,
// namespaced config system. Every key is cortex.<NAME> -> CORTEX_<NAME>.
package config

import "github.com/inventedsarawak/hyperion/packages/common/config"

// Service is the config namespace for this microservice.
const Service = "cortex"

// Defaults for local development via deploy/docker-compose.yml.
const (
	DefaultDatabaseURL      = "postgres://hyperion:hyperion@localhost:5432/hyperion?sslmode=disable"
	DefaultElasticsearchURL = "http://localhost:9200"
	DefaultIndexName        = "hyperion-vulnerabilities"
	DefaultGRPCAddr         = ":50051"
	DefaultNeo4jURI         = "bolt://localhost:7687"
	DefaultNeo4jUsername    = "neo4j"
	DefaultNeo4jPassword    = "hyperion"
	DefaultNeo4jDatabase    = "neo4j"
)

// Config holds cortex's runtime settings.
type Config struct {
	DatabaseURL      string
	ElasticsearchURL string
	IndexName        string
	GRPCAddr         string
	ServeGRPC        bool
	ConsumeStdin     bool

	Neo4jURI            string
	Neo4jUsername       string
	Neo4jPassword       string
	Neo4jDatabase       string
	BlastRadiusMaxDepth int

	loader *config.Loader
}

// Load reads configuration from the environment, applying defaults.
func Load() Config {
	l := config.For(Service)

	// Secret carries no default (an unset credential must read as unset), so
	// the local-dev fallback is applied here and still reported masked.
	neo4jPassword := l.Secret("NEO4J_PASSWORD")
	if neo4jPassword == "" {
		neo4jPassword = DefaultNeo4jPassword
	}

	return Config{
		loader:           l,
		DatabaseURL:      l.String("DATABASE_URL", DefaultDatabaseURL),
		ElasticsearchURL: l.String("ELASTICSEARCH_URL", DefaultElasticsearchURL),
		IndexName:        l.String("INDEX_NAME", DefaultIndexName),
		GRPCAddr:         l.String("GRPC_ADDR", DefaultGRPCAddr),
		ServeGRPC:        l.Bool("SERVE_GRPC", true),
		ConsumeStdin:     l.Bool("CONSUME_STDIN", false),

		Neo4jURI:      l.String("NEO4J_URI", DefaultNeo4jURI),
		Neo4jUsername: l.String("NEO4J_USERNAME", DefaultNeo4jUsername),
		Neo4jPassword: neo4jPassword,
		Neo4jDatabase: l.String("NEO4J_DATABASE", DefaultNeo4jDatabase),
		// 3 hops covers a repository, the library it names, and that
		// library's own dependency — deep enough to be useful, shallow
		// enough to stay fast on a dense graph.
		BlastRadiusMaxDepth: l.Int("BLAST_RADIUS_MAX_DEPTH", 3),
	}
}

// Describe returns every resolved setting with secrets masked.
func (c Config) Describe() []config.Entry {
	if c.loader == nil {
		return nil
	}
	return c.loader.Describe()
}
