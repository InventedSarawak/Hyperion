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
)

// Config holds cortex's runtime settings.
type Config struct {
	DatabaseURL      string
	ElasticsearchURL string
	IndexName        string
	GRPCAddr         string
	ServeGRPC        bool
	ConsumeStdin     bool

	loader *config.Loader
}

// Load reads configuration from the environment, applying defaults.
func Load() Config {
	l := config.For(Service)
	return Config{
		loader:           l,
		DatabaseURL:      l.String("DATABASE_URL", DefaultDatabaseURL),
		ElasticsearchURL: l.String("ELASTICSEARCH_URL", DefaultElasticsearchURL),
		IndexName:        l.String("INDEX_NAME", DefaultIndexName),
		GRPCAddr:         l.String("GRPC_ADDR", DefaultGRPCAddr),
		ServeGRPC:        l.Bool("SERVE_GRPC", true),
		ConsumeStdin:     l.Bool("CONSUME_STDIN", false),
	}
}

// Describe returns every resolved setting with secrets masked.
func (c Config) Describe() []config.Entry {
	if c.loader == nil {
		return nil
	}
	return c.loader.Describe()
}
