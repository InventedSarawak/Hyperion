// Package config loads cortex's settings through Hyperion's centralized,
// namespaced config system. Every key is cortex.<NAME> -> CORTEX_<NAME>.
package config

import (
	"time"

	"github.com/inventedsarawak/hyperion/packages/common/config"
	"github.com/inventedsarawak/hyperion/packages/common/kafka"
)

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
	DefaultRedisAddr        = "localhost:6379"
	DefaultSubscriptionIdx  = "hyperion-subscriptions"
	// DefaultConsumerGroup names cortex's ingest group on the signal topic.
	DefaultConsumerGroup = "intel-indexer"
)

// Config holds cortex's runtime settings.
type Config struct {
	DatabaseURL      string
	ElasticsearchURL string
	IndexName        string
	GRPCAddr         string
	ServeGRPC        bool
	ConsumeStdin     bool
	// IngestWorkers is how many events are ingested concurrently. Each is
	// I/O-bound, so this is what sets backfill throughput.
	IngestWorkers int
	// IngestProgressEvery is how many ingested findings pass between progress
	// lines. A backfill runs for half an hour; silence is indistinguishable
	// from a stall.
	IngestProgressEvery int
	// LogLevel is debug, info, warn or error. At debug every finding ingested
	// is logged as it lands.
	LogLevel string

	Neo4jURI            string
	Neo4jUsername       string
	Neo4jPassword       string
	Neo4jDatabase       string
	BlastRadiusMaxDepth int

	RedisAddr         string
	SubscriptionIndex string
	AlertDedupeWindow time.Duration

	// GitHubBaseURL and GitHubToken drive repository discovery for the
	// watchlist. The token is optional but the anonymous budget (60/hour)
	// runs out after a few lookups.
	GitHubBaseURL string
	GitHubToken   string

	Kafka KafkaConfig

	loader *config.Loader
}

// KafkaConfig drives the event-backbone consumer, which is how cortex is fed
// by default.
//
// This is a second inbound adapter, not a second service: cortex consumes the
// topic and serves the API in one process. ConsumeStdin remains for the pipe
// (`task ingest`, `task backfill`) and takes precedence over this when set —
// a piped run reads its events from stdin and exits at EOF.
type KafkaConfig struct {
	Enabled bool
	Brokers []string
	Topic   string
	// Group is the consumer group. Every member of one group shares the
	// partitions between them; a second group would read the same records
	// again, independently — which is how relic (v4) will archive the same
	// firehose without disturbing ingest.
	Group string
	// Partitions applies only when cortex has to create the topic.
	Partitions int
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
		loader:              l,
		DatabaseURL:         l.String("DATABASE_URL", DefaultDatabaseURL),
		ElasticsearchURL:    l.String("ELASTICSEARCH_URL", DefaultElasticsearchURL),
		IndexName:           l.String("INDEX_NAME", DefaultIndexName),
		GRPCAddr:            l.String("GRPC_ADDR", DefaultGRPCAddr),
		ServeGRPC:           l.Bool("SERVE_GRPC", true),
		ConsumeStdin:        l.Bool("CONSUME_STDIN", false),
		IngestWorkers:       l.Int("INGEST_WORKERS", 8),
		IngestProgressEvery: l.Int("INGEST_PROGRESS_EVERY", 1000),
		LogLevel:            l.String("LOG_LEVEL", "info"),

		Neo4jURI:      l.String("NEO4J_URI", DefaultNeo4jURI),
		Neo4jUsername: l.String("NEO4J_USERNAME", DefaultNeo4jUsername),
		Neo4jPassword: neo4jPassword,
		Neo4jDatabase: l.String("NEO4J_DATABASE", DefaultNeo4jDatabase),
		// 3 hops covers a repository, the library it names, and that
		// library's own dependency — deep enough to be useful, shallow
		// enough to stay fast on a dense graph.
		BlastRadiusMaxDepth: l.Int("BLAST_RADIUS_MAX_DEPTH", 3),

		RedisAddr:         l.String("REDIS_ADDR", DefaultRedisAddr),
		SubscriptionIndex: l.String("SUBSCRIPTION_INDEX", DefaultSubscriptionIdx),
		// Advisories are re-observed on every poll and corrected for weeks;
		// an hour is long enough to stop the repeats without hiding a genuinely
		// new finding.
		AlertDedupeWindow: l.Duration("ALERT_DEDUPE_WINDOW", time.Hour),

		GitHubBaseURL: l.String("GITHUB_BASE_URL", "https://api.github.com"),
		GitHubToken:   l.Secret("GITHUB_TOKEN"),

		Kafka: KafkaConfig{
			Enabled:    l.Bool("KAFKA_ENABLED", true),
			Brokers:    l.List("KAFKA_BROKERS", []string{kafka.DefaultBroker}),
			Topic:      l.String("KAFKA_TOPIC", kafka.TopicSignals),
			Group:      l.String("KAFKA_GROUP", DefaultConsumerGroup),
			Partitions: l.Int("KAFKA_PARTITIONS", kafka.DefaultPartitions),
		},
	}
}

// Describe returns every resolved setting with secrets masked.
func (c Config) Describe() []config.Entry {
	if c.loader == nil {
		return nil
	}
	return c.loader.Describe()
}
