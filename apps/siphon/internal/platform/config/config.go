// Package config loads siphon's settings through Hyperion's centralized,
// namespaced config system. Every key is siphon.<NAME> -> SIPHON_<NAME>.
//
// Each ingestion source has its own block. A source that needs a credential
// stays inactive until that credential is present, so siphon runs with whatever
// subset of the ten sources is configured.
package config

import (
	"time"

	"github.com/inventedsarawak/hyperion/packages/common/config"
	"github.com/inventedsarawak/hyperion/packages/common/kafka"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/checkpoint"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/dedupe"
)

// Service is the config namespace for this microservice.
const Service = "siphon"

// Config holds siphon's runtime settings.
type Config struct {
	PollInterval time.Duration
	// LogLevel is debug, info, warn or error. At debug every signal
	// published is logged as it goes out.
	LogLevel string
	Lookback time.Duration

	NVD           NVDConfig
	GitHub        GitHubConfig
	CISAKEV       CISAKEVConfig
	ExploitDB     ExploitDBConfig
	MITRE         MITREConfig
	VendorAdvisor VendorAdvisoryConfig
	OSINT         OSINTConfig
	PackageFeeds  PackageFeedConfig
	Shodan        ShodanConfig
	GSD           GSDConfig

	RepoScan   RepoScanConfig
	Kafka      KafkaConfig
	Checkpoint CheckpointConfig
	Dedupe     DedupeConfig

	loader *config.Loader
}

// CheckpointConfig controls whether the ingestion watermark outlives the
// process. With it off, every restart reaches back exactly one Lookback — which
// re-reads what was already read, and misses anything published during an
// outage longer than that window.
type CheckpointConfig struct {
	Enabled   bool
	RedisAddr string
}

// DedupeConfig suppresses republishing observations that have not changed.
//
// The Window is a cost boundary, not a correctness one: forgetting early means
// publishing something unchanged again, which is merely wasteful. It is worth
// knowing that clearing the store (or waiting out the window) is what makes
// siphon republish everything it has seen — after wiping cortex's databases,
// do one or the other, or run a backfill.
type DedupeConfig struct {
	Enabled   bool
	RedisAddr string
	Window    time.Duration
}

// KafkaConfig chooses where published events go.
//
// Kafka is the default: the running system needs durability and replay, which
// a pipe cannot give it. Stdout is kept, not left behind — `task ingest` and
// `task backfill` set SIPHON_KAFKA_ENABLED=false and pipe siphon into cortex,
// which is still the simplest way to run the whole chain in one command. Both
// are adapters behind the same port, which is the point of the hexagon: the
// workflow above them cannot tell the difference.
type KafkaConfig struct {
	// Enabled publishes to Kafka instead of stdout.
	Enabled bool
	Brokers []string
	Topic   string
	// Partitions applies only when siphon has to create the topic.
	Partitions int
	// DependencyTopic carries repository manifest reads. When Kafka is on,
	// scans are published here instead of being sent to cortex over gRPC.
	DependencyTopic string
}

// RepoScanConfig drives the supply-chain half of ingestion: reading tracked
// repositories' manifests and reporting them to cortex.
//
// What to scan is not configured here. The watchlist lives in cortex and is
// edited in the product (deck's Repositories tab); siphon polls it. The
// -repos and -orgs flags remain for one-off scans from a script.
type RepoScanConfig struct {
	Enabled bool
	// PerOwnerLimit caps how many repositories a one-off -orgs scan takes
	// from each owner. Every repository costs roughly three API calls.
	PerOwnerLimit int
	// WatchInterval is how often the watchlist is checked for repositories
	// that are due — short, so one added in the UI is read within seconds.
	WatchInterval time.Duration
	// Interval is how long a successful scan stays fresh before the
	// repository is read again.
	Interval time.Duration
	// RetryInterval is how long a failed scan waits before it is retried.
	RetryInterval time.Duration
	BaseURL       string
	Token         string
	CortexAddr    string
}

// NVDConfig — source 1. Key optional: lifts 5 -> 50 req / 30s.
type NVDConfig struct {
	Enabled  bool
	BaseURL  string
	APIKey   string
	PageSize int
	MaxPages int
}

// GitHubConfig — source 2. Token optional: lifts 60 -> 5,000 req/hour.
type GitHubConfig struct {
	Enabled bool
	BaseURL string
	Token   string
}

// CISAKEVConfig — source 3. Public JSON catalog, no credential.
type CISAKEVConfig struct {
	Enabled bool
	FeedURL string
}

// ExploitDBConfig — source 4. Public CSV mirror, no credential.
type ExploitDBConfig struct {
	Enabled bool
	CSVURL  string
}

// MITREConfig — source 5. Public CVE Services API, no credential.
type MITREConfig struct {
	Enabled bool
	BaseURL string
}

// VendorAdvisoryConfig — source 6. Red Hat is public; MSRC key optional.
type VendorAdvisoryConfig struct {
	Enabled       bool
	RedHatBaseURL string
	MSRCBaseURL   string
	MSRCAPIKey    string
}

// OSINTConfig — source 7. Public RSS/Atom feeds, no credential.
type OSINTConfig struct {
	Enabled  bool
	FeedURLs []string
}

// PackageFeedConfig — source 8. OSV-backed watchlist, no credential.
type PackageFeedConfig struct {
	Enabled   bool
	BaseURL   string
	Watchlist []string
	// BulkBaseURL and BulkEcosystems drive the backfill, which reads OSV's
	// per-ecosystem exports rather than querying package by package.
	BulkBaseURL    string
	BulkEcosystems []string
}

// ShodanConfig — source 9. Uses the FREE CVEDB service; api.shodan.io key is
// optional and only needed for host-exposure enrichment.
type ShodanConfig struct {
	Enabled bool
	BaseURL string
	APIKey  string
}

// GSDConfig — source 10. OSV.dev, no credential.
type GSDConfig struct {
	Enabled bool
	BaseURL string
}

// Default endpoints, used when the env var is unset.
const (
	DefaultNVDBaseURL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	DefaultGitHubBaseURL     = "https://api.github.com"
	DefaultCISAKEVFeedURL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultExploitDBCSVURL   = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
	DefaultMITREBaseURL      = "https://cveawg.mitre.org/api"
	DefaultRedHatBaseURL     = "https://access.redhat.com/hydra/rest/securitydata"
	DefaultMSRCBaseURL       = "https://api.msrc.microsoft.com/cvrf/v3.0"
	DefaultShodanBaseURL     = "https://cvedb.shodan.io"
	DefaultOSVBaseURL        = "https://api.osv.dev/v1"
	DefaultOSVBulkBaseURL    = "https://osv-vulnerabilities.storage.googleapis.com"
	DefaultFullDisclosureRSS = "https://seclists.org/rss/fulldisclosure.rss"
	DefaultCortexGRPCAddr    = "localhost:50051"
)

// Load reads configuration from the environment, applying defaults.
func Load() Config {
	l := config.For(Service)

	return Config{
		loader:       l,
		PollInterval: l.Duration("POLL_INTERVAL", 10*time.Minute),
		LogLevel:     l.String("LOG_LEVEL", "info"),
		Lookback:     l.Duration("LOOKBACK", 2*time.Hour),

		NVD: NVDConfig{
			Enabled:  l.Bool("NVD_ENABLED", true),
			BaseURL:  l.String("NVD_BASE_URL", DefaultNVDBaseURL),
			APIKey:   l.Secret("NVD_API_KEY"),
			PageSize: l.Int("NVD_PAGE_SIZE", 2000),
			MaxPages: l.Int("NVD_MAX_PAGES", 5),
		},
		GitHub: GitHubConfig{
			Enabled: l.Bool("GITHUB_ENABLED", true),
			BaseURL: l.String("GITHUB_BASE_URL", DefaultGitHubBaseURL),
			Token:   l.Secret("GITHUB_TOKEN"),
		},
		CISAKEV: CISAKEVConfig{
			Enabled: l.Bool("CISA_KEV_ENABLED", true),
			FeedURL: l.String("CISA_KEV_FEED_URL", DefaultCISAKEVFeedURL),
		},
		ExploitDB: ExploitDBConfig{
			Enabled: l.Bool("EXPLOITDB_ENABLED", true),
			CSVURL:  l.String("EXPLOITDB_CSV_URL", DefaultExploitDBCSVURL),
		},
		MITRE: MITREConfig{
			Enabled: l.Bool("MITRE_ENABLED", true),
			BaseURL: l.String("MITRE_BASE_URL", DefaultMITREBaseURL),
		},
		VendorAdvisor: VendorAdvisoryConfig{
			Enabled:       l.Bool("VENDOR_ENABLED", true),
			RedHatBaseURL: l.String("VENDOR_REDHAT_BASE_URL", DefaultRedHatBaseURL),
			MSRCBaseURL:   l.String("VENDOR_MSRC_BASE_URL", DefaultMSRCBaseURL),
			MSRCAPIKey:    l.Secret("VENDOR_MSRC_API_KEY"),
		},
		OSINT: OSINTConfig{
			Enabled:  l.Bool("OSINT_ENABLED", true),
			FeedURLs: l.List("OSINT_RSS_FEEDS", []string{DefaultFullDisclosureRSS}),
		},
		PackageFeeds: PackageFeedConfig{
			Enabled:     l.Bool("PACKAGE_FEEDS_ENABLED", true),
			BaseURL:     l.String("PACKAGE_OSV_BASE_URL", DefaultOSVBaseURL),
			Watchlist:   l.List("PACKAGE_WATCHLIST", nil),
			BulkBaseURL: l.String("PACKAGE_OSV_BULK_BASE_URL", DefaultOSVBulkBaseURL),
			BulkEcosystems: l.List("PACKAGE_OSV_BULK_ECOSYSTEMS",
				[]string{"npm", "PyPI", "Go", "Maven", "crates.io", "RubyGems", "NuGet", "Packagist"}),
		},
		Shodan: ShodanConfig{
			Enabled: l.Bool("SHODAN_ENABLED", true),
			BaseURL: l.String("SHODAN_BASE_URL", DefaultShodanBaseURL),
			APIKey:  l.Secret("SHODAN_API_KEY"),
		},
		GSD: GSDConfig{
			Enabled: l.Bool("GSD_ENABLED", true),
			BaseURL: l.String("GSD_BASE_URL", DefaultOSVBaseURL),
		},

		RepoScan: RepoScanConfig{
			Enabled:       l.Bool("REPO_SCAN_ENABLED", true),
			PerOwnerLimit: l.Int("REPO_ORG_LIMIT", 20),
			WatchInterval: l.Duration("REPO_WATCH_INTERVAL", 30*time.Second),
			// Manifests change on the order of days, not minutes, and every
			// scan costs GitHub quota — so this is deliberately far slower
			// than the advisory poll.
			Interval:      l.Duration("REPO_SCAN_INTERVAL", 6*time.Hour),
			RetryInterval: l.Duration("REPO_RETRY_INTERVAL", 15*time.Minute),
			BaseURL:       l.String("GITHUB_BASE_URL", DefaultGitHubBaseURL),
			Token:         l.Secret("GITHUB_TOKEN"),
			CortexAddr:    l.String("CORTEX_GRPC_ADDR", DefaultCortexGRPCAddr),
		},

		Checkpoint: CheckpointConfig{
			Enabled:   l.Bool("CHECKPOINT_ENABLED", true),
			RedisAddr: l.String("REDIS_ADDR", checkpoint.DefaultAddr),
		},

		Dedupe: DedupeConfig{
			Enabled:   l.Bool("DEDUPE_ENABLED", true),
			RedisAddr: l.String("REDIS_ADDR", dedupe.DefaultAddr),
			// Comfortably longer than any lookback window, so an advisory is
			// published once rather than on every poll that still sees it.
			Window: l.Duration("DEDUPE_WINDOW", 24*time.Hour),
		},

		Kafka: KafkaConfig{
			Enabled:         l.Bool("KAFKA_ENABLED", true),
			Brokers:         l.List("KAFKA_BROKERS", []string{kafka.DefaultBroker}),
			Topic:           l.String("KAFKA_TOPIC", kafka.TopicSignals),
			Partitions:      l.Int("KAFKA_PARTITIONS", kafka.DefaultPartitions),
			DependencyTopic: l.String("KAFKA_DEPENDENCY_TOPIC", kafka.TopicDependencies),
		},
	}
}

// Describe returns every resolved setting with secrets masked, for startup logs.
func (c Config) Describe() []config.Entry {
	if c.loader == nil {
		return nil
	}
	return c.loader.Describe()
}
