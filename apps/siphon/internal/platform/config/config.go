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
)

// Service is the config namespace for this microservice.
const Service = "siphon"

// Config holds siphon's runtime settings.
type Config struct {
	PollInterval time.Duration
	Lookback     time.Duration

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

	loader *config.Loader
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
	DefaultFullDisclosureRSS = "https://seclists.org/rss/fulldisclosure.rss"
)

// Load reads configuration from the environment, applying defaults.
func Load() Config {
	l := config.For(Service)

	return Config{
		loader:       l,
		PollInterval: l.Duration("POLL_INTERVAL", 10*time.Minute),
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
			Enabled:   l.Bool("PACKAGE_FEEDS_ENABLED", true),
			BaseURL:   l.String("PACKAGE_OSV_BASE_URL", DefaultOSVBaseURL),
			Watchlist: l.List("PACKAGE_WATCHLIST", nil),
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
	}
}

// Describe returns every resolved setting with secrets masked, for startup logs.
func (c Config) Describe() []config.Entry {
	if c.loader == nil {
		return nil
	}
	return c.loader.Describe()
}
