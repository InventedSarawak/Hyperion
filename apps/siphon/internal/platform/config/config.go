// Package config loads siphon's runtime configuration from the environment.
//
// Every ingestion source has its own block. A source that needs a credential
// stays inactive until that credential is present, so siphon can run with any
// subset of the ten sources configured.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

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
}

// NVDConfig configures the National Vulnerability Database source (source 1).
// The API key is optional but strongly recommended: it lifts the rate limit
// from 5 to 50 requests per rolling 30s window.
type NVDConfig struct {
	Enabled  bool
	BaseURL  string
	APIKey   string
	PageSize int
	MaxPages int
}

// GitHubConfig configures the GitHub Advisory Database source (source 2).
// A personal access token lifts the REST limit from 60 to 5000 requests/hour.
type GitHubConfig struct {
	Enabled bool
	BaseURL string
	Token   string
}

// CISAKEVConfig configures the CISA Known Exploited Vulnerabilities catalog
// (source 3). It is a public JSON feed and needs no credential.
type CISAKEVConfig struct {
	Enabled bool
	FeedURL string
}

// ExploitDBConfig configures the Exploit-DB source (source 4). Data is a CSV
// in the public GitLab mirror; no credential required.
type ExploitDBConfig struct {
	Enabled bool
	CSVURL  string
}

// MITREConfig configures the MITRE CVE List source (source 5), served by the
// public CVE Services API. No credential is needed for read access.
type MITREConfig struct {
	Enabled bool
	BaseURL string
}

// VendorAdvisoryConfig configures vendor security advisories (source 6).
// Red Hat's Security Data API is public; MSRC also serves anonymously but a
// key raises limits.
type VendorAdvisoryConfig struct {
	Enabled       bool
	RedHatBaseURL string
	MSRCBaseURL   string
	MSRCAPIKey    string
}

// OSINTConfig configures OSINT / mailing-list ingestion (source 7) from a list
// of RSS/Atom feed URLs, e.g. the Full Disclosure list.
type OSINTConfig struct {
	Enabled  bool
	FeedURLs []string
}

// PackageFeedConfig configures package-manager metadata feeds (source 8) used
// for blast-radius dependency mapping.
type PackageFeedConfig struct {
	Enabled      bool
	NPMBaseURL   string
	PyPIBaseURL  string
	RubyGemsBase string
	Ecosystems   []string
}

// ShodanConfig configures Shodan/Censys internet-exposure enrichment
// (source 9). Requires a paid API key; inactive without one.
type ShodanConfig struct {
	Enabled bool
	BaseURL string
	APIKey  string
}

// GSDConfig configures the Global Security Database / OSV source (source 10).
// The OSV.dev API is public and needs no credential.
type GSDConfig struct {
	Enabled bool
	BaseURL string
}

// Default endpoints for each source, used when the env var is unset.
const (
	DefaultNVDBaseURL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	DefaultGitHubBaseURL     = "https://api.github.com"
	DefaultCISAKEVFeedURL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultExploitDBCSVURL   = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
	DefaultMITREBaseURL      = "https://cveawg.mitre.org/api"
	DefaultRedHatBaseURL     = "https://access.redhat.com/hydra/rest/securitydata"
	DefaultMSRCBaseURL       = "https://api.msrc.microsoft.com/cvrf/v3.0"
	DefaultNPMBaseURL        = "https://registry.npmjs.org"
	DefaultPyPIBaseURL       = "https://pypi.org/pypi"
	DefaultRubyGemsBaseURL   = "https://rubygems.org/api/v1"
	DefaultShodanBaseURL     = "https://api.shodan.io"
	DefaultGSDBaseURL        = "https://api.osv.dev/v1"
	DefaultFullDisclosureRSS = "https://seclists.org/rss/fulldisclosure.rss"
)

// Load reads configuration from the environment, applying defaults.
func Load() Config {
	return Config{
		PollInterval: getduration("SIPHON_POLL_INTERVAL", 10*time.Minute),
		Lookback:     getduration("SIPHON_LOOKBACK", 2*time.Hour),

		NVD: NVDConfig{
			Enabled:  getbool("SIPHON_NVD_ENABLED", true),
			BaseURL:  getenv("SIPHON_NVD_BASE_URL", DefaultNVDBaseURL),
			APIKey:   getenv("SIPHON_NVD_API_KEY", ""),
			PageSize: getint("SIPHON_NVD_PAGE_SIZE", 2000),
			MaxPages: getint("SIPHON_NVD_MAX_PAGES", 5),
		},
		GitHub: GitHubConfig{
			Enabled: getbool("SIPHON_GITHUB_ENABLED", true),
			BaseURL: getenv("SIPHON_GITHUB_BASE_URL", DefaultGitHubBaseURL),
			Token:   getenv("SIPHON_GITHUB_TOKEN", ""),
		},
		CISAKEV: CISAKEVConfig{
			Enabled: getbool("SIPHON_CISA_KEV_ENABLED", true),
			FeedURL: getenv("SIPHON_CISA_KEV_FEED_URL", DefaultCISAKEVFeedURL),
		},
		ExploitDB: ExploitDBConfig{
			Enabled: getbool("SIPHON_EXPLOITDB_ENABLED", true),
			CSVURL:  getenv("SIPHON_EXPLOITDB_CSV_URL", DefaultExploitDBCSVURL),
		},
		MITRE: MITREConfig{
			Enabled: getbool("SIPHON_MITRE_ENABLED", true),
			BaseURL: getenv("SIPHON_MITRE_BASE_URL", DefaultMITREBaseURL),
		},
		VendorAdvisor: VendorAdvisoryConfig{
			Enabled:       getbool("SIPHON_VENDOR_ENABLED", true),
			RedHatBaseURL: getenv("SIPHON_VENDOR_REDHAT_BASE_URL", DefaultRedHatBaseURL),
			MSRCBaseURL:   getenv("SIPHON_VENDOR_MSRC_BASE_URL", DefaultMSRCBaseURL),
			MSRCAPIKey:    getenv("SIPHON_VENDOR_MSRC_API_KEY", ""),
		},
		OSINT: OSINTConfig{
			Enabled:  getbool("SIPHON_OSINT_ENABLED", true),
			FeedURLs: getlist("SIPHON_OSINT_RSS_FEEDS", []string{DefaultFullDisclosureRSS}),
		},
		PackageFeeds: PackageFeedConfig{
			Enabled:      getbool("SIPHON_PACKAGE_FEEDS_ENABLED", true),
			NPMBaseURL:   getenv("SIPHON_PACKAGE_NPM_BASE_URL", DefaultNPMBaseURL),
			PyPIBaseURL:  getenv("SIPHON_PACKAGE_PYPI_BASE_URL", DefaultPyPIBaseURL),
			RubyGemsBase: getenv("SIPHON_PACKAGE_RUBYGEMS_BASE_URL", DefaultRubyGemsBaseURL),
			Ecosystems:   getlist("SIPHON_PACKAGE_ECOSYSTEMS", []string{"npm", "pypi"}),
		},
		Shodan: ShodanConfig{
			Enabled: getbool("SIPHON_SHODAN_ENABLED", true),
			BaseURL: getenv("SIPHON_SHODAN_BASE_URL", DefaultShodanBaseURL),
			APIKey:  getenv("SIPHON_SHODAN_API_KEY", ""),
		},
		GSD: GSDConfig{
			Enabled: getbool("SIPHON_GSD_ENABLED", true),
			BaseURL: getenv("SIPHON_GSD_BASE_URL", DefaultGSDBaseURL),
		},
	}
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func getduration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func getint(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return fallback
}

func getbool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			return b
		}
	}
	return fallback
}

func getlist(key string, fallback []string) []string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}
