// Package sources is the composition helper that decides which ingestion
// sources are active for this run.
//
// A source becomes active when it is enabled in config and has any credential
// it requires. Anything else is reported inactive with a human-readable reason,
// so it is obvious at a glance which of the ten documented feeds siphon is
// actually pulling from.
package sources

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/cisakev"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/exploitdb"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/github"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/gsd"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/mitre"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/nvd"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/osint"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/packagefeed"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/shodan"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/vendor"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/platform/config"
)

// Status describes one source's availability for this run.
type Status struct {
	Kind    valueobject.SourceKind
	Name    string
	Active  bool
	Reason  string             // why it is inactive; empty when active
	Note    string             // extra context when active (e.g. degraded limits)
	Client  ports.SourceClient // non-nil only when Active
	NeedsNo bool               // true when the source needs no credential at all
}

// Registry is the resolved set of sources for this run.
type Registry struct {
	statuses []Status
}

// Build resolves every documented source against the supplied configuration.
// httpClient may be nil, in which case each adapter uses its own default.
func Build(cfg config.Config, httpClient *http.Client) *Registry {
	opts := httpOptions(httpClient)

	return &Registry{statuses: []Status{
		buildNVD(cfg.NVD, opts),
		buildGitHub(cfg.GitHub, opts),
		buildCISAKEV(cfg.CISAKEV, opts),
		buildExploitDB(cfg.ExploitDB, opts),
		buildMITRE(cfg.MITRE, opts),
		buildVendor(cfg.VendorAdvisor, opts),
		buildOSINT(cfg.OSINT, opts),
		buildPackageFeed(cfg.PackageFeeds, httpClient),
		buildShodan(cfg.Shodan, opts),
		buildGSD(cfg.GSD, opts),
	}}
}

func httpOptions(httpClient *http.Client) []sourcehttp.Option {
	if httpClient == nil {
		return nil
	}
	return []sourcehttp.Option{sourcehttp.WithHTTPClient(httpClient)}
}

// --- per-source construction ---

func buildNVD(cfg config.NVDConfig, opts []sourcehttp.Option) Status {
	kind := valueobject.SourceKindNVD
	if !cfg.Enabled {
		return disabled(kind)
	}

	// NVD works unauthenticated, just far more slowly.
	note := ""
	if cfg.APIKey == "" {
		note = "no API key: limited to 5 requests / 30s (set SIPHON_NVD_API_KEY for 50)"
	}
	client := nvd.New(nil, cfg.BaseURL, cfg.APIKey,
		nvd.WithPageSize(cfg.PageSize),
		nvd.WithMaxPages(cfg.MaxPages),
	)
	return active(kind, client, note)
}

func buildGitHub(cfg config.GitHubConfig, opts []sourcehttp.Option) Status {
	kind := valueobject.SourceKindGitHubAdvisory
	if !cfg.Enabled {
		return disabled(kind)
	}

	note := ""
	if cfg.Token == "" {
		note = "no token: limited to 60 requests/hour (set SIPHON_GITHUB_TOKEN for 5,000)"
	}
	return active(kind, github.New(cfg.BaseURL, cfg.Token, opts...), note)
}

func buildCISAKEV(cfg config.CISAKEVConfig, opts []sourcehttp.Option) Status {
	kind := valueobject.SourceKindCISAKEV
	if !cfg.Enabled {
		return disabled(kind)
	}
	return noCredential(active(kind, cisakev.New(cfg.FeedURL, opts...), ""))
}

func buildExploitDB(cfg config.ExploitDBConfig, opts []sourcehttp.Option) Status {
	kind := valueobject.SourceKindExploitDB
	if !cfg.Enabled {
		return disabled(kind)
	}
	return noCredential(active(kind, exploitdb.New(cfg.CSVURL, opts...), ""))
}

func buildMITRE(cfg config.MITREConfig, opts []sourcehttp.Option) Status {
	kind := valueobject.SourceKindMITRE
	if !cfg.Enabled {
		return disabled(kind)
	}
	return noCredential(active(kind, mitre.New(cfg.BaseURL, opts...), ""))
}

func buildVendor(cfg config.VendorAdvisoryConfig, opts []sourcehttp.Option) Status {
	kind := valueobject.SourceKindVendorAdvisory
	if !cfg.Enabled {
		return disabled(kind)
	}

	note := "Red Hat advisories (public)"
	if cfg.MSRCAPIKey == "" {
		note += "; MSRC key unset (optional)"
	}
	return noCredential(active(kind, vendor.New(cfg.RedHatBaseURL, opts...), note))
}

func buildOSINT(cfg config.OSINTConfig, opts []sourcehttp.Option) Status {
	kind := valueobject.SourceKindOSINT
	if !cfg.Enabled {
		return disabled(kind)
	}
	note := fmt.Sprintf("%d feed(s)", len(cfg.FeedURLs))
	return noCredential(active(kind, osint.New(cfg.FeedURLs, opts...), note))
}

func buildPackageFeed(cfg config.PackageFeedConfig, httpClient *http.Client) Status {
	kind := valueobject.SourceKindPackageFeed
	if !cfg.Enabled {
		return disabled(kind)
	}

	client := packagefeed.New(cfg.BaseURL, cfg.Watchlist, httpClient)
	note := "OSV-backed watchlist"
	if len(cfg.Watchlist) == 0 {
		note += " (using default starter list; set SIPHON_PACKAGE_WATCHLIST)"
	}
	return noCredential(active(kind, client, note))
}

func buildShodan(cfg config.ShodanConfig, opts []sourcehttp.Option) Status {
	kind := valueobject.SourceKindShodan
	if !cfg.Enabled {
		return disabled(kind)
	}

	// CVEDB is free; the paid api.shodan.io key is not needed for this source.
	note := "via free CVEDB (no key required)"
	return noCredential(active(kind, shodan.New(cfg.BaseURL, cfg.APIKey, opts...), note))
}

func buildGSD(cfg config.GSDConfig, opts []sourcehttp.Option) Status {
	kind := valueobject.SourceKindGSD
	if !cfg.Enabled {
		return disabled(kind)
	}
	return noCredential(active(kind, gsd.New(cfg.BaseURL, opts...), "via OSV.dev"))
}

// --- status helpers ---

func active(kind valueobject.SourceKind, client ports.SourceClient, note string) Status {
	return Status{Kind: kind, Name: kind.DisplayName(), Active: true, Client: client, Note: note}
}

func disabled(kind valueobject.SourceKind) Status {
	return Status{
		Kind:   kind,
		Name:   kind.DisplayName(),
		Active: false,
		Reason: fmt.Sprintf("disabled via SIPHON_%s_ENABLED=false", envSuffix(kind)),
	}
}

func noCredential(s Status) Status {
	s.NeedsNo = true
	return s
}

// envSuffix maps a source kind to the env var fragment that toggles it.
func envSuffix(kind valueobject.SourceKind) string {
	switch kind {
	case valueobject.SourceKindGitHubAdvisory:
		return "GITHUB"
	case valueobject.SourceKindExploitDB:
		return "EXPLOITDB"
	case valueobject.SourceKindVendorAdvisory:
		return "VENDOR"
	case valueobject.SourceKindPackageFeed:
		return "PACKAGE_FEEDS"
	default:
		return strings.ToUpper(kind.String())
	}
}

// Statuses returns every known source's status, in documented order.
func (r *Registry) Statuses() []Status { return r.statuses }

// ActiveClients returns the source clients that will actually be polled.
func (r *Registry) ActiveClients() []ports.SourceClient {
	var out []ports.SourceClient
	for _, s := range r.statuses {
		if s.Active && s.Client != nil {
			out = append(out, s.Client)
		}
	}
	return out
}

// ActiveKinds lists the kinds that are active, for logging.
func (r *Registry) ActiveKinds() []string {
	var out []string
	for _, s := range r.statuses {
		if s.Active {
			out = append(out, s.Kind.String())
		}
	}
	return out
}

// InactiveReasons maps each inactive source to why it is inactive.
func (r *Registry) InactiveReasons() map[string]string {
	out := make(map[string]string)
	for _, s := range r.statuses {
		if !s.Active {
			out[s.Kind.String()] = s.Reason
		}
	}
	return out
}
