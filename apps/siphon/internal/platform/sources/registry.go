// Package sources is the composition helper that decides which ingestion
// sources are active for this run.
//
// A source becomes active only when it is (a) implemented, (b) enabled in
// config, and (c) supplied with any credential it requires. Anything else is
// reported as inactive with a human-readable reason, so operators can see at a
// glance which of the ten documented feeds siphon is actually pulling from.
package sources

import (
	"fmt"
	"net/http"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/nvd"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/platform/config"
)

// Status describes one source's availability for this run.
type Status struct {
	Kind   valueobject.SourceKind
	Name   string
	Active bool
	Reason string             // why it is inactive; empty when active
	Client ports.SourceClient // non-nil only when Active
}

// Registry is the resolved set of sources for this run.
type Registry struct {
	statuses []Status
}

// Build resolves every documented source against the supplied configuration.
// httpClient may be nil, in which case each adapter uses its own default.
func Build(cfg config.Config, httpClient *http.Client) *Registry {
	return &Registry{statuses: []Status{
		buildNVD(cfg.NVD, httpClient),
		notImplemented(valueobject.SourceKindGitHubAdvisory, cfg.GitHub.Enabled, credential(cfg.GitHub.Token, "SIPHON_GITHUB_TOKEN")),
		notImplemented(valueobject.SourceKindCISAKEV, cfg.CISAKEV.Enabled, ""),
		notImplemented(valueobject.SourceKindExploitDB, cfg.ExploitDB.Enabled, ""),
		notImplemented(valueobject.SourceKindMITRE, cfg.MITRE.Enabled, ""),
		notImplemented(valueobject.SourceKindVendorAdvisory, cfg.VendorAdvisor.Enabled, ""),
		notImplemented(valueobject.SourceKindOSINT, cfg.OSINT.Enabled, ""),
		notImplemented(valueobject.SourceKindPackageFeed, cfg.PackageFeeds.Enabled, ""),
		notImplemented(valueobject.SourceKindShodan, cfg.Shodan.Enabled, credential(cfg.Shodan.APIKey, "SIPHON_SHODAN_API_KEY")),
		notImplemented(valueobject.SourceKindGSD, cfg.GSD.Enabled, ""),
	}}
}

// buildNVD constructs the NVD adapter. NVD works without a key, so the source
// stays active either way; the key only raises the rate limit.
func buildNVD(cfg config.NVDConfig, httpClient *http.Client) Status {
	kind := valueobject.SourceKindNVD
	if !cfg.Enabled {
		return inactive(kind, "disabled via SIPHON_NVD_ENABLED=false")
	}

	client := nvd.New(httpClient, cfg.BaseURL, cfg.APIKey,
		nvd.WithPageSize(cfg.PageSize),
		nvd.WithMaxPages(cfg.MaxPages),
	)
	return Status{Kind: kind, Name: kind.DisplayName(), Active: true, Client: client}
}

// notImplemented reports a documented source that has no adapter yet. The
// credential reason (if any) is surfaced too, so the operator knows what will
// still be needed once the adapter lands.
func notImplemented(kind valueobject.SourceKind, enabled bool, credentialReason string) Status {
	switch {
	case !enabled:
		return inactive(kind, "disabled via configuration")
	case credentialReason != "":
		return inactive(kind, "adapter not implemented yet; also "+credentialReason)
	default:
		return inactive(kind, "adapter not implemented yet")
	}
}

// credential returns an empty string when the secret is present, or a reason
// naming the environment variable that supplies it.
func credential(value, envVar string) string {
	if value != "" {
		return ""
	}
	return fmt.Sprintf("missing credential %s", envVar)
}

func inactive(kind valueobject.SourceKind, reason string) Status {
	return Status{Kind: kind, Name: kind.DisplayName(), Active: false, Reason: reason}
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
