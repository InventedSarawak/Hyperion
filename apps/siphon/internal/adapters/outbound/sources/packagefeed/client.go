// Package packagefeed is an OUTBOUND adapter for package-manager ecosystems
// (npm, PyPI, RubyGems, Go, ...), used to drive the blast-radius feature.
//
// Package registries do not publish vulnerabilities themselves, so this adapter
// resolves a watchlist of packages against OSV.dev, which indexes advisories
// per ecosystem package. That yields exactly what blast radius needs: "which
// CVEs affect the libraries we track". No credential required.
// Docs: https://google.github.io/osv.dev/post-v1-query/
package packagefeed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/osv"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// DefaultBaseURL is the OSV.dev API root.
const DefaultBaseURL = "https://api.osv.dev/v1"

// DefaultWatchlist is a small starter set of widely-depended-on packages.
// Format per entry: "<ecosystem>:<package>".
var DefaultWatchlist = []string{
	"npm:lodash",
	"npm:express",
	"PyPI:django",
	"PyPI:requests",
}

const requestDelay = 300 * time.Millisecond

// Client resolves watched packages to their known vulnerabilities.
type Client struct {
	http      *http.Client
	baseURL   string
	watchlist []string
	limiter   <-chan time.Time
}

// New builds a package-feed client over a watchlist.
func New(baseURL string, watchlist []string, httpClient *http.Client) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if len(watchlist) == 0 {
		watchlist = DefaultWatchlist
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{http: httpClient, baseURL: baseURL, watchlist: watchlist}
}

// Kind reports the source this client speaks for.
func (c *Client) Kind() valueobject.SourceKind { return valueobject.SourceKindPackageFeed }

// Fetch queries OSV for each watched package and emits the advisories that
// changed at or after `since`.
func (c *Client) Fetch(ctx context.Context, since time.Time) ([]model.SourceSignal, error) {
	var (
		signals []model.SourceSignal
		seen    = map[string]struct{}{}
	)

	for _, watched := range c.watchlist {
		ecosystem, name, ok := splitWatch(watched)
		if !ok {
			continue
		}

		vulns, err := c.query(ctx, ecosystem, name)
		if err != nil {
			// One bad package must not fail the whole poll.
			continue
		}

		for _, v := range vulns {
			signal, ok := osv.ToSourceSignal(v, since)
			if !ok {
				continue
			}
			// A CVE can affect several watched packages; emit it once.
			if _, dup := seen[signal.CVEID]; dup {
				continue
			}
			seen[signal.CVEID] = struct{}{}

			signal.Description = fmt.Sprintf("Affects watched package %s (%s). %s", name, ecosystem, signal.Description)
			signals = append(signals, signal)
		}
		time.Sleep(requestDelay)
	}
	return signals, nil
}

// query asks OSV which vulnerabilities affect one package.
func (c *Client) query(ctx context.Context, ecosystem, name string) ([]osv.Vulnerability, error) {
	body, err := json.Marshal(map[string]any{
		"package": map[string]string{"name": name, "ecosystem": ecosystem},
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("packagefeed: osv status %d for %s/%s", resp.StatusCode, ecosystem, name)
	}

	var out struct {
		Vulns []osv.Vulnerability `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Vulns, nil
}

// splitWatch parses "<ecosystem>:<package>".
func splitWatch(entry string) (ecosystem, name string, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(entry), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
