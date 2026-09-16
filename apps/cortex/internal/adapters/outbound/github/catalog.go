// Package github is an OUTBOUND adapter implementing ports.RepositoryCatalog
// against the GitHub REST API: it lists the repositories a user or
// organization owns, so they can be picked for tracking instead of typed.
//
// Docs: https://docs.github.com/en/rest/repos/repos#list-organization-repositories
// and https://docs.github.com/en/rest/repos/repos#list-repositories-for-a-user
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// DefaultBaseURL is the public GitHub API.
const DefaultBaseURL = "https://api.github.com"

// pageSize is GitHub's maximum page size for repository listings.
const pageSize = 100

// Catalog lists an owner's repositories.
type Catalog struct {
	http    *http.Client
	baseURL string
	token   string
}

// New builds a catalog. The token is optional: listing works anonymously, but
// the anonymous budget is 60 requests an hour shared by everything on the host.
func New(httpClient *http.Client, baseURL, token string) *Catalog {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Catalog{http: httpClient, baseURL: strings.TrimRight(baseURL, "/"), token: token}
}

// errNotFound is a 404 from one endpoint, before falling back to the other.
var errNotFound = errors.New("github: not found")

// ListOwnerRepositories lists repositories, most recently pushed first.
//
// GitHub separates organizations from users at the API level and 404s on the
// wrong one, so this asks /orgs first and falls back to /users — the caller
// types a name and should not need to know which kind of account it is.
func (c *Catalog) ListOwnerRepositories(ctx context.Context, owner string, limit int) ([]model.DiscoveredRepository, error) {
	owner = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(owner), "@"))
	if owner == "" {
		return nil, fmt.Errorf("github: owner is required")
	}

	repos, err := c.list(ctx, "orgs", owner, limit)
	if errors.Is(err, errNotFound) {
		repos, err = c.list(ctx, "users", owner, limit)
	}
	if errors.Is(err, errNotFound) {
		return nil, ports.OwnerNotFound(owner)
	}
	return repos, err
}

// listing is the subset of a repository listing that is shown.
type listing struct {
	FullName    string `json:"full_name"`
	Description string `json:"description"`
	Language    string `json:"language"`
	Stars       int    `json:"stargazers_count"`
	PushedAt    string `json:"pushed_at"`
	Fork        bool   `json:"fork"`
	Archived    bool   `json:"archived"`
	Disabled    bool   `json:"disabled"`
}

func (c *Catalog) list(ctx context.Context, kind, owner string, limit int) ([]model.DiscoveredRepository, error) {
	var out []model.DiscoveredRepository
	for page := 1; len(out) < limit; page++ {
		var batch []listing
		if err := c.get(ctx, c.pageURL(kind, owner, page), &batch); err != nil {
			return nil, err
		}
		for _, r := range batch {
			if r.Disabled || r.FullName == "" {
				continue // a disabled repository cannot be read at all
			}
			pushed, _ := time.Parse(time.RFC3339, r.PushedAt)
			out = append(out, model.DiscoveredRepository{
				FullName:    r.FullName,
				Description: r.Description,
				Language:    r.Language,
				Stars:       r.Stars,
				PushedAt:    pushed,
				Fork:        r.Fork,
				Archived:    r.Archived,
			})
			if len(out) == limit {
				return out, nil
			}
		}
		if len(batch) < pageSize {
			break
		}
	}
	return out, nil
}

func (c *Catalog) pageURL(kind, owner string, page int) string {
	q := url.Values{}
	q.Set("per_page", strconv.Itoa(pageSize))
	q.Set("page", strconv.Itoa(page))
	q.Set("sort", "pushed") // most recently active first, so a limit keeps what matters
	q.Set("direction", "desc")
	if kind == "users" {
		q.Set("type", "owner") // not repositories the user merely collaborates on
	}
	return fmt.Sprintf("%s/%s/%s/repos?%s", c.baseURL, kind, url.PathEscape(owner), q.Encode())
}

func (c *Catalog) get(ctx context.Context, endpoint string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("github: build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "hyperion-cortex/1.0")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("github: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return errNotFound
	case resp.Header.Get("X-RateLimit-Remaining") == "0":
		reset := resp.Header.Get("X-RateLimit-Reset")
		if secs, err := strconv.ParseInt(reset, 10, 64); err == nil {
			reset = time.Unix(secs, 0).Format(time.Kitchen)
		}
		return fmt.Errorf("github: rate limit exhausted until %s; set CORTEX_GITHUB_TOKEN to raise it", reset)
	case resp.StatusCode != http.StatusOK:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("github: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return fmt.Errorf("github: decode: %w", err)
	}
	return nil
}
