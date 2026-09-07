package githubrepo

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
)

// discoverPageSize is GitHub's maximum page size for repository listings.
const discoverPageSize = 100

// Discover lists an owner's repositories, newest activity first.
//
// GitHub separates organizations from users at the API level, and asking the
// wrong endpoint 404s. Rather than make the caller know which one an owner is,
// this tries /orgs and falls back to /users.
func (c *Client) Discover(ctx context.Context, owner string, limit int) ([]string, error) {
	if owner == "" {
		return nil, fmt.Errorf("github discover: owner is required")
	}
	if limit <= 0 {
		limit = discoverPageSize
	}

	names, err := c.listRepos(ctx, "orgs", owner, limit)
	if errors.Is(err, sourcehttp.ErrNotFound) {
		// Not an organization — try it as a user account.
		names, err = c.listRepos(ctx, "users", owner, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("github discover %s: %w", owner, err)
	}
	return names, nil
}

// repoListing is the subset of the repository listing we act on.
type repoListing struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Fork     bool   `json:"fork"`
	Archived bool   `json:"archived"`
	Disabled bool   `json:"disabled"`
	Owner    struct {
		Login string `json:"login"`
	} `json:"owner"`
}

func (c *Client) listRepos(ctx context.Context, kind, owner string, limit int) ([]string, error) {
	var out []string

	for page := 1; len(out) < limit; page++ {
		endpoint, err := c.listURL(kind, owner, page)
		if err != nil {
			return nil, err
		}

		var batch []repoListing
		if err := c.http.GetJSON(ctx, endpoint, &batch); err != nil {
			return nil, err
		}

		for _, r := range batch {
			// A fork's manifest describes upstream's dependencies, not the
			// owner's; an archived or disabled repository ships nothing.
			if r.Fork || r.Archived || r.Disabled {
				continue
			}
			full := r.FullName
			if full == "" && r.Owner.Login != "" && r.Name != "" {
				full = r.Owner.Login + "/" + r.Name
			}
			if full == "" {
				continue
			}
			out = append(out, full)
			if len(out) == limit {
				return out, nil
			}
		}

		if len(batch) < discoverPageSize {
			break // last page
		}
	}
	return out, nil
}

func (c *Client) listURL(kind, owner string, page int) (string, error) {
	u, err := url.Parse(fmt.Sprintf("%s/%s/%s/repos", c.baseURL, kind, url.PathEscape(owner)))
	if err != nil {
		return "", fmt.Errorf("github discover: parse url: %w", err)
	}
	q := u.Query()
	q.Set("per_page", strconv.Itoa(discoverPageSize))
	q.Set("page", strconv.Itoa(page))
	q.Set("sort", "pushed") // most recently active first, so a limit keeps what matters
	q.Set("direction", "desc")
	if kind == "users" {
		q.Set("type", "owner") // exclude repos the user merely collaborates on
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
