// Package githubrepo is an OUTBOUND adapter that reads a repository's
// dependency manifests from GitHub, mapping them onto a domain snapshot.
//
// It is distinct from adapters/outbound/sources/github, which reads the
// Advisory Database. That one asks "what is vulnerable?"; this one asks "who
// depends on what?" — the two halves the blast-radius traversal joins.
//
// Docs: https://docs.github.com/en/rest/repos/contents
package githubrepo

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/repos/manifest"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
)

// DefaultBaseURL is the public GitHub REST API root.
const DefaultBaseURL = "https://api.github.com"

// Pacing mirrors the advisory adapter: a token lifts the hourly budget from 60
// to 5,000. Each repository costs one metadata call plus one call per manifest
// probed, so an unauthenticated scan of more than a handful of repositories
// will exhaust the budget.
const (
	delayWithToken    = time.Second
	delayWithoutToken = 5 * time.Second
)

// Client reads manifests from GitHub repositories.
type Client struct {
	http    *sourcehttp.Client
	baseURL string
	parsers []manifest.Parser
	now     func() time.Time
	log     *slog.Logger
}

// New builds a repository client. An empty token still works, just slowly.
func New(baseURL, token string, opts ...sourcehttp.Option) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}

	delay := delayWithoutToken
	all := []sourcehttp.Option{
		sourcehttp.WithHeader("Accept", "application/vnd.github+json"),
		sourcehttp.WithHeader("X-GitHub-Api-Version", "2022-11-28"),
	}
	if token != "" {
		delay = delayWithToken
		all = append(all, sourcehttp.WithHeader("Authorization", "Bearer "+token))
	}
	all = append(all, opts...)

	return &Client{
		http:    sourcehttp.New(delay, all...),
		baseURL: baseURL,
		parsers: manifest.Parsers(),
		now:     time.Now,
		log:     slog.Default(),
	}
}

// Scan reads every manifest it recognizes and returns one merged snapshot.
//
// A repository with no manifest we understand is a successful, empty result:
// the repository itself is still worth recording, and a later scan may find
// one. A manifest that is present but unreadable is reported, since that is a
// gap in coverage rather than an absence of data.
func (c *Client) Scan(ctx context.Context, owner, name string) (model.RepositorySnapshot, error) {
	meta, err := c.repository(ctx, owner, name)
	if err != nil {
		return model.RepositorySnapshot{}, err
	}

	snapshot := model.RepositorySnapshot{
		Repository: model.Repository{
			Owner:         meta.Owner.Login,
			Name:          meta.Name,
			URL:           meta.HTMLURL,
			DefaultBranch: meta.DefaultBranch,
		},
		Author:     model.Author{Login: meta.Owner.Login, URL: meta.Owner.HTMLURL},
		ObservedAt: c.now().UTC(),
	}
	// Fall back to what the caller asked for when the API omits a field.
	if snapshot.Repository.Owner == "" {
		snapshot.Repository.Owner = owner
	}
	if snapshot.Repository.Name == "" {
		snapshot.Repository.Name = name
	}

	var errs []error
	for _, parser := range c.parsers {
		content, err := c.manifestFile(ctx, owner, name, parser.Path())
		switch {
		case errors.Is(err, sourcehttp.ErrNotFound):
			continue // this repository simply does not use that ecosystem
		case err != nil:
			errs = append(errs, err)
			continue
		}

		parsed, err := parser.Parse(content)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s/%s: %w", owner, name, err))
			continue
		}
		snapshot = snapshot.Merge(parsed)
	}
	return snapshot, errors.Join(errs...)
}

// --- GitHub wire DTOs (private to the adapter) ---

type repositoryMeta struct {
	Name          string `json:"name"`
	HTMLURL       string `json:"html_url"`
	DefaultBranch string `json:"default_branch"`
	Owner         struct {
		Login   string `json:"login"`
		HTMLURL string `json:"html_url"`
	} `json:"owner"`
}

type contentsFile struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
	Size     int    `json:"size"`
}

func (c *Client) repository(ctx context.Context, owner, name string) (repositoryMeta, error) {
	var meta repositoryMeta
	url := fmt.Sprintf("%s/repos/%s/%s", c.baseURL, owner, name)
	if err := c.http.GetJSON(ctx, url, &meta); err != nil {
		if errors.Is(err, sourcehttp.ErrNotFound) {
			return repositoryMeta{}, repoNotFound{owner: owner, name: name}
		}
		return repositoryMeta{}, fmt.Errorf("github repo %s/%s: %w", owner, name, err)
	}
	return meta, nil
}

// manifestFile fetches one file's contents from the repository's default branch.
func (c *Client) manifestFile(ctx context.Context, owner, name, path string) ([]byte, error) {
	var file contentsFile
	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s", c.baseURL, owner, name, path)
	if err := c.http.GetJSON(ctx, url, &file); err != nil {
		return nil, fmt.Errorf("github contents %s/%s/%s: %w", owner, name, path, err)
	}

	// Above ~1 MB the API stops inlining content and offers a download URL
	// instead. No real go.mod or package.json reaches that, so rather than
	// build a second fetch path, say plainly that this one was skipped.
	if file.Content == "" {
		return nil, fmt.Errorf("github contents %s/%s/%s: no inline content (size %d bytes)",
			owner, name, path, file.Size)
	}
	if file.Encoding != "base64" {
		return nil, fmt.Errorf("github contents %s/%s/%s: unexpected encoding %q",
			owner, name, path, file.Encoding)
	}

	// GitHub wraps the base64 payload at 60 columns.
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
	if err != nil {
		return nil, fmt.Errorf("github contents %s/%s/%s: decode: %w", owner, name, path, err)
	}
	return decoded, nil
}

// repoNotFound is GitHub's 404 for a repository, worded for whoever reads the
// watchlist: this message is what the Repositories tab shows beside a failed
// scan. GitHub answers 404 rather than 403 for a private repository the token
// cannot read, so that possibility is named too.
type repoNotFound struct{ owner, name string }

func (e repoNotFound) Error() string {
	return fmt.Sprintf("GitHub has no repository %s/%s — it may have been renamed or deleted, "+
		"or it is private and the token cannot read it", e.owner, e.name)
}

func (e repoNotFound) Unwrap() error { return sourcehttp.ErrNotFound }
