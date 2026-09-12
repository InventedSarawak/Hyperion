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
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/repos/manifest"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
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

// Scan reads every dependency file it recognizes, anywhere in the repository,
// and returns one merged snapshot.
//
// The whole tree is listed in one request and the files are picked by name,
// because manifests live wherever a project puts them: a monorepo has a go.mod
// per service, a web app keeps its package.json in frontend/, a Foundry
// project vendors its Solidity libraries as git submodules.
//
// A repository with nothing we understand is a successful, empty result: the
// repository itself is still worth recording, and a later scan may find
// something. A file that is present but unreadable is reported, since that is
// a gap in coverage rather than an absence of data.
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

	files, submodules, err := c.tree(ctx, owner, name, meta.DefaultBranch)
	switch {
	case errors.Is(err, errEmptyRepository):
		return snapshot, nil // nothing committed yet: nothing to read, and nothing wrong
	case err != nil:
		return snapshot, err
	}

	found, dropped := manifest.Discover(files, c.parsers)
	if dropped > 0 {
		c.log.Warn("more dependency files than one scan reads; the deepest were left out",
			"repository", owner+"/"+name, "read", len(found), "left_out", dropped)
	}

	var errs []error
	for _, f := range found {
		content, err := c.fileAt(ctx, owner, name, f.Path, "")
		switch {
		case errors.Is(err, sourcehttp.ErrNotFound):
			continue // removed since the tree was listed
		case err != nil:
			errs = append(errs, err)
			continue
		}
		parsed, err := f.Parser.Parse(f.Path, content)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s/%s: %w", owner, name, err))
			continue
		}
		snapshot = snapshot.Merge(parsed)
	}

	if len(submodules) > 0 && slices.Contains(files, ".gitmodules") {
		deps, err := c.submoduleDependencies(ctx, owner, name, submodules)
		snapshot.Dependencies = append(snapshot.Dependencies, deps...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return snapshot, errors.Join(errs...)
}

// errEmptyRepository is a repository with no commits: it has no tree.
var errEmptyRepository = errors.New("github: repository is empty")

type gitTree struct {
	Tree []struct {
		Path string `json:"path"`
		Type string `json:"type"` // blob, tree, or commit (a submodule)
		SHA  string `json:"sha"`
	} `json:"tree"`
	Truncated bool `json:"truncated"`
}

// tree lists every file in the repository at the branch, and every submodule
// with the commit it is pinned to.
func (c *Client) tree(ctx context.Context, owner, name, branch string) ([]string, map[string]string, error) {
	if branch == "" {
		branch = "HEAD"
	}
	endpoint := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1", c.baseURL, owner, name, url.PathEscape(branch))
	var t gitTree
	if err := c.http.GetJSON(ctx, endpoint, &t); err != nil {
		if errors.Is(err, sourcehttp.ErrConflict) {
			return nil, nil, errEmptyRepository
		}
		return nil, nil, fmt.Errorf("github tree %s/%s: %w", owner, name, err)
	}
	if t.Truncated {
		c.log.Warn("repository too large to list in one request; scanning the part GitHub returned",
			"repository", owner+"/"+name)
	}
	var files []string
	submodules := map[string]string{}
	for _, entry := range t.Tree {
		switch entry.Type {
		case "blob":
			files = append(files, entry.Path)
		case "commit":
			submodules[entry.Path] = entry.SHA
		}
	}
	return files, submodules, nil
}

// maxSubmodules bounds the extra requests submodule resolution may make.
const maxSubmodules = 30

// submoduleDependencies turns git submodules that vendor a published library
// — how Foundry projects pull in OpenZeppelin — into ordinary dependencies,
// by reading the library's own version file at the commit it is pinned to.
func (c *Client) submoduleDependencies(ctx context.Context, owner, name string, pinned map[string]string) ([]model.Dependency, error) {
	content, err := c.fileAt(ctx, owner, name, ".gitmodules", "")
	if err != nil {
		return nil, err
	}
	var (
		deps []model.Dependency
		errs []error
	)
	for i, sub := range manifest.ParseGitmodules(content) {
		if i >= maxSubmodules {
			break
		}
		sha, ok := pinned[sub.Path]
		if !ok {
			continue
		}
		src, ok := manifest.SourceOf(sub.URL)
		if !ok {
			continue // not on GitHub: nothing this adapter can read
		}
		body, err := c.fileAt(ctx, src.Owner, src.Repo, src.VersionFile, sha)
		switch {
		case errors.Is(err, sourcehttp.ErrNotFound):
			continue // no version file: nothing published to match against
		case err != nil:
			errs = append(errs, err)
			continue
		}
		pkg, version, ok := manifest.ReadPackageVersion(body)
		if !ok {
			continue
		}
		if src.Package != "" {
			pkg = src.Package
		}
		deps = append(deps, model.Dependency{
			Package:      valueobject.NewPackageRef("npm", pkg, version),
			Direct:       true,
			ManifestPath: ".gitmodules (" + sub.Path + ")",
		})
	}
	return deps, errors.Join(errs...)
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

// fileAt fetches one file's contents, from the default branch when ref is
// empty.
func (c *Client) fileAt(ctx context.Context, owner, name, filePath, ref string) ([]byte, error) {
	segments := strings.Split(filePath, "/")
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	endpoint := fmt.Sprintf("%s/repos/%s/%s/contents/%s", c.baseURL, owner, name, strings.Join(segments, "/"))
	if ref != "" {
		endpoint += "?ref=" + url.QueryEscape(ref)
	}

	var file contentsFile
	if err := c.http.GetJSON(ctx, endpoint, &file); err != nil {
		return nil, fmt.Errorf("github contents %s/%s/%s: %w", owner, name, filePath, err)
	}

	// Above ~1 MB the API stops inlining content and offers a download URL
	// instead. No real manifest reaches that, so rather than build a second
	// fetch path, say plainly that this one was skipped.
	if file.Content == "" {
		return nil, fmt.Errorf("github contents %s/%s/%s: no inline content (size %d bytes)",
			owner, name, filePath, file.Size)
	}
	if file.Encoding != "base64" {
		return nil, fmt.Errorf("github contents %s/%s/%s: unexpected encoding %q",
			owner, name, filePath, file.Encoding)
	}

	// GitHub wraps the base64 payload at 60 columns.
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
	if err != nil {
		return nil, fmt.Errorf("github contents %s/%s/%s: decode: %w", owner, name, filePath, err)
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
