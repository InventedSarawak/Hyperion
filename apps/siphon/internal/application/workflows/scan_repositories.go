package workflows

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/ports"
)

// ScanRepositories reads the dependency manifests of every watched repository
// and reports each one to the intelligence service.
//
// This is the supply-chain half of ingestion: the source adapters answer "what
// is vulnerable?", and this answers "who depends on what?". Neither is useful
// for blast radius without the other.
type ScanRepositories struct {
	client     ports.RepositoryClient
	discoverer ports.RepositoryDiscoverer
	publisher  ports.DependencyPublisher
	targets    Targets
	log        *slog.Logger
}

// Targets is what to scan: repositories named explicitly, plus every
// repository belonging to the named owners.
type Targets struct {
	Repositories  []string // "owner/name"
	Organizations []string // org or user logins to enumerate
	PerOwnerLimit int      // cap per owner; each repository costs ~3 API calls
}

// NewScanRepositories wires the use case with its outbound ports. The
// discoverer may be nil when only explicit repositories are configured.
func NewScanRepositories(
	client ports.RepositoryClient,
	discoverer ports.RepositoryDiscoverer,
	publisher ports.DependencyPublisher,
	targets Targets,
) *ScanRepositories {
	return &ScanRepositories{
		client:     client,
		discoverer: discoverer,
		publisher:  publisher,
		targets:    targets,
		log:        slog.Default(),
	}
}

// resolve expands the configured owners into repository names and merges them
// with the explicit list, removing duplicates.
//
// Discovery runs on every scan rather than once at startup: a repository
// created after the process booted is exactly the one most likely to be
// missing from anyone's hand-written watchlist.
func (s *ScanRepositories) resolve(ctx context.Context) ([]string, []error) {
	var (
		errs []error
		out  []string
		seen = make(map[string]struct{})
	)

	add := func(entry string) {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return
		}
		key := strings.ToLower(entry)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, entry)
	}

	for _, entry := range s.targets.Repositories {
		add(entry)
	}

	for _, owner := range s.targets.Organizations {
		owner = strings.TrimSpace(owner)
		if owner == "" {
			continue
		}
		if s.discoverer == nil {
			errs = append(errs, fmt.Errorf("scan repositories: %q configured but discovery is unavailable", owner))
			continue
		}

		found, err := s.discoverer.Discover(ctx, owner, s.targets.PerOwnerLimit)
		if err != nil {
			s.log.Error("repository discovery failed", "owner", owner, "error", err)
			errs = append(errs, err)
			continue
		}
		s.log.Info("repositories discovered", "owner", owner, "count", len(found))
		for _, entry := range found {
			add(entry)
		}
	}
	return out, errs
}

// Run scans every watched repository and returns the total number of
// dependency edges written. One repository failing does not stop the rest:
// errors are collected and returned together, after every repository has been
// attempted.
//
// The `since` argument is accepted so the scheduler can drive this like any
// other poller, and deliberately ignored: a manifest has no watermark. Its
// current contents are the whole truth, and there is no incremental window to
// ask for.
func (s *ScanRepositories) Run(ctx context.Context, _ time.Time) (int, error) {
	repositories, errs := s.resolve(ctx)
	total := 0

	for _, entry := range repositories {
		owner, name, err := splitRepository(entry)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		written, err := scanAndPublish(ctx, s.client, s.publisher, owner, name)
		if err != nil {
			errs = append(errs, err)
			if written == 0 {
				continue
			}
		}

		total += written
		s.log.Info("repository scanned", "repository", entry, "written", written)
	}
	return total, errors.Join(errs...)
}

// scanAndPublish reads one repository's manifests and hands them to the
// intelligence service, returning the edges written.
//
// A partial read is still published — one unreadable manifest should not
// discard the ones that parsed — and its error is returned alongside the
// count, so the caller can both record the edges and report the problem.
func scanAndPublish(
	ctx context.Context,
	client ports.RepositoryClient,
	publisher ports.DependencyPublisher,
	owner, name string,
) (int, error) {
	snapshot, scanErr := client.Scan(ctx, owner, name)
	if scanErr != nil && snapshot.Validate() != nil {
		return 0, scanErr
	}

	written, err := publisher.Publish(ctx, snapshot)
	if err != nil {
		return 0, errors.Join(scanErr, err)
	}
	return written, scanErr
}

// splitRepository parses an "owner/name" watchlist entry.
func splitRepository(entry string) (string, string, error) {
	owner, name, found := strings.Cut(strings.TrimSpace(entry), "/")
	owner, name = strings.TrimSpace(owner), strings.TrimSpace(name)
	if !found || owner == "" || name == "" {
		return "", "", fmt.Errorf("scan repositories: %q is not in owner/name form", entry)
	}
	return owner, name, nil
}
