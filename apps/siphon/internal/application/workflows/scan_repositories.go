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
	client       ports.RepositoryClient
	publisher    ports.DependencyPublisher
	repositories []string // "owner/name"
	log          *slog.Logger
}

// NewScanRepositories wires the use case with its outbound ports.
func NewScanRepositories(client ports.RepositoryClient, publisher ports.DependencyPublisher, repositories []string) *ScanRepositories {
	return &ScanRepositories{
		client:       client,
		publisher:    publisher,
		repositories: repositories,
		log:          slog.Default(),
	}
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
	var (
		total int
		errs  []error
	)

	for _, entry := range s.repositories {
		owner, name, err := splitRepository(entry)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		snapshot, err := s.client.Scan(ctx, owner, name)
		if err != nil {
			// A partial read is still worth publishing: one unreadable
			// manifest should not discard the ones that parsed.
			s.log.Warn("repository scan incomplete", "repository", entry, "error", err)
			errs = append(errs, err)
			if snapshot.Validate() != nil {
				continue
			}
		}

		written, err := s.publisher.Publish(ctx, snapshot)
		if err != nil {
			s.log.Error("dependency publish failed", "repository", entry, "error", err)
			errs = append(errs, err)
			continue
		}

		total += written
		s.log.Info("repository scanned",
			"repository", snapshot.Repository.FullName(),
			"publishes", snapshot.Publishes.Name,
			"dependencies", len(snapshot.Dependencies),
			"written", written)
	}
	return total, errors.Join(errs...)
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
