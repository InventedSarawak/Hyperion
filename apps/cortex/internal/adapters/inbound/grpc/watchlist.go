package grpc

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	watchlistv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/watchlist/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// WatchlistManager is the write side this adapter drives.
type WatchlistManager interface {
	Track(ctx context.Context, fullNames []string) ([]model.TrackedRepository, error)
	Untrack(ctx context.Context, fullName string) (bool, error)
	RecordScan(ctx context.Context, outcome model.ScanOutcome) error
}

// WatchlistReader is the read side this adapter drives.
type WatchlistReader interface {
	Repositories(ctx context.Context) ([]model.TrackedRepository, error)
	Discover(ctx context.Context, owner string, limit int) ([]model.DiscoveredRepository, error)
}

// WatchlistServer implements watchlistv1.WatchlistServiceServer.
type WatchlistServer struct {
	watchlistv1.UnimplementedWatchlistServiceServer
	manage WatchlistManager
	read   WatchlistReader
}

// NewWatchlistServer wires the adapter to the watchlist use cases.
func NewWatchlistServer(manage WatchlistManager, read WatchlistReader) *WatchlistServer {
	return &WatchlistServer{manage: manage, read: read}
}

// ListRepositories returns every tracked repository.
func (s *WatchlistServer) ListRepositories(ctx context.Context, _ *watchlistv1.ListRepositoriesRequest) (*watchlistv1.ListRepositoriesResponse, error) {
	repos, err := s.read.Repositories(ctx)
	if err != nil {
		return nil, mapWatchlistError(err)
	}
	return &watchlistv1.ListRepositoriesResponse{Repositories: toProtoTracked(repos)}, nil
}

// DiscoverRepositories lists an owner's repositories on GitHub.
func (s *WatchlistServer) DiscoverRepositories(ctx context.Context, req *watchlistv1.DiscoverRepositoriesRequest) (*watchlistv1.DiscoverRepositoriesResponse, error) {
	if req.GetOwner() == "" {
		return nil, status.Error(codes.InvalidArgument, "discover: owner must not be empty")
	}
	found, err := s.read.Discover(ctx, req.GetOwner(), int(req.GetLimit()))
	if err != nil {
		return nil, mapWatchlistError(err)
	}

	out := make([]*watchlistv1.DiscoveredRepository, 0, len(found))
	for _, r := range found {
		out = append(out, &watchlistv1.DiscoveredRepository{
			FullName:    r.FullName,
			Description: r.Description,
			Language:    r.Language,
			Stars:       int32(r.Stars),
			PushedAt:    toTimestamp(r.PushedAt),
			Fork:        r.Fork,
			Archived:    r.Archived,
			Tracked:     r.Tracked,
		})
	}
	return &watchlistv1.DiscoverRepositoriesResponse{Owner: req.GetOwner(), Repositories: out}, nil
}

// TrackRepositories adds repositories to the watchlist.
func (s *WatchlistServer) TrackRepositories(ctx context.Context, req *watchlistv1.TrackRepositoriesRequest) (*watchlistv1.TrackRepositoriesResponse, error) {
	repos, err := s.manage.Track(ctx, req.GetFullNames())
	if err != nil {
		return nil, mapWatchlistError(err)
	}
	return &watchlistv1.TrackRepositoriesResponse{Repositories: toProtoTracked(repos)}, nil
}

// UntrackRepository removes a repository from the watchlist and the graph.
func (s *WatchlistServer) UntrackRepository(ctx context.Context, req *watchlistv1.UntrackRepositoryRequest) (*watchlistv1.UntrackRepositoryResponse, error) {
	removed, err := s.manage.Untrack(ctx, req.GetFullName())
	if err != nil {
		return nil, mapWatchlistError(err)
	}
	return &watchlistv1.UntrackRepositoryResponse{Removed: removed}, nil
}

// ReportScan records one scan's outcome.
func (s *WatchlistServer) ReportScan(ctx context.Context, req *watchlistv1.ReportScanRequest) (*watchlistv1.ReportScanResponse, error) {
	scannedAt := time.Time{}
	if req.GetScannedAt() != nil {
		scannedAt = req.GetScannedAt().AsTime()
	}
	err := s.manage.RecordScan(ctx, model.ScanOutcome{
		FullName:        req.GetFullName(),
		Succeeded:       req.GetSucceeded(),
		Error:           req.GetError(),
		DependencyCount: int(req.GetDependencyCount()),
		ScannedAt:       scannedAt,
	})
	if err != nil {
		return nil, mapWatchlistError(err)
	}
	return &watchlistv1.ReportScanResponse{}, nil
}

func mapWatchlistError(err error) error {
	switch {
	case errors.Is(err, model.ErrInvalidRepositoryName), errors.Is(err, commands.ErrNothingToTrack):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ports.ErrOwnerNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, ports.ErrCatalogUnavailable):
		return status.Error(codes.Unavailable, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

func toProtoTracked(repos []model.TrackedRepository) []*watchlistv1.TrackedRepository {
	out := make([]*watchlistv1.TrackedRepository, 0, len(repos))
	for _, r := range repos {
		out = append(out, &watchlistv1.TrackedRepository{
			FullName:        r.FullName(),
			Url:             r.URL(),
			Status:          toProtoScanStatus(r.Status),
			AddedAt:         toTimestamp(r.AddedAt),
			LastScanAt:      toTimestamp(r.LastScanAt),
			LastError:       r.LastError,
			DependencyCount: int32(r.DependencyCount),
		})
	}
	return out
}

func toProtoScanStatus(s model.ScanStatus) watchlistv1.ScanStatus {
	switch s {
	case model.ScanPending:
		return watchlistv1.ScanStatus_SCAN_STATUS_PENDING
	case model.ScanScanned:
		return watchlistv1.ScanStatus_SCAN_STATUS_SCANNED
	case model.ScanFailed:
		return watchlistv1.ScanStatus_SCAN_STATUS_FAILED
	default:
		return watchlistv1.ScanStatus_SCAN_STATUS_UNSPECIFIED
	}
}
