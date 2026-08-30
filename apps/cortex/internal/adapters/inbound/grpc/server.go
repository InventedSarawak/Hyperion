// Package grpc is an INBOUND adapter exposing cortex's read API over gRPC.
// It implements the generated IntelligenceServiceServer, translating wire
// requests into use-case calls and domain results back onto the contract.
package grpc

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// Searcher is the use case this adapter drives (consumer-side interface).
type Searcher interface {
	Handle(ctx context.Context, query string, pageSize int, pageToken string) (queries.Result, error)
}

// Server implements intelv1.IntelligenceServiceServer.
type Server struct {
	intelv1.UnimplementedIntelligenceServiceServer
	search Searcher
}

// NewServer wires the gRPC adapter to the search use case.
func NewServer(search Searcher) *Server { return &Server{search: search} }

// Search handles the RPC: proto request -> use case -> proto response.
func (s *Server) Search(ctx context.Context, req *intelv1.SearchRequest) (*intelv1.SearchResponse, error) {
	result, err := s.search.Handle(ctx, req.GetQuery(), int(req.GetPageSize()), req.GetPageToken())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	results := make([]*intelv1.SearchResult, 0, len(result.Hits))
	for _, hit := range result.Hits {
		results = append(results, &intelv1.SearchResult{
			Vulnerability: toProtoVulnerability(hit.Vulnerability),
			Score:         hit.Score,
		})
	}

	return &intelv1.SearchResponse{
		Results:       results,
		NextPageToken: result.NextPageToken,
	}, nil
}

// --- mapping: cortex domain -> wire contract ---

func toProtoVulnerability(v model.Vulnerability) *commonv1.Vulnerability {
	return &commonv1.Vulnerability{
		CveId:       v.CVEID,
		Title:       v.Title,
		Description: v.Description,
		Scores:      toProtoScores(v.Scores),
		References:  v.References,
		PublishedAt: toTimestamp(v.PublishedAt),
		ModifiedAt:  toTimestamp(v.ModifiedAt),
	}
}

func toProtoScores(scores []model.CVSS) []*commonv1.Cvss {
	out := make([]*commonv1.Cvss, 0, len(scores))
	for _, s := range scores {
		out = append(out, &commonv1.Cvss{
			Version:   s.Version,
			BaseScore: s.BaseScore,
			Vector:    s.Vector,
			Severity:  toProtoSeverity(s.Severity),
		})
	}
	return out
}

func toProtoSeverity(s model.Severity) commonv1.Severity {
	switch s {
	case model.SeverityNone:
		return commonv1.Severity_SEVERITY_NONE
	case model.SeverityLow:
		return commonv1.Severity_SEVERITY_LOW
	case model.SeverityMedium:
		return commonv1.Severity_SEVERITY_MEDIUM
	case model.SeverityHigh:
		return commonv1.Severity_SEVERITY_HIGH
	case model.SeverityCritical:
		return commonv1.Severity_SEVERITY_CRITICAL
	default:
		return commonv1.Severity_SEVERITY_UNSPECIFIED
	}
}

func toTimestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}
