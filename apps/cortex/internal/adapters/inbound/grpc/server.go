// Package grpc is an INBOUND adapter exposing cortex's read API over gRPC.
// It implements the generated IntelligenceServiceServer, translating wire
// requests into use-case calls and domain results back onto the contract.
package grpc

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// Searcher is the use case this adapter drives (consumer-side interface).
type Searcher interface {
	Handle(ctx context.Context, query string, sort model.SearchSort, kinds []model.FindingKind, pageSize int, pageToken string) (queries.Result, error)
}

// DependencyIngester records a repository's manifest in the dependency graph.
type DependencyIngester interface {
	Handle(ctx context.Context, snapshot model.RepositorySnapshot) (int, error)
}

// BlastRadiusCalculator answers which repositories a vulnerability reaches.
type BlastRadiusCalculator interface {
	Handle(ctx context.Context, cveID string, maxDepth, limit int) (model.BlastRadius, error)
}

// VulnerabilityReader loads one finding from the store of record.
type VulnerabilityReader interface {
	GetByID(ctx context.Context, cveID string) (model.Vulnerability, error)
}

// Server implements intelv1.IntelligenceServiceServer.
type Server struct {
	intelv1.UnimplementedIntelligenceServiceServer
	search Searcher
	deps   DependencyIngester
	blast  BlastRadiusCalculator
	vulns  VulnerabilityReader
}

// NewServer wires the gRPC adapter to cortex's use cases. The graph use cases
// may be nil when no graph backend is configured; the RPCs that need them then
// report Unavailable rather than answering wrongly.
func NewServer(search Searcher, deps DependencyIngester, blast BlastRadiusCalculator, vulns VulnerabilityReader) *Server {
	return &Server{search: search, deps: deps, blast: blast, vulns: vulns}
}

// GetVulnerability returns one finding in full.
func (s *Server) GetVulnerability(ctx context.Context, req *intelv1.GetVulnerabilityRequest) (*intelv1.GetVulnerabilityResponse, error) {
	id := valueobject.NormalizeCVEID(req.GetCveId())
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "get vulnerability: id must not be empty")
	}
	v, err := s.vulns.GetByID(ctx, id)
	switch {
	case errors.Is(err, ports.ErrNotFound):
		return nil, status.Errorf(codes.NotFound, "no finding %s", id)
	case err != nil:
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &intelv1.GetVulnerabilityResponse{Vulnerability: toProtoVulnerability(v)}, nil
}

// Search handles the RPC: proto request -> use case -> proto response.
func (s *Server) Search(ctx context.Context, req *intelv1.SearchRequest) (*intelv1.SearchResponse, error) {
	result, err := s.search.Handle(ctx, req.GetQuery(), fromProtoSort(req.GetSort()),
		fromProtoKinds(req.GetKinds()), int(req.GetPageSize()), req.GetPageToken())
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
		Results:           results,
		NextPageToken:     result.NextPageToken,
		TotalResults:      result.Total,
		TotalIsLowerBound: result.TotalIsLowerBound,
	}, nil
}

// fromProtoSort maps the wire enum; unspecified means relevance.
func fromProtoSort(s intelv1.SearchSort) model.SearchSort {
	if s == intelv1.SearchSort_SEARCH_SORT_NEWEST {
		return model.SortNewest
	}
	return model.SortRelevance
}

// fromProtoKinds maps the kinds a search asks for; none means every kind.
func fromProtoKinds(kinds []commonv1.FindingKind) []model.FindingKind {
	var out []model.FindingKind
	for _, k := range kinds {
		switch k {
		case commonv1.FindingKind_FINDING_KIND_MALWARE:
			out = append(out, model.KindMalware)
		case commonv1.FindingKind_FINDING_KIND_VULNERABILITY, commonv1.FindingKind_FINDING_KIND_UNSPECIFIED:
			out = append(out, model.KindVulnerability)
		}
	}
	return out
}

// --- mapping: cortex domain -> wire contract ---

func toProtoKind(k model.FindingKind) commonv1.FindingKind {
	if k == model.KindMalware {
		return commonv1.FindingKind_FINDING_KIND_MALWARE
	}
	return commonv1.FindingKind_FINDING_KIND_VULNERABILITY
}

func toProtoVulnerability(v model.Vulnerability) *commonv1.Vulnerability {
	return &commonv1.Vulnerability{
		CveId:       v.CVEID,
		Aliases:     v.Aliases,
		Kind:        toProtoKind(v.Kind),
		Title:       v.Title,
		Description: v.Description,
		Scores:      toProtoScores(v.Scores),
		References:  v.References,
		PublishedAt: toTimestamp(v.PublishedAt),
		ModifiedAt:  toTimestamp(v.ModifiedAt),
		// These never reached the wire before, so no client could say which
		// libraries a finding affects or which feeds reported it.
		AffectedPackages: toProtoPackageRefs(v.AffectedPackages),
		Sources:          v.Sources,
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
