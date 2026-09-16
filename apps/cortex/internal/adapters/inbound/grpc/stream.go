package grpc

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// FindingSubscriber is what the streaming endpoint needs from the broadcaster
// (consumer-side interface, so the adapter depends on a method rather than on
// the concrete fan-out).
type FindingSubscriber interface {
	Subscribe() (<-chan model.Vulnerability, func())
}

// WithFindingStream enables StreamFindings on this server.
func (s *Server) WithFindingStream(sub FindingSubscriber) *Server {
	s.findings = sub
	return s
}

// StreamFindings pushes findings to the caller as they are ingested.
//
// The stream carries what arrives from now on and never replays history: it is
// a feed, not a query, and a client that wants what came before asks Search.
// That keeps this endpoint cheap — no cursor, no storage, nothing to resume.
func (s *Server) StreamFindings(req *intelv1.StreamFindingsRequest, stream intelv1.IntelligenceService_StreamFindingsServer) error {
	if s.findings == nil {
		return status.Error(codes.Unavailable, "live findings are not enabled on this server")
	}

	wanted := kindFilter(req.GetKinds())

	updates, unsubscribe := s.findings.Subscribe()
	defer unsubscribe()

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			// The client hung up, or the server is shutting down. Either way
			// the subscription goes with it.
			return nil
		case v, ok := <-updates:
			if !ok {
				return nil
			}
			if wanted != nil && !wanted[v.Kind] {
				continue
			}
			if err := stream.Send(&intelv1.StreamFindingsResponse{
				Vulnerability: toProtoVulnerability(v),
				IngestedAt:    timestamppb.Now(),
			}); err != nil {
				// A send failure is the client going away mid-write; nothing
				// here is worth retrying.
				return err
			}
		}
	}
}

// kindFilter turns the requested kinds into a lookup, or nil for "everything".
// It reuses the same mapping Search uses, so "vulnerabilities only" means the
// same thing on the feed as it does in a query.
func kindFilter(kinds []commonv1.FindingKind) map[model.FindingKind]bool {
	domain := fromProtoKinds(kinds)
	if len(domain) == 0 {
		return nil
	}
	out := make(map[model.FindingKind]bool, len(domain))
	for _, k := range domain {
		out[k] = true
	}
	return out
}
