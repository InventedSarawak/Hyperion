// Package grpc is an OUTBOUND adapter implementing ports.IntelligenceClient
// by calling cortex over gRPC. It is the only place in nexus that touches the
// generated contract types.
package grpc

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
)

// Client wraps the generated gRPC stub.
type Client struct {
	conn   *grpc.ClientConn
	stub   intelv1.IntelligenceServiceClient
	timout time.Duration
}

// Dial opens a connection to cortex. Local development uses plaintext; TLS
// credentials belong here when the services are deployed apart.
func Dial(addr string) (*Client, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("grpc: dial %s: %w", addr, err)
	}
	return &Client{conn: conn, stub: intelv1.NewIntelligenceServiceClient(conn), timout: 10 * time.Second}, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Search calls cortex and maps the response back into nexus view models.
func (c *Client) Search(ctx context.Context, query string, pageSize int, pageToken string) (model.SearchResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timout)
	defer cancel()

	resp, err := c.stub.Search(ctx, &intelv1.SearchRequest{
		Query:     query,
		PageSize:  int32(pageSize),
		PageToken: pageToken,
	})
	if err != nil {
		return model.SearchResult{}, fmt.Errorf("grpc: search: %w", err)
	}

	hits := make([]model.SearchHit, 0, len(resp.GetResults()))
	for _, r := range resp.GetResults() {
		hits = append(hits, model.SearchHit{
			Vulnerability: toViewModel(r.GetVulnerability()),
			Score:         r.GetScore(),
		})
	}
	return model.SearchResult{Hits: hits, NextPageToken: resp.GetNextPageToken()}, nil
}

// --- mapping: wire contract -> nexus view model ---

func toViewModel(v *commonv1.Vulnerability) model.Vulnerability {
	return model.Vulnerability{
		CVEID:       v.GetCveId(),
		Title:       v.GetTitle(),
		Description: v.GetDescription(),
		Scores:      toViewScores(v.GetScores()),
		References:  v.GetReferences(),
		PublishedAt: fromTimestamp(v.GetPublishedAt()),
		ModifiedAt:  fromTimestamp(v.GetModifiedAt()),
	}
}

func toViewScores(scores []*commonv1.Cvss) []model.CVSS {
	out := make([]model.CVSS, 0, len(scores))
	for _, s := range scores {
		out = append(out, model.CVSS{
			Version:   s.GetVersion(),
			BaseScore: s.GetBaseScore(),
			Vector:    s.GetVector(),
			Severity:  severityLabel(s.GetSeverity()),
		})
	}
	return out
}

// severityLabel converts the enum to the short form clients expect.
func severityLabel(s commonv1.Severity) string {
	switch s {
	case commonv1.Severity_SEVERITY_NONE:
		return "NONE"
	case commonv1.Severity_SEVERITY_LOW:
		return "LOW"
	case commonv1.Severity_SEVERITY_MEDIUM:
		return "MEDIUM"
	case commonv1.Severity_SEVERITY_HIGH:
		return "HIGH"
	case commonv1.Severity_SEVERITY_CRITICAL:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func fromTimestamp(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}
