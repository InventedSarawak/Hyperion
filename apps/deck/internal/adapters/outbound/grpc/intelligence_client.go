// Package grpc is an OUTBOUND adapter implementing ports.IntelligenceAPI by
// calling cortex over gRPC. It is the only place in deck that touches the
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

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// Client wraps the generated gRPC stub.
type Client struct {
	conn    *grpc.ClientConn
	stub    intelv1.IntelligenceServiceClient
	timeout time.Duration
}

// Dial opens a connection to cortex. Local development uses plaintext; TLS
// credentials belong here once the services are deployed apart (v4).
func Dial(addr string) (*Client, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("grpc: dial %s: %w", addr, err)
	}
	return &Client{
		conn:    conn,
		stub:    intelv1.NewIntelligenceServiceClient(conn),
		timeout: 15 * time.Second,
	}, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Search calls cortex and maps one page into deck's view models.
func (c *Client) Search(ctx context.Context, query string, sort model.SearchSort, pageSize int, pageToken string) (model.SearchPage, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	wireSort := intelv1.SearchSort_SEARCH_SORT_RELEVANCE
	if sort == model.SortNewest {
		wireSort = intelv1.SearchSort_SEARCH_SORT_NEWEST
	}
	resp, err := c.stub.Search(ctx, &intelv1.SearchRequest{
		Query:     query,
		Sort:      wireSort,
		PageSize:  int32(pageSize),
		PageToken: pageToken,
	})
	if err != nil {
		return model.SearchPage{}, fmt.Errorf("grpc: search: %w", err)
	}

	page := model.SearchPage{
		NextPageToken:     resp.GetNextPageToken(),
		Total:             resp.GetTotalResults(),
		TotalIsLowerBound: resp.GetTotalIsLowerBound(),
		Hits:              make([]model.SearchHit, 0, len(resp.GetResults())),
	}
	for _, r := range resp.GetResults() {
		page.Hits = append(page.Hits, model.SearchHit{
			Vulnerability: toViewModel(r.GetVulnerability()),
			Score:         r.GetScore(),
		})
	}
	return page, nil
}

// BlastRadius calls cortex and maps the traversal into deck's view models.
func (c *Client) BlastRadius(ctx context.Context, cveID string, maxDepth int) (model.BlastRadius, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.stub.GetBlastRadius(ctx, &intelv1.GetBlastRadiusRequest{
		CveId:    cveID,
		MaxDepth: int32(maxDepth),
	})
	if err != nil {
		return model.BlastRadius{}, fmt.Errorf("grpc: blast radius: %w", err)
	}

	radius := model.BlastRadius{CVEID: resp.GetCveId()}
	for _, p := range resp.GetVulnerablePackages() {
		radius.VulnerablePackages = append(radius.VulnerablePackages, packageLabel(p))
	}
	for _, r := range resp.GetRepositories() {
		repo := r.GetRepository()
		radius.Repositories = append(radius.Repositories, model.ImpactedRepository{
			FullName:   repo.GetOwner() + "/" + repo.GetName(),
			AuthorName: r.GetAuthor().GetLogin(),
			URL:        repo.GetUrl(),
			ViaPackage: packageLabel(r.GetViaPackage()),
			Depth:      int(r.GetDepth()),
			Direct:     r.GetDirect(),
			Path:       r.GetPath(),
		})
	}
	return radius, nil
}

// packageLabel renders a package reference the way the graph keys it.
func packageLabel(p *commonv1.PackageRef) string {
	if p == nil {
		return ""
	}
	ecosystem := ecosystemLabel(p.GetEcosystem())
	if ecosystem == "" {
		return p.GetName()
	}
	return ecosystem + ":" + p.GetName()
}

func ecosystemLabel(e commonv1.Ecosystem) string {
	switch e {
	case commonv1.Ecosystem_ECOSYSTEM_GO:
		return "go"
	case commonv1.Ecosystem_ECOSYSTEM_NPM:
		return "npm"
	case commonv1.Ecosystem_ECOSYSTEM_PYPI:
		return "pypi"
	case commonv1.Ecosystem_ECOSYSTEM_MAVEN:
		return "maven"
	case commonv1.Ecosystem_ECOSYSTEM_CARGO:
		return "cargo"
	case commonv1.Ecosystem_ECOSYSTEM_RUBYGEMS:
		return "rubygems"
	case commonv1.Ecosystem_ECOSYSTEM_NUGET:
		return "nuget"
	case commonv1.Ecosystem_ECOSYSTEM_PACKAGIST:
		return "packagist"
	default:
		return ""
	}
}

// --- mapping: wire contract -> deck view model ---

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
