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
	watchlistv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/watchlist/v1"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// Client wraps the generated gRPC stubs, which share one connection.
type Client struct {
	conn      *grpc.ClientConn
	stub      intelv1.IntelligenceServiceClient
	watchlist watchlistv1.WatchlistServiceClient
	timeout   time.Duration
}

// Dial opens a connection to cortex. Local development uses plaintext; TLS
// credentials belong here once the services are deployed apart (v4).
func Dial(addr string) (*Client, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("grpc: dial %s: %w", addr, err)
	}
	return &Client{
		conn:      conn,
		stub:      intelv1.NewIntelligenceServiceClient(conn),
		watchlist: watchlistv1.NewWatchlistServiceClient(conn),
		timeout:   15 * time.Second,
	}, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Search calls cortex and maps one page into deck's view models.
func (c *Client) Search(ctx context.Context, query string, sort model.SearchSort, kinds []model.FindingKind, pageSize int, pageToken string) (model.SearchPage, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	wireSort := intelv1.SearchSort_SEARCH_SORT_RELEVANCE
	if sort == model.SortNewest {
		wireSort = intelv1.SearchSort_SEARCH_SORT_NEWEST
	}
	resp, err := c.stub.Search(ctx, &intelv1.SearchRequest{
		Query:     query,
		Sort:      wireSort,
		Kinds:     wireKinds(kinds),
		PageSize:  int32(pageSize),
		PageToken: pageToken,
	})
	if err != nil {
		return model.SearchPage{}, describe(err)
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
		return model.BlastRadius{}, describe(err)
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

			DeclaredVersion:  r.GetDeclaredVersion(),
			AffectedVersions: r.GetAffectedVersions(),
			Verdict:          verdictLabel(r.GetVerdict()),
		})
	}
	return radius, nil
}

// RepositoryExposure asks cortex which vulnerabilities a repository has.
func (c *Client) RepositoryExposure(ctx context.Context, fullName string, includeUnaffected bool) (model.RepositoryExposure, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.stub.GetRepositoryExposure(ctx, &intelv1.GetRepositoryExposureRequest{
		FullName:          fullName,
		IncludeUnaffected: includeUnaffected,
	})
	if err != nil {
		return model.RepositoryExposure{}, describe(err)
	}
	exp := model.RepositoryExposure{
		FullName: resp.GetFullName(),
		Scanned:  resp.GetScanned(),
		Summary:  toSummary(resp.GetSummary()),
	}
	for _, f := range resp.GetFindings() {
		exp.Findings = append(exp.Findings, model.RepositoryFinding{
			Vulnerability:    toViewModel(f.GetVulnerability()),
			Package:          packageLabel(f.GetViaPackage()),
			DeclaredVersion:  f.GetViaPackage().GetVersion(),
			AffectedVersions: f.GetAffectedVersions(),
			Verdict:          verdictLabel(f.GetVerdict()),
			Depth:            int(f.GetDepth()),
			Direct:           f.GetDirect(),
			Path:             f.GetPath(),
		})
	}
	return exp, nil
}

// verdictLabel maps the wire verdict onto deck's.
func verdictLabel(v commonv1.ExposureVerdict) string {
	switch v {
	case commonv1.ExposureVerdict_EXPOSURE_VERDICT_AFFECTED:
		return model.VerdictAffected
	case commonv1.ExposureVerdict_EXPOSURE_VERDICT_POSSIBLY_AFFECTED:
		return model.VerdictPossiblyAffected
	case commonv1.ExposureVerdict_EXPOSURE_VERDICT_NOT_AFFECTED:
		return model.VerdictNotAffected
	case commonv1.ExposureVerdict_EXPOSURE_VERDICT_UNKNOWN:
		return model.VerdictUnknown
	default:
		return ""
	}
}

func toSummary(s *commonv1.ExposureSummary) model.ExposureSummary {
	return model.ExposureSummary{
		Computed:         s.GetComputed(),
		CriticalAffected: int(s.GetCriticalAffected()),
		CriticalPossible: int(s.GetCriticalPossible()),
		HighAffected:     int(s.GetHighAffected()),
		HighPossible:     int(s.GetHighPossible()),
		Total:            int(s.GetTotal()),
	}
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
	packages := make([]model.AffectedPackage, 0, len(v.GetAffectedPackages()))
	for _, p := range v.GetAffectedPackages() {
		packages = append(packages, model.AffectedPackage{Package: packageLabel(p), VersionRange: p.GetVersion()})
	}
	kind := model.KindVulnerability
	if v.GetKind() == commonv1.FindingKind_FINDING_KIND_MALWARE {
		kind = model.KindMalware
	}
	return model.Vulnerability{
		CVEID:            v.GetCveId(),
		Aliases:          v.GetAliases(),
		Kind:             kind,
		Title:            v.GetTitle(),
		Description:      v.GetDescription(),
		Scores:           toViewScores(v.GetScores()),
		References:       v.GetReferences(),
		PublishedAt:      fromTimestamp(v.GetPublishedAt()),
		ModifiedAt:       fromTimestamp(v.GetModifiedAt()),
		Sources:          v.GetSources(),
		AffectedPackages: packages,
	}
}

// Vulnerability fetches one finding in full.
func (c *Client) Vulnerability(ctx context.Context, id string) (model.Vulnerability, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.stub.GetVulnerability(ctx, &intelv1.GetVulnerabilityRequest{CveId: id})
	if err != nil {
		return model.Vulnerability{}, describe(err)
	}
	return toViewModel(resp.GetVulnerability()), nil
}

// wireKinds maps the kinds a search asks for onto the wire enum.
func wireKinds(kinds []model.FindingKind) []commonv1.FindingKind {
	out := make([]commonv1.FindingKind, 0, len(kinds))
	for _, k := range kinds {
		if k == model.KindMalware {
			out = append(out, commonv1.FindingKind_FINDING_KIND_MALWARE)
		} else {
			out = append(out, commonv1.FindingKind_FINDING_KIND_VULNERABILITY)
		}
	}
	return out
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
