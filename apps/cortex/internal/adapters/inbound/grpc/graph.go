package grpc

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// IngestDependencies records one repository's manifest as graph edges.
func (s *Server) IngestDependencies(ctx context.Context, req *intelv1.IngestDependenciesRequest) (*intelv1.IngestDependenciesResponse, error) {
	if s.deps == nil {
		return nil, status.Error(codes.Unavailable, ports.ErrGraphUnavailable.Error())
	}
	if req.GetRepository() == nil {
		return nil, status.Error(codes.InvalidArgument, model.ErrMissingRepositoryIdentity.Error())
	}

	written, err := s.deps.Handle(ctx, toDomainSnapshot(req))
	if err != nil {
		return nil, mapGraphError(err)
	}
	return &intelv1.IngestDependenciesResponse{DependenciesWritten: int32(written)}, nil
}

// GetBlastRadius answers "who is exposed to this CVE?".
func (s *Server) GetBlastRadius(ctx context.Context, req *intelv1.GetBlastRadiusRequest) (*intelv1.GetBlastRadiusResponse, error) {
	if s.blast == nil {
		return nil, status.Error(codes.Unavailable, ports.ErrGraphUnavailable.Error())
	}
	if valueobject.NormalizeCVEID(req.GetCveId()) == "" {
		return nil, status.Error(codes.InvalidArgument, msgNeedID)
	}

	radius, err := s.blast.Handle(ctx, req.GetCveId(), int(req.GetMaxDepth()), int(req.GetLimit()))
	if err != nil {
		return nil, mapGraphError(err)
	}

	impacted := make([]*intelv1.ImpactedRepository, 0, len(radius.Repositories))
	for _, r := range radius.Repositories {
		impacted = append(impacted, &intelv1.ImpactedRepository{
			Repository:       toProtoRepository(r.Repository),
			ViaPackage:       toProtoPackageRef(r.ViaPackage),
			Author:           toProtoAuthor(r.Author),
			Depth:            int32(r.Depth),
			Direct:           r.Direct,
			Path:             r.Path,
			DeclaredVersion:  r.DeclaredVersion,
			AffectedVersions: r.AffectedVersions,
			Verdict:          toProtoVerdict(r.Verdict),
		})
	}

	return &intelv1.GetBlastRadiusResponse{
		CveId:              radius.CVEID,
		VulnerablePackages: toProtoPackageRefs(radius.VulnerablePackages),
		Repositories:       impacted,
		TotalRepositories:  int32(radius.TotalRepositories()),
	}, nil
}

// GetRepositoryExposure answers "which vulnerabilities does this repository have?".
func (s *Server) GetRepositoryExposure(ctx context.Context, req *intelv1.GetRepositoryExposureRequest) (*intelv1.GetRepositoryExposureResponse, error) {
	if s.exposure == nil {
		return nil, status.Error(codes.Unavailable, ports.ErrGraphUnavailable.Error())
	}
	exp, err := s.exposure.Handle(ctx, req.GetFullName(), int(req.GetMaxDepth()), req.GetIncludeUnaffected())
	switch {
	case errors.Is(err, queries.ErrNeedRepository):
		return nil, status.Error(codes.InvalidArgument, err.Error())
	case err != nil:
		return nil, mapGraphError(err)
	}

	findings := make([]*intelv1.RepositoryFinding, 0, len(exp.Findings))
	for _, e := range exp.Findings {
		findings = append(findings, &intelv1.RepositoryFinding{
			Vulnerability:    toProtoVulnerability(e.Finding),
			ViaPackage:       toProtoPackageRef(e.Package),
			AffectedVersions: e.AffectedVersions,
			Verdict:          toProtoVerdict(e.Verdict),
			Depth:            int32(e.Depth),
			Direct:           e.Direct,
			Path:             e.Path,
		})
	}
	return &intelv1.GetRepositoryExposureResponse{
		FullName: exp.FullName,
		Findings: findings,
		Summary:  toProtoSummary(exp.Summary),
		Scanned:  exp.Scanned,
	}, nil
}

func toProtoVerdict(v valueobject.ExposureVerdict) commonv1.ExposureVerdict {
	switch v {
	case valueobject.ExposureAffected:
		return commonv1.ExposureVerdict_EXPOSURE_VERDICT_AFFECTED
	case valueobject.ExposurePossible:
		return commonv1.ExposureVerdict_EXPOSURE_VERDICT_POSSIBLY_AFFECTED
	case valueobject.ExposureNotAffected:
		return commonv1.ExposureVerdict_EXPOSURE_VERDICT_NOT_AFFECTED
	case valueobject.ExposureUnknown:
		return commonv1.ExposureVerdict_EXPOSURE_VERDICT_UNKNOWN
	default:
		return commonv1.ExposureVerdict_EXPOSURE_VERDICT_UNSPECIFIED
	}
}

func toProtoSummary(s model.ExposureSummary) *commonv1.ExposureSummary {
	return &commonv1.ExposureSummary{
		Computed:         s.Computed,
		CriticalAffected: int32(s.CriticalAffected),
		CriticalPossible: int32(s.CriticalPossible),
		HighAffected:     int32(s.HighAffected),
		HighPossible:     int32(s.HighPossible),
		Total:            int32(s.Total),
	}
}

// mapGraphError translates a domain failure into the right gRPC status. A
// missing backend is Unavailable, not Internal: it is a deployment gap the
// caller can retry past, and it must never be mistaken for an empty answer.
func mapGraphError(err error) error {
	switch {
	case errors.Is(err, ports.ErrGraphUnavailable):
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, model.ErrMissingRepositoryIdentity),
		errors.Is(err, model.ErrMissingCVEID),
		errors.Is(err, model.ErrMissingLibraryName),
		errors.Is(err, valueobject.ErrMissingPackageName):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// --- mapping: wire contract -> cortex domain ---

func toDomainSnapshot(req *intelv1.IngestDependenciesRequest) model.RepositorySnapshot {
	repo := req.GetRepository()

	deps := make([]model.Dependency, 0, len(req.GetDependencies()))
	for _, d := range req.GetDependencies() {
		deps = append(deps, model.Dependency{
			Package:      toDomainPackageRef(d.GetPackage()),
			Direct:       d.GetDirect(),
			ManifestPath: d.GetManifestPath(),
			Locked:       d.GetLocked(),
		})
	}

	snapshot := model.RepositorySnapshot{
		Repository: model.Repository{
			Owner:         repo.GetOwner(),
			Name:          repo.GetName(),
			URL:           repo.GetUrl(),
			DefaultBranch: repo.GetDefaultBranch(),
		},
		Publishes:    toDomainPackageRef(req.GetPublishes()),
		Dependencies: deps,
		ObservedAt:   req.GetObservedAt().AsTime(),
	}
	if a := req.GetAuthor(); a != nil {
		snapshot.Author = model.Author{Login: a.GetLogin(), Name: a.GetName(), URL: a.GetUrl()}
	}
	if req.GetObservedAt() == nil {
		snapshot.ObservedAt = time.Time{}
	}
	return snapshot
}

func toDomainPackageRef(p *commonv1.PackageRef) valueobject.PackageRef {
	if p == nil {
		return valueobject.PackageRef{}
	}
	return valueobject.PackageRef{
		Ecosystem: fromProtoEcosystem(p.GetEcosystem()),
		Name:      p.GetName(),
		Version:   p.GetVersion(),
	}
}

func fromProtoEcosystem(e commonv1.Ecosystem) valueobject.Ecosystem {
	switch e {
	case commonv1.Ecosystem_ECOSYSTEM_GO:
		return valueobject.EcosystemGo
	case commonv1.Ecosystem_ECOSYSTEM_NPM:
		return valueobject.EcosystemNPM
	case commonv1.Ecosystem_ECOSYSTEM_PYPI:
		return valueobject.EcosystemPyPI
	case commonv1.Ecosystem_ECOSYSTEM_MAVEN:
		return valueobject.EcosystemMaven
	case commonv1.Ecosystem_ECOSYSTEM_CARGO:
		return valueobject.EcosystemCargo
	case commonv1.Ecosystem_ECOSYSTEM_RUBYGEMS:
		return valueobject.EcosystemRubyGems
	case commonv1.Ecosystem_ECOSYSTEM_NUGET:
		return valueobject.EcosystemNuGet
	case commonv1.Ecosystem_ECOSYSTEM_PACKAGIST:
		return valueobject.EcosystemPackagist
	default:
		return valueobject.EcosystemUnknown
	}
}

// --- mapping: cortex domain -> wire contract ---

func toProtoRepository(r model.Repository) *commonv1.Repository {
	return &commonv1.Repository{
		Owner:         r.Owner,
		Name:          r.Name,
		Url:           r.URL,
		DefaultBranch: r.DefaultBranch,
	}
}

func toProtoAuthor(a model.Author) *commonv1.Author {
	if a.IsZero() {
		return nil
	}
	return &commonv1.Author{Login: a.Login, Name: a.Name, Url: a.URL}
}

func toProtoPackageRefs(refs []valueobject.PackageRef) []*commonv1.PackageRef {
	out := make([]*commonv1.PackageRef, 0, len(refs))
	for _, r := range refs {
		out = append(out, toProtoPackageRef(r))
	}
	return out
}

func toProtoPackageRef(r valueobject.PackageRef) *commonv1.PackageRef {
	if r.IsZero() {
		return nil
	}
	return &commonv1.PackageRef{
		Ecosystem: toProtoEcosystem(r.Ecosystem),
		Name:      r.Name,
		Version:   r.Version,
	}
}

func toProtoEcosystem(e valueobject.Ecosystem) commonv1.Ecosystem {
	switch e {
	case valueobject.EcosystemGo:
		return commonv1.Ecosystem_ECOSYSTEM_GO
	case valueobject.EcosystemNPM:
		return commonv1.Ecosystem_ECOSYSTEM_NPM
	case valueobject.EcosystemPyPI:
		return commonv1.Ecosystem_ECOSYSTEM_PYPI
	case valueobject.EcosystemMaven:
		return commonv1.Ecosystem_ECOSYSTEM_MAVEN
	case valueobject.EcosystemCargo:
		return commonv1.Ecosystem_ECOSYSTEM_CARGO
	case valueobject.EcosystemRubyGems:
		return commonv1.Ecosystem_ECOSYSTEM_RUBYGEMS
	case valueobject.EcosystemNuGet:
		return commonv1.Ecosystem_ECOSYSTEM_NUGET
	case valueobject.EcosystemPackagist:
		return commonv1.Ecosystem_ECOSYSTEM_PACKAGIST
	default:
		return commonv1.Ecosystem_ECOSYSTEM_UNSPECIFIED
	}
}
