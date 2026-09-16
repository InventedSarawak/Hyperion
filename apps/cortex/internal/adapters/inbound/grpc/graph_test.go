package grpc_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"

	grpcadapter "github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/inbound/grpc"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// stubIngester stands in for the dependency-ingest use case.
type stubIngester struct {
	got     model.RepositorySnapshot
	written int
	err     error
}

func (s *stubIngester) Handle(_ context.Context, snapshot model.RepositorySnapshot) (int, error) {
	s.got = snapshot
	return s.written, s.err
}

// stubBlast stands in for the blast-radius use case.
type stubBlast struct {
	gotCVE   string
	gotDepth int
	gotLimit int
	result   model.BlastRadius
	err      error
}

func (s *stubBlast) Handle(_ context.Context, cveID string, depth, limit int) (model.BlastRadius, error) {
	s.gotCVE, s.gotDepth, s.gotLimit = cveID, depth, limit
	return s.result, s.err
}

var _ = Describe("gRPC IngestDependencies", func() {
	ctx := context.Background()

	request := func() *intelv1.IngestDependenciesRequest {
		return &intelv1.IngestDependenciesRequest{
			Repository: &commonv1.Repository{
				Owner: "gin-gonic", Name: "gin",
				Url: "https://github.com/gin-gonic/gin", DefaultBranch: "master",
			},
			Author: &commonv1.Author{Login: "gin-gonic", Name: "Gin Web Framework"},
			Publishes: &commonv1.PackageRef{
				Ecosystem: commonv1.Ecosystem_ECOSYSTEM_GO,
				Name:      "github.com/gin-gonic/gin",
			},
			Dependencies: []*commonv1.Dependency{{
				Package: &commonv1.PackageRef{
					Ecosystem: commonv1.Ecosystem_ECOSYSTEM_GO,
					Name:      "golang.org/x/net",
					Version:   "v0.17.0",
				},
				Direct:       true,
				ManifestPath: "go.mod",
			}},
			ObservedAt: timestamppb.Now(),
		}
	}

	It("maps the wire request onto a domain snapshot", func() {
		stub := &stubIngester{written: 1}

		resp, err := grpcadapter.NewServer(nil, stub, nil, nil).IngestDependencies(ctx, request())

		Expect(err).ToNot(HaveOccurred())
		Expect(resp.GetDependenciesWritten()).To(Equal(int32(1)))

		Expect(stub.got.Repository.FullName()).To(Equal("gin-gonic/gin"))
		Expect(stub.got.Author.Login).To(Equal("gin-gonic"))
		Expect(stub.got.Publishes.Key()).To(Equal("go:github.com/gin-gonic/gin"))
		Expect(stub.got.Dependencies).To(HaveLen(1))
		Expect(stub.got.Dependencies[0].Package.Ecosystem).To(Equal(valueobject.EcosystemGo))
		Expect(stub.got.Dependencies[0].Package.Version).To(Equal("v0.17.0"))
		Expect(stub.got.Dependencies[0].Direct).To(BeTrue())
		Expect(stub.got.ObservedAt.IsZero()).To(BeFalse())
	})

	It("treats an absent author and an absent published module as optional", func() {
		stub := &stubIngester{}
		req := request()
		req.Author, req.Publishes, req.ObservedAt = nil, nil, nil

		_, err := grpcadapter.NewServer(nil, stub, nil, nil).IngestDependencies(ctx, req)

		Expect(err).ToNot(HaveOccurred())
		Expect(stub.got.Author.IsZero()).To(BeTrue())
		Expect(stub.got.Publishes.IsZero()).To(BeTrue())
		Expect(stub.got.ObservedAt.IsZero()).To(BeTrue())
	})

	It("rejects a request with no repository", func() {
		_, err := grpcadapter.NewServer(nil, &stubIngester{}, nil, nil).
			IngestDependencies(ctx, &intelv1.IngestDependenciesRequest{})
		Expect(status.Code(err)).To(Equal(codes.InvalidArgument))
	})

	It("reports Unavailable when no graph is configured", func() {
		_, err := grpcadapter.NewServer(nil, nil, nil, nil).IngestDependencies(ctx, request())
		Expect(status.Code(err)).To(Equal(codes.Unavailable))
	})

	It("maps a missing graph backend to Unavailable, not Internal", func() {
		stub := &stubIngester{err: ports.ErrGraphUnavailable}
		_, err := grpcadapter.NewServer(nil, stub, nil, nil).IngestDependencies(ctx, request())
		Expect(status.Code(err)).To(Equal(codes.Unavailable))
	})

	It("maps a domain validation failure to InvalidArgument", func() {
		stub := &stubIngester{err: model.ErrMissingRepositoryIdentity}
		_, err := grpcadapter.NewServer(nil, stub, nil, nil).IngestDependencies(ctx, request())
		Expect(status.Code(err)).To(Equal(codes.InvalidArgument))
	})

	It("maps an unexpected backend failure to Internal", func() {
		stub := &stubIngester{err: errors.New("bolt: connection reset")}
		_, err := grpcadapter.NewServer(nil, stub, nil, nil).IngestDependencies(ctx, request())
		Expect(status.Code(err)).To(Equal(codes.Internal))
	})
})

var _ = Describe("gRPC GetBlastRadius", func() {
	ctx := context.Background()

	It("maps a domain radius onto the wire contract", func() {
		stub := &stubBlast{result: model.BlastRadius{
			CVEID:              "CVE-2021-44228",
			VulnerablePackages: []valueobject.PackageRef{valueobject.NewPackageRef("maven", "org.apache.logging.log4j:log4j-core", "")},
			Repositories: []model.ImpactedRepository{{
				Repository: model.Repository{Owner: "acme", Name: "api", URL: "https://example.test/acme/api"},
				Author:     model.Author{Login: "acme"},
				ViaPackage: valueobject.NewPackageRef("maven", "org.apache.logging.log4j:log4j-core", ""),
				Depth:      2,
				Direct:     false,
				Path:       []string{"acme/api", "maven:framework", "maven:org.apache.logging.log4j:log4j-core"},
			}},
		}}

		resp, err := grpcadapter.NewServer(nil, nil, stub, nil).GetBlastRadius(ctx, &intelv1.GetBlastRadiusRequest{
			CveId: "CVE-2021-44228", MaxDepth: 3, Limit: 50,
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(stub.gotCVE).To(Equal("CVE-2021-44228"))
		Expect(stub.gotDepth).To(Equal(3))
		Expect(stub.gotLimit).To(Equal(50))

		Expect(resp.GetCveId()).To(Equal("CVE-2021-44228"))
		Expect(resp.GetTotalRepositories()).To(Equal(int32(1)))
		Expect(resp.GetVulnerablePackages()).To(HaveLen(1))
		Expect(resp.GetVulnerablePackages()[0].GetEcosystem()).To(Equal(commonv1.Ecosystem_ECOSYSTEM_MAVEN))

		hit := resp.GetRepositories()[0]
		Expect(hit.GetRepository().GetOwner()).To(Equal("acme"))
		Expect(hit.GetAuthor().GetLogin()).To(Equal("acme"))
		Expect(hit.GetDepth()).To(Equal(int32(2)))
		Expect(hit.GetDirect()).To(BeFalse())
		Expect(hit.GetPath()).To(HaveLen(3))
	})

	It("returns an empty-but-successful response when nothing is exposed", func() {
		stub := &stubBlast{result: model.BlastRadius{CVEID: "CVE-2021-44228"}}

		resp, err := grpcadapter.NewServer(nil, nil, stub, nil).GetBlastRadius(ctx, &intelv1.GetBlastRadiusRequest{
			CveId: "CVE-2021-44228",
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(resp.GetRepositories()).To(BeEmpty())
		Expect(resp.GetTotalRepositories()).To(Equal(int32(0)))
	})

	It("rejects an empty CVE id", func() {
		_, err := grpcadapter.NewServer(nil, nil, &stubBlast{}, nil).
			GetBlastRadius(ctx, &intelv1.GetBlastRadiusRequest{CveId: "  "})
		Expect(status.Code(err)).To(Equal(codes.InvalidArgument))
	})

	It("reports Unavailable rather than an empty radius when no graph is configured", func() {
		_, err := grpcadapter.NewServer(nil, nil, nil, nil).
			GetBlastRadius(ctx, &intelv1.GetBlastRadiusRequest{CveId: "CVE-2021-44228"})
		Expect(status.Code(err)).To(Equal(codes.Unavailable))
	})
})
