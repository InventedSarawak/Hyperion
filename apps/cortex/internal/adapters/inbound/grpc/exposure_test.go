package grpc_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"

	grpcadapter "github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/inbound/grpc"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	vo "github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

type stubExposure struct {
	gotName    string
	gotInclude bool
	result     model.RepositoryExposure
	err        error
}

func (s *stubExposure) Handle(_ context.Context, name string, _ int, include bool) (model.RepositoryExposure, error) {
	s.gotName, s.gotInclude = name, include
	return s.result, s.err
}

var _ = Describe("gRPC repository exposure", func() {
	ctx := context.Background()

	It("maps a repository's findings, verdicts and flag onto the wire", func() {
		stub := &stubExposure{result: model.RepositoryExposure{
			FullName: "InventedSarawak/CacheMiss",
			Scanned:  true,
			Findings: []model.Exposure{{
				Finding:          model.Vulnerability{CVEID: "CVE-2025-54793", Title: "Astro open redirect"},
				Package:          vo.PackageRef{Ecosystem: vo.EcosystemNPM, Name: "astro", Version: "^5.11.0"},
				AffectedVersions: ">= 5.2.0, < 5.12.8",
				Verdict:          vo.ExposurePossible,
				Depth:            1,
				Direct:           true,
			}},
			Summary: model.ExposureSummary{Computed: true, HighPossible: 2, Total: 5},
		}}

		resp, err := grpcadapter.NewServer(nil, nil, nil, nil).WithRepositoryExposure(stub).
			GetRepositoryExposure(ctx, &intelv1.GetRepositoryExposureRequest{FullName: "inventedsarawak/cachemiss", IncludeUnaffected: true})

		Expect(err).ToNot(HaveOccurred())
		Expect(stub.gotName).To(Equal("inventedsarawak/cachemiss"))
		Expect(stub.gotInclude).To(BeTrue())
		Expect(resp.GetFullName()).To(Equal("InventedSarawak/CacheMiss"))
		Expect(resp.GetScanned()).To(BeTrue())
		f := resp.GetFindings()[0]
		Expect(f.GetVulnerability().GetCveId()).To(Equal("CVE-2025-54793"))
		Expect(f.GetViaPackage().GetName()).To(Equal("astro"))
		Expect(f.GetViaPackage().GetVersion()).To(Equal("^5.11.0"))
		Expect(f.GetAffectedVersions()).To(Equal(">= 5.2.0, < 5.12.8"))
		Expect(f.GetVerdict()).To(Equal(commonv1.ExposureVerdict_EXPOSURE_VERDICT_POSSIBLY_AFFECTED))
		Expect(resp.GetSummary().GetHighPossible()).To(Equal(int32(2)))
		Expect(resp.GetSummary().GetComputed()).To(BeTrue())
	})

	It("rejects a request that names no repository", func() {
		stub := &stubExposure{err: queries.ErrNeedRepository}
		_, err := grpcadapter.NewServer(nil, nil, nil, nil).WithRepositoryExposure(stub).
			GetRepositoryExposure(ctx, &intelv1.GetRepositoryExposureRequest{})
		Expect(status.Code(err)).To(Equal(codes.InvalidArgument))
		Expect(status.Convert(err).Message()).To(Equal("enter a repository as owner/name"))
	})

	It("is unavailable when nothing can answer it", func() {
		_, err := grpcadapter.NewServer(nil, nil, nil, nil).
			GetRepositoryExposure(ctx, &intelv1.GetRepositoryExposureRequest{FullName: "a/b"})
		Expect(status.Code(err)).To(Equal(codes.Unavailable))
	})
})
