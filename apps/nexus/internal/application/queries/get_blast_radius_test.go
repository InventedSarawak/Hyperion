package queries_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
)

// blastStub records what the use case passes down.
type blastStub struct {
	gotCVE   string
	gotDepth int
	gotLimit int
	result   model.BlastRadius
	err      error
}

func (s *blastStub) Search(context.Context, string, model.SearchSort, int, string) (model.SearchResult, error) {
	return model.SearchResult{}, nil
}

func (s *blastStub) BlastRadius(_ context.Context, cveID string, maxDepth, limit int) (model.BlastRadius, error) {
	s.gotCVE, s.gotDepth, s.gotLimit = cveID, maxDepth, limit
	return s.result, s.err
}

var _ = Describe("GetBlastRadius use case", func() {
	ctx := context.Background()

	It("rejects an empty cveId before spending a round trip", func() {
		stub := &blastStub{}
		_, err := queries.NewGetBlastRadius(stub).Handle(ctx, "   ", 0, 0)

		Expect(err).To(MatchError(ContainSubstring("must not be empty")))
		Expect(stub.gotCVE).To(BeEmpty(), "the backend should not have been called")
	})

	It("applies defaults when depth and limit are unset", func() {
		stub := &blastStub{}
		_, err := queries.NewGetBlastRadius(stub).Handle(ctx, "CVE-1", 0, 0)

		Expect(err).ToNot(HaveOccurred())
		Expect(stub.gotDepth).To(Equal(queries.DefaultBlastRadiusDepth))
		Expect(stub.gotLimit).To(Equal(queries.DefaultBlastRadiusLimit))
	})

	It("caps depth and limit at the edge", func() {
		stub := &blastStub{}
		_, err := queries.NewGetBlastRadius(stub).Handle(ctx, "CVE-1", 9999, 9999)

		Expect(err).ToNot(HaveOccurred())
		Expect(stub.gotDepth).To(Equal(queries.MaxBlastRadiusDepth))
		Expect(stub.gotLimit).To(Equal(queries.MaxBlastRadiusLimit))
	})

	It("wraps a backend failure with the CVE it was asking about", func() {
		stub := &blastStub{err: errors.New("graph unavailable")}
		_, err := queries.NewGetBlastRadius(stub).Handle(ctx, "CVE-2021-44228", 0, 0)

		Expect(err).To(MatchError(ContainSubstring("CVE-2021-44228")))
		Expect(err).To(MatchError(ContainSubstring("graph unavailable")))
	})

	It("passes the result through", func() {
		stub := &blastStub{result: model.BlastRadius{
			CVEID:              "CVE-1",
			VulnerablePackages: []string{"npm:next"},
			Repositories:       []model.ImpactedRepository{{Owner: "vercel", Name: "commerce"}},
		}}

		radius, err := queries.NewGetBlastRadius(stub).Handle(ctx, "CVE-1", 0, 0)

		Expect(err).ToNot(HaveOccurred())
		Expect(radius.Linked()).To(BeTrue())
		Expect(radius.Repositories[0].FullName()).To(Equal("vercel/commerce"))
	})
})
