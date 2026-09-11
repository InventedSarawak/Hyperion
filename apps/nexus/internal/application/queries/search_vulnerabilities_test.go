package queries_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
)

// stubIntelligence stands in for the cortex client (outbound port).
type stubIntelligence struct {
	called   bool
	gotSort  model.SearchSort
	gotKinds []model.FindingKind
	gotTerm  string
	gotSize  int
	gotToken string
	result   model.SearchResult
	err      error
}

func (s *stubIntelligence) Search(_ context.Context, term string, sort model.SearchSort, kinds []model.FindingKind, size int, token string) (model.SearchResult, error) {
	s.gotKinds = kinds
	s.called = true
	s.gotTerm, s.gotSort, s.gotSize, s.gotToken = term, sort, size, token
	return s.result, s.err
}

var _ = Describe("SearchVulnerabilities use case", func() {
	ctx := context.Background()

	It("delegates to the intelligence client and returns its result", func() {
		stub := &stubIntelligence{result: model.SearchResult{
			Hits:          []model.SearchHit{{Vulnerability: model.Vulnerability{CVEID: "CVE-2021-44228"}, Score: 9}},
			NextPageToken: "25",
		}}

		got, err := queries.NewSearchVulnerabilities(stub).Handle(ctx, "log4j", model.SortRelevance, nil, 10, "")

		Expect(err).ToNot(HaveOccurred())
		Expect(stub.gotTerm).To(Equal("log4j"))
		Expect(stub.gotSize).To(Equal(10))
		Expect(got.Hits).To(HaveLen(1))
		Expect(got.NextPageToken).To(Equal("25"))
	})

	It("rejects an empty term without calling the backend", func() {
		stub := &stubIntelligence{}
		_, err := queries.NewSearchVulnerabilities(stub).Handle(ctx, "  ", model.SortRelevance, nil, 10, "")

		Expect(err).To(HaveOccurred())
		Expect(stub.called).To(BeFalse())
	})

	It("accepts an empty term when sorting by newest: the live feed", func() {
		stub := &stubIntelligence{result: model.SearchResult{TotalResults: 6771}}
		got, err := queries.NewSearchVulnerabilities(stub).Handle(ctx, "", model.SortNewest, nil, 25, "")

		Expect(err).ToNot(HaveOccurred())
		Expect(stub.called).To(BeTrue())
		Expect(stub.gotSort).To(Equal(model.SortNewest))
		Expect(got.TotalResults).To(Equal(int64(6771)))
	})

	It("treats an unknown sort as relevance", func() {
		stub := &stubIntelligence{}
		_, err := queries.NewSearchVulnerabilities(stub).Handle(ctx, "log4j", "sideways", nil, 25, "")
		Expect(err).ToNot(HaveOccurred())
		Expect(stub.gotSort).To(Equal(model.SortRelevance))
	})

	It("propagates a backend failure", func() {
		stub := &stubIntelligence{err: errors.New("cortex down")}
		_, err := queries.NewSearchVulnerabilities(stub).Handle(ctx, "log4j", model.SortRelevance, nil, 10, "")
		Expect(err).To(HaveOccurred())
	})

	It("forwards the page token", func() {
		stub := &stubIntelligence{}
		_, err := queries.NewSearchVulnerabilities(stub).Handle(ctx, "log4j", model.SortRelevance, nil, 10, "50")

		Expect(err).ToNot(HaveOccurred())
		Expect(stub.gotToken).To(Equal("50"))
	})
})

// BlastRadius satisfies ports.IntelligenceClient; the blast-radius specs use
// their own stub, so this one only needs to compile.
func (s *stubIntelligence) BlastRadius(context.Context, string, int, int) (model.BlastRadius, error) {
	return model.BlastRadius{}, nil
}

// Vulnerability satisfies ports.IntelligenceClient.
func (s *stubIntelligence) Vulnerability(context.Context, string) (model.Vulnerability, error) {
	return model.Vulnerability{}, nil
}

var _ = Describe("SearchVulnerabilities kinds", func() {
	It("passes the kinds asked for through to cortex", func() {
		stub := &stubIntelligence{}
		_, err := queries.NewSearchVulnerabilities(stub).Handle(context.Background(), "axios", model.SortRelevance,
			[]model.FindingKind{model.KindMalware}, 10, "")
		Expect(err).ToNot(HaveOccurred())
		Expect(stub.gotKinds).To(Equal([]model.FindingKind{model.KindMalware}))
	})
})
