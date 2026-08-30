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
	gotTerm  string
	gotSize  int
	gotToken string
	result   model.SearchResult
	err      error
}

func (s *stubIntelligence) Search(_ context.Context, term string, size int, token string) (model.SearchResult, error) {
	s.gotTerm, s.gotSize, s.gotToken = term, size, token
	return s.result, s.err
}

var _ = Describe("SearchVulnerabilities use case", func() {
	ctx := context.Background()

	It("delegates to the intelligence client and returns its result", func() {
		stub := &stubIntelligence{result: model.SearchResult{
			Hits:          []model.SearchHit{{Vulnerability: model.Vulnerability{CVEID: "CVE-2021-44228"}, Score: 9}},
			NextPageToken: "25",
		}}

		got, err := queries.NewSearchVulnerabilities(stub).Handle(ctx, "log4j", 10, "")

		Expect(err).ToNot(HaveOccurred())
		Expect(stub.gotTerm).To(Equal("log4j"))
		Expect(stub.gotSize).To(Equal(10))
		Expect(got.Hits).To(HaveLen(1))
		Expect(got.NextPageToken).To(Equal("25"))
	})

	It("rejects an empty term without calling the backend", func() {
		stub := &stubIntelligence{}
		_, err := queries.NewSearchVulnerabilities(stub).Handle(ctx, "  ", 10, "")

		Expect(err).To(HaveOccurred())
		Expect(stub.gotTerm).To(BeEmpty())
	})

	It("propagates a backend failure", func() {
		stub := &stubIntelligence{err: errors.New("cortex down")}
		_, err := queries.NewSearchVulnerabilities(stub).Handle(ctx, "log4j", 10, "")
		Expect(err).To(HaveOccurred())
	})

	It("forwards the page token", func() {
		stub := &stubIntelligence{}
		_, err := queries.NewSearchVulnerabilities(stub).Handle(ctx, "log4j", 10, "50")

		Expect(err).ToNot(HaveOccurred())
		Expect(stub.gotToken).To(Equal("50"))
	})
})
