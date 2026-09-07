package queries_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// stubIndex records the arguments it was called with and returns canned hits.
type stubIndex struct {
	gotQuery  string
	gotSize   int
	gotOffset int
	hits      []model.SearchHit
	err       error
}

func (s *stubIndex) Index(context.Context, model.Vulnerability) error { return nil }
func (s *stubIndex) Ready(context.Context) error                      { return nil }

func (s *stubIndex) Search(_ context.Context, q string, size, offset int) ([]model.SearchHit, error) {
	s.gotQuery, s.gotSize, s.gotOffset = q, size, offset
	return s.hits, s.err
}

func hits(n int) []model.SearchHit {
	out := make([]model.SearchHit, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, model.SearchHit{Vulnerability: model.Vulnerability{CVEID: "CVE-X"}, Score: 1})
	}
	return out
}

var _ = Describe("Search use case", func() {
	ctx := context.Background()

	It("passes the query through and returns hits", func() {
		idx := &stubIndex{hits: hits(2)}

		res, err := queries.NewSearch(idx).Handle(ctx, "log4j", 10, "")

		Expect(err).ToNot(HaveOccurred())
		Expect(idx.gotQuery).To(Equal("log4j"))
		Expect(idx.gotSize).To(Equal(10))
		Expect(res.Hits).To(HaveLen(2))
	})

	It("rejects an empty query rather than scanning everything", func() {
		_, err := queries.NewSearch(&stubIndex{}).Handle(ctx, "   ", 10, "")
		Expect(err).To(HaveOccurred())
	})

	It("applies the default page size when none is given", func() {
		idx := &stubIndex{}
		_, err := queries.NewSearch(idx).Handle(ctx, "log4j", 0, "")

		Expect(err).ToNot(HaveOccurred())
		Expect(idx.gotSize).To(Equal(queries.DefaultPageSize))
	})

	It("caps an oversized page size", func() {
		idx := &stubIndex{}
		_, err := queries.NewSearch(idx).Handle(ctx, "log4j", 100000, "")

		Expect(err).ToNot(HaveOccurred())
		Expect(idx.gotSize).To(Equal(queries.MaxPageSize))
	})

	It("returns a next page token only when the page is full", func() {
		full := &stubIndex{hits: hits(5)}
		res, err := queries.NewSearch(full).Handle(ctx, "log4j", 5, "")
		Expect(err).ToNot(HaveOccurred())
		Expect(res.NextPageToken).To(Equal("5"))

		partial := &stubIndex{hits: hits(2)}
		res, err = queries.NewSearch(partial).Handle(ctx, "log4j", 5, "")
		Expect(err).ToNot(HaveOccurred())
		Expect(res.NextPageToken).To(BeEmpty())
	})

	It("decodes a page token into the index offset", func() {
		idx := &stubIndex{}
		_, err := queries.NewSearch(idx).Handle(ctx, "log4j", 5, "10")

		Expect(err).ToNot(HaveOccurred())
		Expect(idx.gotOffset).To(Equal(10))
	})

	It("rejects a malformed page token", func() {
		_, err := queries.NewSearch(&stubIndex{}).Handle(ctx, "log4j", 5, "not-a-number")
		Expect(err).To(HaveOccurred())
	})

	It("propagates an index failure", func() {
		idx := &stubIndex{err: errors.New("es down")}
		_, err := queries.NewSearch(idx).Handle(ctx, "log4j", 5, "")
		Expect(err).To(HaveOccurred())
	})
})
