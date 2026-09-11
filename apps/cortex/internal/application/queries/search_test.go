package queries_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// stubIndex records the query it was given and returns a canned page.
type stubIndex struct {
	got   model.SearchQuery
	hits  []model.SearchHit
	total int64
	err   error
}

func (s *stubIndex) Index(context.Context, model.Vulnerability) error { return nil }
func (s *stubIndex) Ready(context.Context) error                      { return nil }
func (s *stubIndex) IDs(context.Context) ([]string, error)            { return nil, nil }
func (s *stubIndex) Delete(context.Context, string) error             { return nil }

func (s *stubIndex) Search(_ context.Context, q model.SearchQuery) (model.SearchPage, error) {
	s.got = q
	return model.SearchPage{Hits: s.hits, Total: s.total}, s.err
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
	relevance, newest := model.SortRelevance, model.SortNewest

	It("passes the query and sort through and returns hits", func() {
		idx := &stubIndex{hits: hits(2), total: 2}

		res, err := queries.NewSearch(idx).Handle(ctx, "log4j", relevance, nil, 10, "")

		Expect(err).ToNot(HaveOccurred())
		Expect(idx.got.Text).To(Equal("log4j"))
		Expect(idx.got.Sort).To(Equal(relevance))
		Expect(idx.got.Size).To(Equal(10))
		Expect(res.Hits).To(HaveLen(2))
		Expect(res.Total).To(Equal(int64(2)))
	})

	It("treats an unspecified sort as relevance", func() {
		idx := &stubIndex{}
		_, err := queries.NewSearch(idx).Handle(ctx, "log4j", "", nil, 10, "")
		Expect(err).ToNot(HaveOccurred())
		Expect(idx.got.Sort).To(Equal(relevance))
	})

	It("rejects an empty query under relevance, where every record would tie", func() {
		_, err := queries.NewSearch(&stubIndex{}).Handle(ctx, "   ", relevance, nil, 10, "")
		Expect(err).To(MatchError(ContainSubstring("enter a search term")))
	})

	It("accepts an empty query when sorting by newest: that is the live feed", func() {
		idx := &stubIndex{hits: hits(3), total: 812}
		res, err := queries.NewSearch(idx).Handle(ctx, "", newest, nil, 25, "")

		Expect(err).ToNot(HaveOccurred())
		Expect(idx.got.Sort).To(Equal(newest))
		Expect(idx.got.Text).To(BeEmpty())
		Expect(res.Total).To(Equal(int64(812)))
	})

	It("applies the default page size when none is given", func() {
		idx := &stubIndex{}
		_, err := queries.NewSearch(idx).Handle(ctx, "log4j", relevance, nil, 0, "")
		Expect(err).ToNot(HaveOccurred())
		Expect(idx.got.Size).To(Equal(queries.DefaultPageSize))
	})

	It("caps an oversized page size", func() {
		idx := &stubIndex{}
		_, err := queries.NewSearch(idx).Handle(ctx, "log4j", relevance, nil, 100000, "")
		Expect(err).ToNot(HaveOccurred())
		Expect(idx.got.Size).To(Equal(queries.MaxPageSize))
	})

	It("offers a next page exactly when the total says more remain", func() {
		idx := &stubIndex{hits: hits(5), total: 12}
		res, err := queries.NewSearch(idx).Handle(ctx, "log4j", relevance, nil, 5, "")
		Expect(err).ToNot(HaveOccurred())
		Expect(res.NextPageToken).To(Equal("5"))

		idx = &stubIndex{hits: hits(2), total: 12}
		res, err = queries.NewSearch(idx).Handle(ctx, "log4j", relevance, nil, 5, "10")
		Expect(err).ToNot(HaveOccurred())
		Expect(res.NextPageToken).To(BeEmpty(), "10 + 2 = 12: that was the last page")
	})

	It("does not offer a next page when a full page exactly reaches the total", func() {
		// The old rule, "a full page means there may be more", would send the
		// client after an empty page here.
		idx := &stubIndex{hits: hits(5), total: 5}
		res, err := queries.NewSearch(idx).Handle(ctx, "log4j", relevance, nil, 5, "")
		Expect(err).ToNot(HaveOccurred())
		Expect(res.NextPageToken).To(BeEmpty())
	})

	It("falls back to the full-page rule when the index reports no total", func() {
		full := &stubIndex{hits: hits(5)}
		res, err := queries.NewSearch(full).Handle(ctx, "log4j", relevance, nil, 5, "")
		Expect(err).ToNot(HaveOccurred())
		Expect(res.NextPageToken).To(Equal("5"))

		partial := &stubIndex{hits: hits(2)}
		res, err = queries.NewSearch(partial).Handle(ctx, "log4j", relevance, nil, 5, "")
		Expect(err).ToNot(HaveOccurred())
		Expect(res.NextPageToken).To(BeEmpty())
	})

	It("decodes a page token into the index offset", func() {
		idx := &stubIndex{}
		_, err := queries.NewSearch(idx).Handle(ctx, "log4j", relevance, nil, 5, "10")
		Expect(err).ToNot(HaveOccurred())
		Expect(idx.got.Offset).To(Equal(10))
	})

	It("rejects a malformed page token", func() {
		_, err := queries.NewSearch(&stubIndex{}).Handle(ctx, "log4j", relevance, nil, 5, "not-a-number")
		Expect(err).To(HaveOccurred())
	})

	It("shrinks the last page at the result window instead of failing it", func() {
		idx := &stubIndex{hits: hits(10), total: 50000}
		res, err := queries.NewSearch(idx).Handle(ctx, "cve", relevance, nil, 25, "9990")

		Expect(err).ToNot(HaveOccurred())
		Expect(idx.got.Size).To(Equal(10), "9990 + 10 reaches the 10,000 ceiling exactly")
		Expect(res.NextPageToken).To(BeEmpty(), "nothing past the window can be paged to")
	})

	It("refuses to page past the result window", func() {
		_, err := queries.NewSearch(&stubIndex{}).Handle(ctx, "cve", relevance, nil, 25, "10000")
		Expect(err).To(MatchError(ContainSubstring("narrow the query")))
	})

	It("propagates an index failure", func() {
		idx := &stubIndex{err: errors.New("es down")}
		_, err := queries.NewSearch(idx).Handle(ctx, "log4j", relevance, nil, 5, "")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("Search kinds", func() {
	It("passes the kinds asked for through to the index", func() {
		idx := &stubIndex{}
		_, err := queries.NewSearch(idx).Handle(context.Background(), "axios", model.SortRelevance,
			[]model.FindingKind{model.KindVulnerability}, 10, "")
		Expect(err).ToNot(HaveOccurred())
		Expect(idx.got.Kinds).To(Equal([]model.FindingKind{model.KindVulnerability}))
	})
})
