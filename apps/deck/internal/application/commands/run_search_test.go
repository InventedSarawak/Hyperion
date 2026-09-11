package commands_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// pagingAPI serves a fixed result set a page at a time, the way the gateway
// does: the page token is the offset of the next page.
type pagingAPI struct {
	all      []model.SearchHit
	gotQuery string
	gotSort  model.SearchSort
	gotKinds []model.FindingKind
	gotToken string
	err      error
	// insertOnPage2 simulates records arriving between two requests.
	insertOnPage2 []model.SearchHit
}

func (a *pagingAPI) Search(_ context.Context, query string, sort model.SearchSort, kinds []model.FindingKind, size int, token string) (model.SearchPage, error) {
	a.gotQuery, a.gotSort, a.gotKinds, a.gotToken = query, sort, kinds, token
	if a.err != nil {
		return model.SearchPage{}, a.err
	}
	all := a.all
	if token != "" && a.insertOnPage2 != nil {
		all = append(append([]model.SearchHit{}, a.insertOnPage2...), a.all...)
	}
	offset, _ := strconv.Atoi(token)
	end := min(len(all), offset+size)
	page := model.SearchPage{Hits: all[offset:end], Total: int64(len(all))}
	if end < len(all) {
		page.NextPageToken = strconv.Itoa(end)
	}
	return page, nil
}

func (a *pagingAPI) BlastRadius(context.Context, string, int) (model.BlastRadius, error) {
	return model.BlastRadius{}, nil
}

func (a *pagingAPI) Vulnerability(context.Context, string) (model.Vulnerability, error) {
	return model.Vulnerability{}, nil
}

func results(n int) []model.SearchHit {
	out := make([]model.SearchHit, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, model.SearchHit{Vulnerability: model.Vulnerability{CVEID: fmt.Sprintf("CVE-2026-%04d", i)}})
	}
	return out
}

var _ = Describe("RunSearch use case", func() {
	ctx := context.Background()

	It("serves the live feed, newest first, when there is no query", func() {
		api := &pagingAPI{all: results(80)}
		feed, err := commands.NewRunSearch(api).Handle(ctx, "  ", model.SortRelevance, false, 25)

		Expect(err).ToNot(HaveOccurred())
		Expect(api.gotSort).To(Equal(model.SortNewest), "an empty query has only one meaningful order")
		Expect(api.gotQuery).To(BeEmpty())
		Expect(feed.Hits).To(HaveLen(25))
		Expect(feed.Total).To(Equal(int64(80)))
		Expect(feed.HasMore()).To(BeTrue())
	})

	It("defaults a search term to best match", func() {
		api := &pagingAPI{all: results(3)}
		_, err := commands.NewRunSearch(api).Handle(ctx, "next", "", false, 25)
		Expect(err).ToNot(HaveOccurred())
		Expect(api.gotSort).To(Equal(model.SortRelevance))
	})

	It("keeps newest when asked for it with a term", func() {
		api := &pagingAPI{all: results(3)}
		feed, err := commands.NewRunSearch(api).Handle(ctx, "next", model.SortNewest, false, 25)
		Expect(err).ToNot(HaveOccurred())
		Expect(feed.Sort).To(Equal(model.SortNewest))
	})

	It("appends each following page until there are no more", func() {
		api := &pagingAPI{all: results(60)}
		search := commands.NewRunSearch(api)

		feed, err := search.Handle(ctx, "", model.SortNewest, false, 25)
		Expect(err).ToNot(HaveOccurred())

		feed, err = search.More(ctx, feed, 25)
		Expect(err).ToNot(HaveOccurred())
		Expect(api.gotToken).To(Equal("25"))
		Expect(feed.Hits).To(HaveLen(50))

		feed, err = search.More(ctx, feed, 25)
		Expect(err).ToNot(HaveOccurred())
		Expect(feed.Hits).To(HaveLen(60))
		Expect(feed.HasMore()).To(BeFalse())

		Expect(feed.Hits[59].Vulnerability.CVEID).To(Equal("CVE-2026-0059"))
	})

	It("does nothing when asked for more past the end", func() {
		api := &pagingAPI{all: results(3)}
		search := commands.NewRunSearch(api)
		feed, err := search.Handle(ctx, "", model.SortNewest, false, 25)
		Expect(err).ToNot(HaveOccurred())

		api.gotToken = "untouched"
		again, err := search.More(ctx, feed, 25)
		Expect(err).ToNot(HaveOccurred())
		Expect(again.Hits).To(HaveLen(3))
		Expect(api.gotToken).To(Equal("untouched"), "no request is made")
	})

	It("does not show a result twice when new records shift the pages", func() {
		// Offset paging over a newest-first list: one record arriving between
		// requests pushes page one's last item onto the start of page two.
		api := &pagingAPI{all: results(50)}
		search := commands.NewRunSearch(api)
		feed, err := search.Handle(ctx, "", model.SortNewest, false, 25)
		Expect(err).ToNot(HaveOccurred())

		api.insertOnPage2 = []model.SearchHit{{Vulnerability: model.Vulnerability{CVEID: "CVE-NEW"}}}
		feed, err = search.More(ctx, feed, 25)
		Expect(err).ToNot(HaveOccurred())

		seen := map[string]int{}
		for _, h := range feed.Hits {
			seen[h.Vulnerability.CVEID]++
		}
		for id, n := range seen {
			Expect(n).To(Equal(1), "%s appears %d times", id, n)
		}
	})

	It("keeps the loaded pages when fetching the next one fails", func() {
		api := &pagingAPI{all: results(60)}
		search := commands.NewRunSearch(api)
		feed, err := search.Handle(ctx, "", model.SortNewest, false, 25)
		Expect(err).ToNot(HaveOccurred())

		api.err = errors.New("gateway down")
		after, err := search.More(ctx, feed, 25)

		Expect(err).To(MatchError(ContainSubstring("gateway down")))
		Expect(after.Hits).To(HaveLen(25))
		Expect(after.NextPageToken).To(Equal("25"), "so the same page can be retried")
	})

	It("caps the page size", func() {
		api := &pagingAPI{all: results(500)}
		feed, err := commands.NewRunSearch(api).Handle(ctx, "", model.SortNewest, false, 100000)
		Expect(err).ToNot(HaveOccurred())
		Expect(feed.Hits).To(HaveLen(commands.MaxPageSize))
	})

	It("reports a missing connection instead of panicking", func() {
		_, err := commands.NewRunSearch(nil).Handle(ctx, "", model.SortNewest, false, 25)
		Expect(err).To(MatchError(ContainSubstring("not connected")))
	})
})

var _ = Describe("RunSearch malware", func() {
	ctx := context.Background()

	It("leaves malware out of the feed unless asked for, on every page", func() {
		api := &pagingAPI{all: results(60)}
		search := commands.NewRunSearch(api)

		feed, err := search.Handle(ctx, "", model.SortNewest, false, 25)
		Expect(err).ToNot(HaveOccurred())
		Expect(api.gotKinds).To(Equal([]model.FindingKind{model.KindVulnerability}))

		_, err = search.More(ctx, feed, 25)
		Expect(err).ToNot(HaveOccurred())
		Expect(api.gotKinds).To(Equal([]model.FindingKind{model.KindVulnerability}))
	})

	It("asks for every kind once malware is included, and keeps asking while paging", func() {
		api := &pagingAPI{all: results(60)}
		search := commands.NewRunSearch(api)

		feed, err := search.Handle(ctx, "axios", model.SortRelevance, true, 25)
		Expect(err).ToNot(HaveOccurred())
		Expect(feed.IncludeMalware).To(BeTrue())
		Expect(api.gotKinds).To(BeEmpty())

		_, err = search.More(ctx, feed, 25)
		Expect(err).ToNot(HaveOccurred())
		Expect(api.gotKinds).To(BeEmpty())
	})
})
