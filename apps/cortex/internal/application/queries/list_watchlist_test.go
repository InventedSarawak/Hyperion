package queries_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

type stubWatchlist struct {
	ports.Watchlist
	repos []model.TrackedRepository
}

func (s stubWatchlist) List(context.Context) ([]model.TrackedRepository, error) { return s.repos, nil }

type stubCatalog struct {
	repos    []model.DiscoveredRepository
	gotLimit int
	gotOwner string
}

func (s *stubCatalog) ListOwnerRepositories(_ context.Context, owner string, limit int) ([]model.DiscoveredRepository, error) {
	s.gotOwner, s.gotLimit = owner, limit
	return s.repos, nil
}

var _ = Describe("ListWatchlist", func() {
	ctx := context.Background()

	It("marks discovered repositories that are already tracked, ignoring case", func() {
		list := stubWatchlist{repos: []model.TrackedRepository{{Owner: "vercel", Name: "next.js"}}}
		catalog := &stubCatalog{repos: []model.DiscoveredRepository{
			{FullName: "Vercel/Next.js"}, {FullName: "vercel/swr"},
		}}

		got, err := queries.NewListWatchlist(list, catalog).Discover(ctx, "vercel", 0)

		Expect(err).ToNot(HaveOccurred())
		Expect(got[0].Tracked).To(BeTrue())
		Expect(got[1].Tracked).To(BeFalse())
		Expect(catalog.gotLimit).To(Equal(queries.DefaultDiscoverLimit))
	})

	It("caps how many repositories one discovery may list", func() {
		catalog := &stubCatalog{}
		_, err := queries.NewListWatchlist(stubWatchlist{}, catalog).Discover(ctx, "kubernetes", 10_000)
		Expect(err).ToNot(HaveOccurred())
		Expect(catalog.gotLimit).To(Equal(queries.MaxDiscoverLimit))
	})

	It("reports discovery as unavailable without a catalog, while listing still works", func() {
		q := queries.NewListWatchlist(stubWatchlist{repos: []model.TrackedRepository{{Owner: "a", Name: "b"}}}, nil)

		_, err := q.Discover(ctx, "vercel", 0)
		Expect(err).To(MatchError(ports.ErrCatalogUnavailable))

		repos, err := q.Repositories(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(repos).To(HaveLen(1))
	})
})
