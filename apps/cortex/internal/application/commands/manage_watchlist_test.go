package commands_test

import (
	"context"
	"errors"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// memWatchlist is an in-memory ports.Watchlist.
type memWatchlist struct {
	repos    map[string]model.TrackedRepository
	outcomes []model.ScanOutcome
	calls    []string
}

func newMemWatchlist() *memWatchlist {
	return &memWatchlist{repos: map[string]model.TrackedRepository{}}
}

func (m *memWatchlist) List(context.Context) ([]model.TrackedRepository, error) {
	out := make([]model.TrackedRepository, 0, len(m.repos))
	for _, r := range m.repos {
		out = append(out, r)
	}
	return out, nil
}

func (m *memWatchlist) Track(_ context.Context, repos []model.TrackedRepository) ([]model.TrackedRepository, error) {
	m.calls = append(m.calls, "track")
	for _, r := range repos {
		m.repos[strings.ToLower(r.FullName())] = r
	}
	return repos, nil
}

func (m *memWatchlist) Remove(_ context.Context, fullName string) (bool, error) {
	m.calls = append(m.calls, "watchlist.remove")
	_, ok := m.repos[strings.ToLower(fullName)]
	delete(m.repos, strings.ToLower(fullName))
	return ok, nil
}

func (m *memWatchlist) RecordScan(_ context.Context, o model.ScanOutcome) error {
	if _, ok := m.repos[strings.ToLower(o.FullName)]; !ok {
		return ports.ErrNotTracked
	}
	m.outcomes = append(m.outcomes, o)
	return nil
}

// orderedRemover records when the graph removal happened relative to the
// watchlist, and can be told to fail.
type orderedRemover struct {
	list *memWatchlist
	err  error
}

func (r *orderedRemover) RemoveRepository(context.Context, string) error {
	r.list.calls = append(r.list.calls, "graph.remove")
	return r.err
}

var _ = Describe("ManageWatchlist", func() {
	var (
		ctx    = context.Background()
		list   *memWatchlist
		graph  *orderedRemover
		manage *commands.ManageWatchlist
	)

	BeforeEach(func() {
		list = newMemWatchlist()
		graph = &orderedRemover{list: list}
		manage = commands.NewManageWatchlist(list, graph)
	})

	It("tracks a batch, normalizing pasted URLs and collapsing duplicates", func() {
		got, err := manage.Track(ctx, []string{"vercel/next.js", "https://github.com/Vercel/Next.js", " ", "eslint/eslint"})

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(2))
		Expect(list.repos).To(HaveKey("vercel/next.js"))
		Expect(list.repos).To(HaveKey("eslint/eslint"))
	})

	It("rejects the whole batch when any name is invalid, naming every bad one", func() {
		_, err := manage.Track(ctx, []string{"vercel/next.js", "just-an-owner", "a/b/c"})

		Expect(err).To(MatchError(model.ErrInvalidRepositoryName))
		Expect(err.Error()).To(ContainSubstring("just-an-owner"))
		Expect(err.Error()).To(ContainSubstring("a/b/c"))
		Expect(list.repos).To(BeEmpty(), "nothing from a rejected batch is stored")
	})

	It("rejects a request that names nothing", func() {
		_, err := manage.Track(ctx, []string{"", "  "})
		Expect(err).To(MatchError(commands.ErrNothingToTrack))
	})

	It("removes from the graph before the watchlist, so a failure stays visible", func() {
		_, _ = manage.Track(ctx, []string{"vercel/next.js"})
		list.calls = nil

		removed, err := manage.Untrack(ctx, "vercel/next.js")
		Expect(err).ToNot(HaveOccurred())
		Expect(removed).To(BeTrue())
		Expect(list.calls).To(Equal([]string{"graph.remove", "watchlist.remove"}))
	})

	It("keeps the repository tracked when the graph removal fails", func() {
		_, _ = manage.Track(ctx, []string{"vercel/next.js"})
		graph.err = errors.New("neo4j down")

		_, err := manage.Untrack(ctx, "vercel/next.js")
		Expect(err).To(MatchError(ContainSubstring("neo4j down")))
		Expect(list.repos).To(HaveKey("vercel/next.js"))
	})

	It("still untracks when no graph is configured, since there is nothing to remove", func() {
		_, _ = manage.Track(ctx, []string{"vercel/next.js"})
		graph.err = ports.ErrGraphUnavailable

		removed, err := manage.Untrack(ctx, "vercel/next.js")
		Expect(err).ToNot(HaveOccurred())
		Expect(removed).To(BeTrue())
	})

	It("records a scan, and quietly drops one for a repository untracked mid-scan", func() {
		_, _ = manage.Track(ctx, []string{"vercel/next.js"})

		Expect(manage.RecordScan(ctx, model.ScanOutcome{FullName: "vercel/next.js", Succeeded: true, DependencyCount: 42})).To(Succeed())
		Expect(list.outcomes).To(HaveLen(1))

		Expect(manage.RecordScan(ctx, model.ScanOutcome{FullName: "gone/repo", Succeeded: true})).To(Succeed())
		Expect(list.outcomes).To(HaveLen(1))
	})
})
