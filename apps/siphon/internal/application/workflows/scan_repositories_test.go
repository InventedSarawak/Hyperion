package workflows_test

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/application/workflows"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// fakeRepoClient serves canned snapshots per "owner/name".
type fakeRepoClient struct {
	snapshots map[string]model.RepositorySnapshot
	errs      map[string]error
	scanned   []string
}

func (f *fakeRepoClient) Scan(_ context.Context, owner, name string) (model.RepositorySnapshot, error) {
	key := owner + "/" + name
	f.scanned = append(f.scanned, key)
	return f.snapshots[key], f.errs[key]
}

// fakePublisher records what was reported to the intelligence service.
type fakePublisher struct {
	published []model.RepositorySnapshot
	err       error
}

func (f *fakePublisher) Publish(_ context.Context, s model.RepositorySnapshot) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.published = append(f.published, s)
	return len(s.Dependencies), nil
}

func snapshotFor(owner, name string, deps ...string) model.RepositorySnapshot {
	s := model.RepositorySnapshot{
		Repository: model.Repository{Owner: owner, Name: name},
		Author:     model.Author{Login: owner},
	}
	for _, d := range deps {
		s.Dependencies = append(s.Dependencies, model.Dependency{
			Package:      valueobject.NewPackageRef("go", d, "v1.0.0"),
			Direct:       true,
			ManifestPath: "go.mod",
		})
	}
	return s
}

var _ = Describe("ScanRepositories use case", func() {
	ctx := context.Background()

	It("scans each watched repository and reports it", func() {
		client := &fakeRepoClient{snapshots: map[string]model.RepositorySnapshot{
			"gin-gonic/gin": snapshotFor("gin-gonic", "gin", "golang.org/x/net"),
			"acme/api":      snapshotFor("acme", "api", "golang.org/x/net", "golang.org/x/sys"),
		}}
		pub := &fakePublisher{}

		n, err := workflows.NewScanRepositories(client, nil, pub,
			workflows.Targets{Repositories: []string{"gin-gonic/gin", "acme/api"}}).Run(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(3))
		Expect(client.scanned).To(Equal([]string{"gin-gonic/gin", "acme/api"}))
		Expect(pub.published).To(HaveLen(2))
	})

	It("rejects a watchlist entry that is not owner/name", func() {
		client := &fakeRepoClient{}
		_, err := workflows.NewScanRepositories(client, nil, &fakePublisher{},
			workflows.Targets{Repositories: []string{"just-a-name", "/missing-owner", "owner/"}}).Run(ctx, time.Time{})

		Expect(err).To(MatchError(ContainSubstring("owner/name form")))
		Expect(client.scanned).To(BeEmpty())
	})

	It("keeps going when one repository fails", func() {
		client := &fakeRepoClient{
			snapshots: map[string]model.RepositorySnapshot{
				"acme/api": snapshotFor("acme", "api", "golang.org/x/net"),
			},
			errs: map[string]error{"acme/broken": errors.New("403 forbidden")},
		}
		pub := &fakePublisher{}

		n, err := workflows.NewScanRepositories(client, nil, pub,
			workflows.Targets{Repositories: []string{"acme/broken", "acme/api"}}).Run(ctx, time.Time{})

		Expect(err).To(MatchError(ContainSubstring("403 forbidden")))
		Expect(n).To(Equal(1), "the healthy repository is still reported")
		Expect(pub.published).To(HaveLen(1))
	})

	It("still publishes a partial read when one manifest was unreadable", func() {
		// The scan reports an error but returns a usable snapshot: the
		// manifests that did parse are worth recording.
		partial := snapshotFor("acme", "api", "golang.org/x/net")
		client := &fakeRepoClient{
			snapshots: map[string]model.RepositorySnapshot{"acme/api": partial},
			errs:      map[string]error{"acme/api": errors.New("package.json: unexpected end of JSON input")},
		}
		pub := &fakePublisher{}

		n, err := workflows.NewScanRepositories(client, nil, pub, workflows.Targets{Repositories: []string{"acme/api"}}).Run(ctx, time.Time{})

		Expect(err).To(HaveOccurred())
		Expect(n).To(Equal(1))
		Expect(pub.published).To(HaveLen(1))
	})

	It("skips a repository that could not be identified at all", func() {
		client := &fakeRepoClient{errs: map[string]error{"acme/api": errors.New("404 not found")}}
		pub := &fakePublisher{}

		_, err := workflows.NewScanRepositories(client, nil, pub, workflows.Targets{Repositories: []string{"acme/api"}}).Run(ctx, time.Time{})

		Expect(err).To(HaveOccurred())
		Expect(pub.published).To(BeEmpty())
	})

	It("reports a publish failure without stopping the remaining repositories", func() {
		client := &fakeRepoClient{snapshots: map[string]model.RepositorySnapshot{
			"acme/api": snapshotFor("acme", "api", "golang.org/x/net"),
			"acme/web": snapshotFor("acme", "web", "golang.org/x/net"),
		}}
		pub := &fakePublisher{err: errors.New("cortex unavailable")}

		n, err := workflows.NewScanRepositories(client, nil, pub,
			workflows.Targets{Repositories: []string{"acme/api", "acme/web"}}).Run(ctx, time.Time{})

		Expect(err).To(MatchError(ContainSubstring("cortex unavailable")))
		Expect(n).To(Equal(0))
		Expect(client.scanned).To(HaveLen(2), "every repository is still attempted")
	})

	It("does nothing with an empty watchlist", func() {
		n, err := workflows.NewScanRepositories(&fakeRepoClient{}, nil, &fakePublisher{}, workflows.Targets{}).Run(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(0))
	})
})

// fakeDiscoverer enumerates repositories for an owner.
type fakeDiscoverer struct {
	byOwner   map[string][]string
	errs      map[string]error
	gotLimits map[string]int
}

func (f *fakeDiscoverer) Discover(_ context.Context, owner string, limit int) ([]string, error) {
	if f.gotLimits == nil {
		f.gotLimits = map[string]int{}
	}
	f.gotLimits[owner] = limit
	if err := f.errs[owner]; err != nil {
		return nil, err
	}
	return f.byOwner[owner], nil
}

var _ = Describe("ScanRepositories discovery", func() {
	ctx := context.Background()

	It("scans every repository an organization owns", func() {
		client := &fakeRepoClient{snapshots: map[string]model.RepositorySnapshot{
			"vercel/next.js":  snapshotFor("vercel", "next.js", "npm:react"),
			"vercel/commerce": snapshotFor("vercel", "commerce", "npm:next"),
		}}
		disco := &fakeDiscoverer{byOwner: map[string][]string{
			"vercel": {"vercel/next.js", "vercel/commerce"},
		}}

		n, err := workflows.NewScanRepositories(client, disco, &fakePublisher{}, workflows.Targets{
			Organizations: []string{"vercel"}, PerOwnerLimit: 20,
		}).Run(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(2))
		Expect(client.scanned).To(ConsistOf("vercel/next.js", "vercel/commerce"))
		Expect(disco.gotLimits["vercel"]).To(Equal(20))
	})

	It("merges discovered repositories with the explicit list, without duplicates", func() {
		client := &fakeRepoClient{snapshots: map[string]model.RepositorySnapshot{
			"vercel/commerce": snapshotFor("vercel", "commerce", "npm:next"),
			"acme/api":        snapshotFor("acme", "api", "npm:next"),
		}}
		disco := &fakeDiscoverer{byOwner: map[string][]string{
			"vercel": {"vercel/commerce"},
		}}

		_, err := workflows.NewScanRepositories(client, disco, &fakePublisher{}, workflows.Targets{
			Repositories:  []string{"acme/api", "vercel/commerce"},
			Organizations: []string{"vercel"},
		}).Run(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(client.scanned).To(HaveLen(2), "vercel/commerce must not be scanned twice")
	})

	It("treats owner/name as case-insensitive when deduplicating", func() {
		client := &fakeRepoClient{snapshots: map[string]model.RepositorySnapshot{
			"Vercel/Commerce": snapshotFor("Vercel", "Commerce"),
		}}
		disco := &fakeDiscoverer{byOwner: map[string][]string{"vercel": {"vercel/commerce"}}}

		_, err := workflows.NewScanRepositories(client, disco, &fakePublisher{}, workflows.Targets{
			Repositories:  []string{"Vercel/Commerce"},
			Organizations: []string{"vercel"},
		}).Run(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(client.scanned).To(HaveLen(1))
	})

	It("keeps scanning the explicit list when discovery fails", func() {
		client := &fakeRepoClient{snapshots: map[string]model.RepositorySnapshot{
			"acme/api": snapshotFor("acme", "api", "npm:next"),
		}}
		disco := &fakeDiscoverer{errs: map[string]error{"vercel": errors.New("403 forbidden")}}

		n, err := workflows.NewScanRepositories(client, disco, &fakePublisher{}, workflows.Targets{
			Repositories:  []string{"acme/api"},
			Organizations: []string{"vercel"},
		}).Run(ctx, time.Time{})

		Expect(err).To(MatchError(ContainSubstring("403 forbidden")))
		Expect(n).To(Equal(1), "a discovery failure must not cost us the known repositories")
	})

	It("reports an organization configured with no discoverer wired", func() {
		_, err := workflows.NewScanRepositories(&fakeRepoClient{}, nil, &fakePublisher{},
			workflows.Targets{Organizations: []string{"vercel"}}).Run(ctx, time.Time{})

		Expect(err).To(MatchError(ContainSubstring("discovery is unavailable")))
	})

	It("re-discovers on every run, so new repositories are picked up", func() {
		client := &fakeRepoClient{snapshots: map[string]model.RepositorySnapshot{
			"vercel/one": snapshotFor("vercel", "one"),
			"vercel/two": snapshotFor("vercel", "two"),
		}}
		disco := &fakeDiscoverer{byOwner: map[string][]string{"vercel": {"vercel/one"}}}
		scan := workflows.NewScanRepositories(client, disco, &fakePublisher{},
			workflows.Targets{Organizations: []string{"vercel"}})

		_, err := scan.Run(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
		Expect(client.scanned).To(ConsistOf("vercel/one"))

		// A repository created after startup is exactly the one a hand-written
		// watchlist would miss.
		disco.byOwner["vercel"] = []string{"vercel/one", "vercel/two"}
		_, err = scan.Run(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
		Expect(client.scanned).To(ConsistOf("vercel/one", "vercel/one", "vercel/two"))
	})
})
