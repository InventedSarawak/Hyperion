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

		n, err := workflows.NewScanRepositories(client, pub,
			[]string{"gin-gonic/gin", "acme/api"}).Run(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(3))
		Expect(client.scanned).To(Equal([]string{"gin-gonic/gin", "acme/api"}))
		Expect(pub.published).To(HaveLen(2))
	})

	It("rejects a watchlist entry that is not owner/name", func() {
		client := &fakeRepoClient{}
		_, err := workflows.NewScanRepositories(client, &fakePublisher{},
			[]string{"just-a-name", "/missing-owner", "owner/"}).Run(ctx, time.Time{})

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

		n, err := workflows.NewScanRepositories(client, pub,
			[]string{"acme/broken", "acme/api"}).Run(ctx, time.Time{})

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

		n, err := workflows.NewScanRepositories(client, pub, []string{"acme/api"}).Run(ctx, time.Time{})

		Expect(err).To(HaveOccurred())
		Expect(n).To(Equal(1))
		Expect(pub.published).To(HaveLen(1))
	})

	It("skips a repository that could not be identified at all", func() {
		client := &fakeRepoClient{errs: map[string]error{"acme/api": errors.New("404 not found")}}
		pub := &fakePublisher{}

		_, err := workflows.NewScanRepositories(client, pub, []string{"acme/api"}).Run(ctx, time.Time{})

		Expect(err).To(HaveOccurred())
		Expect(pub.published).To(BeEmpty())
	})

	It("reports a publish failure without stopping the remaining repositories", func() {
		client := &fakeRepoClient{snapshots: map[string]model.RepositorySnapshot{
			"acme/api": snapshotFor("acme", "api", "golang.org/x/net"),
			"acme/web": snapshotFor("acme", "web", "golang.org/x/net"),
		}}
		pub := &fakePublisher{err: errors.New("cortex unavailable")}

		n, err := workflows.NewScanRepositories(client, pub,
			[]string{"acme/api", "acme/web"}).Run(ctx, time.Time{})

		Expect(err).To(MatchError(ContainSubstring("cortex unavailable")))
		Expect(n).To(Equal(0))
		Expect(client.scanned).To(HaveLen(2), "every repository is still attempted")
	})

	It("does nothing with an empty watchlist", func() {
		n, err := workflows.NewScanRepositories(&fakeRepoClient{}, &fakePublisher{}, nil).Run(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(0))
	})
})
