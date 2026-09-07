package commands_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// memRepo is an in-memory VulnerabilityRepo (outbound port) for tests.
type memRepo struct {
	store map[string]model.Vulnerability
}

func newMemRepo() *memRepo { return &memRepo{store: map[string]model.Vulnerability{}} }

func (m *memRepo) Upsert(_ context.Context, v model.Vulnerability) error {
	m.store[v.CVEID] = v
	return nil
}

func (m *memRepo) GetByCVE(_ context.Context, cveID string) (model.Vulnerability, error) {
	v, ok := m.store[cveID]
	if !ok {
		return model.Vulnerability{}, ports.ErrNotFound
	}
	return v, nil
}

func (m *memRepo) Count(_ context.Context) (int, error) { return len(m.store), nil }

// memIndex is an in-memory SearchIndex (outbound port) for tests.
type memIndex struct {
	indexed []model.Vulnerability
}

func (m *memIndex) Index(_ context.Context, v model.Vulnerability) error {
	m.indexed = append(m.indexed, v)
	return nil
}

func (m *memIndex) Search(context.Context, string, int, int) ([]model.SearchHit, error) {
	return nil, nil
}

func (m *memIndex) Ready(context.Context) error { return nil }

var _ = Describe("IngestSignal use case", func() {
	ctx := context.Background()

	It("stores a new vulnerability", func() {
		repo := newMemRepo()
		err := commands.NewIngestSignal(repo, &memIndex{}, nil).Handle(ctx, model.Vulnerability{
			CVEID:   "CVE-2021-44228",
			Sources: []string{"nvd"},
		})
		Expect(err).ToNot(HaveOccurred())

		got, err := repo.GetByCVE(ctx, "CVE-2021-44228")
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Sources).To(Equal([]string{"nvd"}))
	})

	It("rejects a vulnerability with no CVE id", func() {
		err := commands.NewIngestSignal(newMemRepo(), &memIndex{}, nil).Handle(ctx, model.Vulnerability{})
		Expect(err).To(MatchError(model.ErrMissingCVEID))
	})

	It("merges a re-observed CVE instead of duplicating (sources unioned)", func() {
		repo := newMemRepo()
		ingest := commands.NewIngestSignal(repo, &memIndex{}, nil)

		Expect(ingest.Handle(ctx, model.Vulnerability{CVEID: "CVE-1", Description: "first", Sources: []string{"nvd"}})).To(Succeed())
		Expect(ingest.Handle(ctx, model.Vulnerability{CVEID: "CVE-1", Description: "updated", Sources: []string{"cisa_kev"}})).To(Succeed())

		count, _ := repo.Count(ctx)
		Expect(count).To(Equal(1))

		got, _ := repo.GetByCVE(ctx, "CVE-1")
		Expect(got.Description).To(Equal("updated"))
		Expect(got.Sources).To(ConsistOf("nvd", "cisa_kev"))
	})

	It("also indexes the stored vulnerability for search", func() {
		repo := newMemRepo()
		index := &memIndex{}

		err := commands.NewIngestSignal(repo, index, nil).Handle(ctx, model.Vulnerability{
			CVEID:   "CVE-2021-44228",
			Sources: []string{"nvd"},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(index.indexed).To(HaveLen(1))
		Expect(index.indexed[0].CVEID).To(Equal("CVE-2021-44228"))
	})
})

var _ = Describe("IngestSignal graph linking", func() {
	ctx := context.Background()
	lodash := valueobject.NewPackageRef("npm", "lodash", "< 4.17.21")

	It("links the CVE to the packages the advisory named", func() {
		graph := newMemGraph()

		err := commands.NewIngestSignal(newMemRepo(), &memIndex{}, graph).Handle(ctx, model.Vulnerability{
			CVEID:            "CVE-2021-23337",
			Sources:          []string{"github_advisory"},
			AffectedPackages: []valueobject.PackageRef{lodash},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(graph.links).To(HaveKey("CVE-2021-23337"))
		Expect(graph.links["CVE-2021-23337"]).To(HaveLen(1))
	})

	It("does not touch the graph for a finding with no affected packages", func() {
		graph := newMemGraph()

		err := commands.NewIngestSignal(newMemRepo(), &memIndex{}, graph).Handle(ctx, model.Vulnerability{
			CVEID: "CVE-2021-44228", Sources: []string{"nvd"},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(graph.links).To(BeEmpty())
	})

	It("stores the record even when the graph is unavailable", func() {
		// The graph is an enrichment; Postgres is the source of truth. A
		// graph outage must never cost us the finding itself.
		graph := newMemGraph()
		graph.writeErr = ports.ErrGraphUnavailable
		repo := newMemRepo()

		err := commands.NewIngestSignal(repo, &memIndex{}, graph).Handle(ctx, model.Vulnerability{
			CVEID:            "CVE-2021-23337",
			Sources:          []string{"github_advisory"},
			AffectedPackages: []valueobject.PackageRef{lodash},
		})

		Expect(err).ToNot(HaveOccurred())
		count, _ := repo.Count(ctx)
		Expect(count).To(Equal(1))
	})

	It("stores the record even when the graph write fails outright", func() {
		graph := newMemGraph()
		graph.writeErr = errors.New("bolt: connection reset")
		repo := newMemRepo()

		err := commands.NewIngestSignal(repo, &memIndex{}, graph).Handle(ctx, model.Vulnerability{
			CVEID:            "CVE-2021-23337",
			Sources:          []string{"github_advisory"},
			AffectedPackages: []valueobject.PackageRef{lodash},
		})

		Expect(err).ToNot(HaveOccurred())
		count, _ := repo.Count(ctx)
		Expect(count).To(Equal(1))
	})
})
