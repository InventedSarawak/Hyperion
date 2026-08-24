package commands_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
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

var _ = Describe("IngestSignal use case", func() {
	ctx := context.Background()

	It("stores a new vulnerability", func() {
		repo := newMemRepo()
		err := commands.NewIngestSignal(repo).Handle(ctx, model.Vulnerability{
			CVEID:   "CVE-2021-44228",
			Sources: []string{"nvd"},
		})
		Expect(err).ToNot(HaveOccurred())

		got, err := repo.GetByCVE(ctx, "CVE-2021-44228")
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Sources).To(Equal([]string{"nvd"}))
	})

	It("rejects a vulnerability with no CVE id", func() {
		err := commands.NewIngestSignal(newMemRepo()).Handle(ctx, model.Vulnerability{})
		Expect(err).To(MatchError(model.ErrMissingCVEID))
	})

	It("merges a re-observed CVE instead of duplicating (sources unioned)", func() {
		repo := newMemRepo()
		ingest := commands.NewIngestSignal(repo)

		Expect(ingest.Handle(ctx, model.Vulnerability{CVEID: "CVE-1", Description: "first", Sources: []string{"nvd"}})).To(Succeed())
		Expect(ingest.Handle(ctx, model.Vulnerability{CVEID: "CVE-1", Description: "updated", Sources: []string{"cisa_kev"}})).To(Succeed())

		count, _ := repo.Count(ctx)
		Expect(count).To(Equal(1))

		got, _ := repo.GetByCVE(ctx, "CVE-1")
		Expect(got.Description).To(Equal("updated"))
		Expect(got.Sources).To(ConsistOf("nvd", "cisa_kev"))
	})
})
