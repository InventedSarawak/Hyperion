package queries_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/ports"
)

type exposureStub struct {
	ports.IntelligenceClient
	gotName    string
	gotInclude bool
	calls      int
}

func (s *exposureStub) RepositoryExposure(_ context.Context, name string, include bool) (model.RepositoryExposure, error) {
	s.calls++
	s.gotName, s.gotInclude = name, include
	return model.RepositoryExposure{FullName: name, Scanned: true}, nil
}

var _ = Describe("GetRepositoryExposure use case", func() {
	ctx := context.Background()

	It("asks cortex for the repository, trimmed", func() {
		stub := &exposureStub{}
		got, err := queries.NewGetRepositoryExposure(stub).Handle(ctx, "  InventedSarawak/CacheMiss ", true)

		Expect(err).ToNot(HaveOccurred())
		Expect(stub.gotName).To(Equal("InventedSarawak/CacheMiss"))
		Expect(stub.gotInclude).To(BeTrue())
		Expect(got.Scanned).To(BeTrue())
	})

	It("rejects an empty name without a round trip", func() {
		stub := &exposureStub{}
		_, err := queries.NewGetRepositoryExposure(stub).Handle(ctx, " ", false)

		Expect(err).To(MatchError("enter a repository as owner/name"))
		Expect(stub.calls).To(BeZero())
	})
})
