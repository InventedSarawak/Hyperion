package queries_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// recordingGraph captures the arguments the use case passes down, so the
// clamping rules can be asserted on.
type recordingGraph struct {
	cveID  string
	depth  int
	limit  int
	result model.BlastRadius
}

func (g *recordingGraph) UpsertRepositorySnapshot(context.Context, model.RepositorySnapshot) (int, error) {
	return 0, nil
}

func (g *recordingGraph) LinkVulnerability(context.Context, string, []valueobject.PackageRef) error {
	return nil
}

func (g *recordingGraph) RemoveVulnerabilities(context.Context, []string) error { return nil }

func (g *recordingGraph) FindBlastRadius(_ context.Context, cveID string, depth, limit int) (model.BlastRadius, error) {
	g.cveID, g.depth, g.limit = cveID, depth, limit
	return g.result, nil
}

func (g *recordingGraph) Ready(context.Context) error { return nil }

func (g *recordingGraph) RemoveRepository(context.Context, string) error { return nil }

// stubResolver maps ids to the findings they name, like the repo.
type stubResolver map[string]model.Vulnerability

func (s stubResolver) GetByID(_ context.Context, id string) (model.Vulnerability, error) {
	if v, ok := s[id]; ok {
		return v, nil
	}
	return model.Vulnerability{}, ports.ErrNotFound
}

var _ = Describe("CalculateBlastRadius use case", func() {
	ctx := context.Background()

	It("walks from the canonical id whichever of the finding's ids was asked for", func() {
		graph := &recordingGraph{}
		resolver := stubResolver{"GHSA-jfh8-c2jp-5v3q": {CVEID: "CVE-2021-44228"}}

		radius, err := queries.NewCalculateBlastRadius(graph, 0).WithResolver(resolver).
			Handle(ctx, "ghsa-jfh8-c2jp-5v3q", 0, 0)

		Expect(err).ToNot(HaveOccurred())
		Expect(graph.cveID).To(Equal("CVE-2021-44228"))
		Expect(radius.CVEID).To(Equal("CVE-2021-44228"))
	})

	It("still asks the graph about an id the store does not know", func() {
		graph := &recordingGraph{}
		_, err := queries.NewCalculateBlastRadius(graph, 0).WithResolver(stubResolver{}).
			Handle(ctx, "CVE-1970-0001", 0, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(graph.cveID).To(Equal("CVE-1970-0001"))
	})

	It("rejects an empty CVE id rather than enumerating the graph", func() {
		_, err := queries.NewCalculateBlastRadius(&recordingGraph{}, 0).Handle(ctx, "   ", 0, 0)
		Expect(err).To(MatchError(ContainSubstring("enter a finding id")))
	})

	It("normalizes a lowercase CVE id so it matches stored records", func() {
		graph := &recordingGraph{}
		_, err := queries.NewCalculateBlastRadius(graph, 0).Handle(ctx, " cve-2021-44228 ", 0, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(graph.cveID).To(Equal("CVE-2021-44228"))
	})

	It("leaves a GHSA id's case alone, since it is significant", func() {
		graph := &recordingGraph{}
		_, err := queries.NewCalculateBlastRadius(graph, 0).Handle(ctx, "GHSA-jfh8-c2jp-5v3q", 0, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(graph.cveID).To(Equal("GHSA-jfh8-c2jp-5v3q"))
	})

	It("applies the configured default depth when none is requested", func() {
		graph := &recordingGraph{}
		_, err := queries.NewCalculateBlastRadius(graph, 5).Handle(ctx, "CVE-1970-0001", 0, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(graph.depth).To(Equal(5))
		Expect(graph.limit).To(Equal(queries.DefaultBlastRadiusLimit))
	})

	It("caps depth and limit so one query cannot walk the whole graph", func() {
		graph := &recordingGraph{}
		_, err := queries.NewCalculateBlastRadius(graph, 0).Handle(ctx, "CVE-1970-0001", 9999, 9999)
		Expect(err).ToNot(HaveOccurred())
		Expect(graph.depth).To(Equal(queries.MaxBlastRadiusDepth))
		Expect(graph.limit).To(Equal(queries.MaxBlastRadiusLimit))
	})

	It("caps an over-large configured default too", func() {
		graph := &recordingGraph{}
		_, err := queries.NewCalculateBlastRadius(graph, 100).Handle(ctx, "CVE-1970-0001", 0, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(graph.depth).To(Equal(queries.MaxBlastRadiusDepth))
	})

	It("reports an unavailable graph instead of returning an empty radius", func() {
		// An empty result from a missing backend would read as "nothing is
		// affected" — the most dangerous wrong answer this service can give.
		_, err := queries.NewCalculateBlastRadius(nil, 0).Handle(ctx, "CVE-2021-44228", 0, 0)
		Expect(err).To(MatchError(ports.ErrGraphUnavailable))
	})

	It("returns the traversal result stamped with the normalized id", func() {
		graph := &recordingGraph{result: model.BlastRadius{
			VulnerablePackages: []valueobject.PackageRef{valueobject.NewPackageRef("npm", "lodash", "")},
			Repositories: []model.ImpactedRepository{{
				Repository: model.Repository{Owner: "acme", Name: "api"},
				Depth:      1,
				Direct:     true,
			}},
		}}

		radius, err := queries.NewCalculateBlastRadius(graph, 0).Handle(ctx, "cve-2021-44228", 0, 0)

		Expect(err).ToNot(HaveOccurred())
		Expect(radius.CVEID).To(Equal("CVE-2021-44228"))
		Expect(radius.Linked()).To(BeTrue())
		Expect(radius.TotalRepositories()).To(Equal(1))
		Expect(radius.Repositories[0].Repository.FullName()).To(Equal("acme/api"))
	})
})
